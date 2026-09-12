// Package sdnapi adapts material-free repository management to HTTP. The 015
// surface is a deliberately bounded profile, not a full RESTCONF server.
package sdnapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

const NodePath = "/restconf/data/etsi-qkd-sdn-node:qkd_node"
const media = "application/yang-data+json"

func New(manager allocation.Manager, config allocation.Config, identities map[string]string) http.Handler {
	c := allocation.Clone(config)
	actors, saes := map[string]string{}, map[string]string{}
	for uri := range c.Principals {
		actors[uri] = uri
	}
	for uri, sae := range identities {
		saes[sae] = uri
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		standard := strings.HasPrefix(r.URL.Path, "/restconf/")
		fail := func(status int) { failure(w, status, standard) }
		actor, ok := security.SAEIdentity(r, actors)
		if !ok {
			fail(401)
			return
		}
		grant := c.Principals[actor]
		if r.URL.RawQuery != "" || r.URL.RawPath != "" {
			fail(400)
			return
		}
		if r.Method == "GET" && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			fail(400)
			return
		}
		if r.URL.Path == "/management/v1/capabilities" && r.Method == "GET" {
			write(w, "application/json", map[string]any{
				"profile": allocation.Profile, "etsi015_version": "2.1.1", "conformance": "partial_profile; not_independently_assessed",
				"etsi015_read":  []string{"qkdn_id", "qkdn_version", "qkdn_location_id", "qkdn_capabilities", "qkd_applications"},
				"etsi015_write": []string{"preconfigured_application/app_qos/ttl (1..2678400 seconds)"},
				"etsi021":       "draft_0.0.1; interface_not_implemented", "etsi023": "draft_0.0.6; interface_not_implemented",
				"commands": []string{"association_rule", "local_ttl", "configured_routes"}, "monitoring": "scoped_local_snapshot_polling",
				"unsupported": []string{"physical_QKD_control", "application_creation", "bandwidth_guarantees", "priority_scheduling", "notifications", "provider_attestation"},
			})
			return
		}
		if r.URL.Path == "/management/v1/commands" && r.Method == "POST" {
			if !grant.Write {
				fail(403)
				return
			}
			b, status := body(r, "application/json")
			if status != 0 {
				fail(status)
				return
			}
			var cmd allocation.Command
			if decodeCommand(b, &cmd) != nil {
				fail(400)
				return
			}
			result, err := manager.ApplyCommand(actor, cmd)
			if err != nil {
				fail(errorStatus(err))
				return
			}
			w.Header().Set("ETag", etag(result.Revision))
			write(w, "application/json", result)
			return
		}
		if r.URL.Path == "/management/v1/state" && r.Method == "GET" {
			v, err := manager.ManagementView(grant.Pairs)
			if err != nil {
				fail(503)
				return
			}
			w.Header().Set("ETag", etag(v.Revision))
			write(w, "application/json", v)
			return
		}
		if standard && strings.HasPrefix(r.URL.Path, NodePath) {
			if r.Method != "GET" && r.Method != "PUT" {
				fail(405)
				return
			}
			suffix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, NodePath), "/")
			if r.Method == "PUT" && !grant.Write {
				fail(403)
				return
			}
			v, err := manager.ManagementView(grant.Pairs)
			if err != nil {
				fail(503)
				return
			}
			node := nodeView(c, saes, v)
			value, name, app := resource(node, v, suffix)
			if name == "" {
				fail(404)
				return
			}
			if r.Method == "GET" {
				if app != nil && name == "ttl" && app.Rule.MaxLocalAgeSeconds == 0 {
					fail(404)
					return
				}
				if r.Header.Get("Accept") != "" && !strings.Contains(r.Header.Get("Accept"), media) && r.Header.Get("Accept") != "*/*" {
					fail(406)
					return
				}
				w.Header().Set("ETag", etag(v.Revision))
				write(w, media, map[string]any{"etsi-qkd-sdn-node:" + name: value})
				return
			}
			if app == nil || !strings.HasSuffix(suffix, "/app_qos/ttl") {
				fail(405)
				return
			}
			revision, valid := matchRevision(r.Header.Get("If-Match"))
			id := core.KeyID(r.Header.Get("X-Command-ID"))
			if !valid || !id.Valid() {
				fail(428)
				return
			}
			b, status := body(r, media)
			if status != 0 {
				fail(status)
				return
			}
			var data struct {
				TTL *uint32 `json:"etsi-qkd-sdn-node:ttl"`
			}
			if metadata.DecodeRequest(b, &data, "etsi-qkd-sdn-node:ttl") != nil || data.TTL == nil || *data.TTL == 0 || *data.TTL > 2678400 {
				fail(400)
				return
			}
			result, err := manager.ApplyCommand(actor, allocation.Command{ID: id, ExpectedRevision: revision, Association: app.Association, LocalTTL: data.TTL})
			if err != nil {
				status := errorStatus(err)
				if status == 409 {
					status = 412
				}
				fail(status)
				return
			}
			w.Header().Set("ETag", etag(result.Revision))
			w.WriteHeader(204)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/management/v1/") {
			fail(405)
		} else {
			fail(404)
		}
	})
}

func nodeView(c allocation.Config, saes map[string]string, v allocation.View) map[string]any {
	apps := []map[string]any{}
	for _, app := range v.Apps {
		qos := map[string]any{"clients_shared_path_enable": false, "clients_shared_keys_required": false}
		if app.Rule.MaxLocalAgeSeconds > 0 {
			qos["ttl"] = app.Rule.MaxLocalAgeSeconds
		}
		apps = append(apps, map[string]any{"app_id": app.AppID, "app_type": "etsi-qkd-node-types:CLIENT", "server_app_id": saes[app.Association.Master], "client_app_id": []string{saes[app.Association.Slave]}, "local_qkdn_id": c.NodeID, "remote_qkdn_id": app.RemoteNodeID, "app_qos": qos})
	}
	// No physical device/link observations are available from the KMS. Unknown
	// status, SKR and QBER are omitted; a responding HTTP server cannot attest them.
	return map[string]any{"qkdn_id": c.NodeID, "qkdn_version": allocation.Profile, "qkdn_location_id": c.Location,
		"qkdn_capabilities": map[string]bool{"link_stats_support": false, "application_stats_support": false, "key_relay_mode_enable": false},
		"qkd_applications":  map[string]any{"qkd_app": apps}, "qkd_interfaces": map[string]any{}, "qkd_links": map[string]any{}}
}
func resource(node map[string]any, v allocation.View, suffix string) (any, string, *allocation.AppView) {
	if suffix == "" {
		return node, "qkd_node", nil
	}
	for name, value := range node {
		if suffix == "/"+name {
			return value, name, nil
		}
	}
	const prefix = "/qkd_applications/qkd_app="
	if !strings.HasPrefix(suffix, prefix) {
		return nil, "", nil
	}
	parts := strings.Split(strings.TrimPrefix(suffix, prefix), "/")
	for i, app := range v.Apps {
		if string(app.AppID) != parts[0] {
			continue
		}
		data := node["qkd_applications"].(map[string]any)["qkd_app"].([]map[string]any)[i]
		if len(parts) == 1 {
			return []map[string]any{data}, "qkd_app", &app
		}
		if len(parts) == 2 && parts[1] == "app_qos" {
			return data["app_qos"], "app_qos", &app
		}
		if len(parts) == 3 && parts[1] == "app_qos" && parts[2] == "ttl" {
			return app.Rule.MaxLocalAgeSeconds, "ttl", &app
		}
	}
	return nil, "", nil
}
func etag(revision uint64) string { return `"` + strconv.FormatUint(revision, 10) + `"` }
func matchRevision(s string) (uint64, bool) {
	n, e := strconv.ParseUint(strings.Trim(s, `"`), 10, 64)
	return n, e == nil && s == etag(n)
}
func body(r *http.Request, want string) ([]byte, int) {
	kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || kind != want {
		return nil, 415
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 16385))
	if e != nil || len(b) > 16384 {
		return nil, 413
	}
	return b, 0
}
func decodeCommand(b []byte, out *allocation.Command) error {
	if metadata.DecodeRequest(b, out, "command_id", "expected_revision", "association", "rule", "routes", "local_ttl_seconds") != nil || !out.Valid() {
		return core.ErrInvalid
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if fields["expected_revision"] == nil || metadata.DecodeRequest(fields["association"], &out.Association, "master", "slave") != nil {
		return core.ErrInvalid
	}
	if out.Rule != nil {
		names := []string{"paused", "allowed_sources", "allowed_issuers", "require_evidence", "allow_satellite", "max_generation_age_seconds", "max_local_age_seconds", "max_keys_per_request"}
		var keys map[string]json.RawMessage
		_ = json.Unmarshal(fields["rule"], &keys)
		if len(keys) != len(names) || metadata.DecodeRequest(fields["rule"], out.Rule, names...) != nil {
			return core.ErrInvalid
		}
	}
	return nil
}
func errorStatus(err error) int {
	switch {
	case errors.Is(err, allocation.ErrConflict):
		return 409
	case errors.Is(err, core.ErrUnauthorized):
		return 403
	case errors.Is(err, core.ErrInvalid):
		return 400
	default:
		return 503
	}
}
func write(w http.ResponseWriter, content string, v any) {
	w.Header().Set("Content-Type", content)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, standard bool) {
	content := "application/json"
	var v any = map[string]string{"message": http.StatusText(status)}
	if standard {
		content = media
		tag := "operation-failed"
		switch status {
		case 401, 403:
			tag = "access-denied"
		case 404:
			tag = "data-missing"
		case 405:
			tag = "operation-not-supported"
		case 400:
			tag = "invalid-value"
		}
		v = map[string]any{"ietf-restconf:errors": map[string]any{"error": []map[string]string{{"error-type": "application", "error-tag": tag, "error-message": http.StatusText(status)}}}}
	}
	w.Header().Set("Content-Type", content)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
