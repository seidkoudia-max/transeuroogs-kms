package sdnapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
)

// The local catalog grants authority. 015 registration cannot introduce a new
// SAE, trust relationship, interface, device URL, or physical adapter.
func serviceMutation(w http.ResponseWriter, r *http.Request, manager allocation.Manager, c allocation.Config, saes map[string]string, actor string) bool {
	suffix := strings.TrimPrefix(r.URL.Path, NodePath)
	kind, id := "", core.KeyID("")
	for _, k := range []string{"app", "link"} {
		container, list := "/qkd_applications", "qkd_app"
		if k == "link" {
			container, list = "/qkd_links", "qkd_link"
		}
		if suffix == container && r.Method == "POST" {
			kind = k
		}
		if strings.HasPrefix(suffix, container+"/"+list+"=") {
			tail := strings.TrimPrefix(suffix, container+"/"+list+"=")
			if !strings.Contains(tail, "/") && (r.Method == "PUT" || r.Method == "DELETE") {
				kind = k
				id = core.KeyID(tail)
			}
		}
	}
	if kind == "" {
		return false
	}
	fail := func(status int) { failure(w, status, true) }
	grant := c.Principals[actor]
	if !grant.Services || !grant.Write {
		fail(403)
		return true
	}
	revision, ok := matchRevision(r.Header.Get("If-Match"))
	commandID := core.KeyID(r.Header.Get("X-Command-ID"))
	if !ok || !commandID.Valid() {
		fail(428)
		return true
	}
	var change allocation.ServiceCommand
	if r.Method == "DELETE" {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			fail(400)
			return true
		}
		change = allocation.ServiceCommand{ID: id, Operation: map[string]string{"app": "application_delete", "link": "link_delete"}[kind]}
	} else {
		b, status := body(r, media)
		if status != 0 {
			fail(status)
			return true
		}
		var err error
		change, err = decodeServiceResource(b, kind, c, saes)
		if err != nil || (r.Method == "PUT" && id != change.ID) {
			fail(400)
			return true
		}
		change.Operation = map[string]string{"app": "application_", "link": "link_"}[kind] + map[string]string{"POST": "create", "PUT": "update"}[r.Method]
	}
	pair := core.Association{}
	if kind == "app" {
		for _, a := range c.Apps {
			if a.AppID == change.ID {
				pair = a.Association
			}
		}
	} else {
		if l, ok := c.Services.Link(change.ID); ok {
			pair = l.Association
		}
	}
	if !pair.Valid() || !slices.Contains(grant.Pairs, pair) {
		fail(403)
		return true
	}
	result, err := manager.ApplyCommand(actor, allocation.Command{ID: commandID, ExpectedRevision: revision, Association: pair, Service: &change})
	if err != nil {
		status := errorStatus(err)
		if status == 409 {
			status = 412
		}
		fail(status)
		return true
	}
	w.Header().Set("ETag", etag(result.Revision))
	if r.Method == "POST" {
		container, list := "qkd_applications", "qkd_app"
		if kind == "link" {
			container, list = "qkd_links", "qkd_link"
		}
		w.Header().Set("Location", NodePath+"/"+container+"/"+list+"="+string(change.ID))
		w.WriteHeader(201)
	} else {
		w.WriteHeader(204)
	}
	return true
}

func decodeServiceResource(b []byte, kind string, c allocation.Config, saes map[string]string) (allocation.ServiceCommand, error) {
	name := "etsi-qkd-sdn-node:qkd_app"
	if kind == "link" {
		name = "etsi-qkd-sdn-node:qkd_link"
	}
	var fields map[string]json.RawMessage
	if metadata.DecodeRequest(b, &fields, name) != nil || len(fields) != 1 {
		return allocation.ServiceCommand{}, core.ErrInvalid
	}
	var items []json.RawMessage
	if json.Unmarshal(fields[name], &items) != nil || len(items) != 1 {
		return allocation.ServiceCommand{}, core.ErrInvalid
	}
	raw := items[0]
	if kind == "link" {
		var v struct {
			ID      core.KeyID `json:"qkdl_id"`
			Enabled *bool      `json:"qkdl_enable"`
		}
		if metadata.DecodeRequest(raw, &v, "qkdl_id", "qkdl_enable") != nil || !v.ID.Valid() || v.Enabled == nil {
			return allocation.ServiceCommand{}, core.ErrInvalid
		}
		return allocation.ServiceCommand{ID: v.ID, Enabled: v.Enabled}, nil
	}
	var v struct {
		ID      core.KeyID      `json:"app_id"`
		Type    string          `json:"app_type"`
		Server  string          `json:"server_app_id"`
		Clients []string        `json:"client_app_id"`
		Local   core.KeyID      `json:"local_qkdn_id"`
		Remote  core.KeyID      `json:"remote_qkdn_id"`
		Expires *time.Time      `json:"expiration_time"`
		Links   []core.KeyID    `json:"backing_qkdl_id"`
		QoS     json.RawMessage `json:"app_qos"`
	}
	if metadata.DecodeRequest(raw, &v, "app_id", "app_type", "server_app_id", "client_app_id", "local_qkdn_id", "remote_qkdn_id", "expiration_time", "backing_qkdl_id", "app_qos") != nil {
		return allocation.ServiceCommand{}, core.ErrInvalid
	}
	var qos struct {
		TTL  *uint32 `json:"ttl"`
		Path bool    `json:"clients_shared_path_enable"`
		Keys bool    `json:"clients_shared_keys_required"`
	}
	if metadata.DecodeRequest(v.QoS, &qos, "ttl", "clients_shared_path_enable", "clients_shared_keys_required") != nil || qos.TTL == nil || qos.Path || qos.Keys {
		return allocation.ServiceCommand{}, core.ErrInvalid
	}
	for _, app := range c.Apps {
		if app.AppID == v.ID && v.Type == "etsi-qkd-node-types:CLIENT" && v.Local == c.NodeID && v.Remote == app.RemoteNodeID && v.Server == saes[app.Association.Master] && slices.Equal(v.Clients, []string{saes[app.Association.Slave]}) {
			return allocation.ServiceCommand{ID: v.ID, TTL: qos.TTL, Expires: v.Expires, Links: v.Links}, nil
		}
	}
	return allocation.ServiceCommand{}, core.ErrInvalid
}

func linkInventory(v allocation.View) ([]map[string]any, []map[string]any) {
	interfaces, links := []map[string]any{}, []map[string]any{}
	for _, link := range v.Links {
		c, s := link.Catalog, link.State
		iface := map[string]any{"qkdi_id": c.LocalInterface, "qkdi_model": c.Model, "qkdi_type": "etsi-qkd-node-types:" + c.Technology}
		if link.Fresh && s.Report != nil {
			iface["qkdi_status"] = "etsi-qkd-node-types:" + s.Report.InterfaceStatus
		}
		interfaces = append(interfaces, iface)
		if !s.Present {
			continue
		}
		item := map[string]any{"qkdl_id": c.ID, "qkdl_enable": s.Enabled, "qkdl_type": "etsi-qkd-node-types:PHYS", "qkdl_local": map[string]any{"qkdn_id": v.NodeID, "qkdi_id": c.LocalInterface}, "qkdl_remote": map[string]any{"qkdn_id": c.RemoteNode, "qkdi_id": c.RemoteInterface}}
		if link.Fresh && s.Report != nil {
			item["qkdl_status"] = "etsi-qkd-node-types:" + s.Report.Status
			item["qkdl_performance"] = performance(s.Report)
		}
		apps := []core.KeyID{}
		for _, app := range v.Apps {
			if app.Service != nil && app.Service.Registered && slices.Contains(app.Service.Links, c.ID) {
				apps = append(apps, app.AppID)
			}
		}
		item["qkdl_applications"] = apps
		links = append(links, item)
	}
	return interfaces, links
}
func performance(r *allocation.LinkReport) map[string]any {
	p := map[string]any{}
	if r.SKR != nil {
		p["skr"] = *r.SKR
	}
	if r.ESKR != nil {
		p["eskr"] = *r.ESKR
	}
	// The pinned model's physical-performance when compares the qualified
	// identityref to the unqualified string 'PHYS'. Keep QBER in project reports
	// until an agreed model/validator profile resolves that condition.
	return p
}

// Bounded, durable, scoped event pages deliberately use a project endpoint.
// This is not advertised as the RFC 8040 notification-stream transport or 023.
// Four commands fit the audited response limit even at maximum request size.
func changes(w http.ResponseWriter, r *http.Request, manager allocation.Manager, pairs []core.Association) {
	reader, ok := manager.(allocation.ChangeReader)
	if !ok {
		failure(w, 503, false)
		return
	}
	after, err := strconv.ParseUint(r.Header.Get("X-After-Revision"), 10, 64)
	if err != nil {
		failure(w, 400, false)
		return
	}
	page, err := reader.ManagementChanges(pairs, after, 4)
	if err != nil {
		failure(w, errorStatus(err), false)
		return
	}
	w.Header().Set("ETag", etag(page.Revision))
	write(w, "application/json", page)
}
