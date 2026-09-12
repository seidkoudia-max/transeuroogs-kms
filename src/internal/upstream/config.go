// Package upstream defines the explicit, synthetic segmented-service profile.
package upstream

import (
	"net/url"
	"strings"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const Profile = "synthetic-segmented-v1"

// FinalProfile is a deliberately bounded 014 adapter, not a claim of SES conformance.
const FinalProfile = "etsi014-final-uuidv4-256-v1"

const LinkProfile = "etsi014-link-uuidv4-256-v1"

type Config struct {
	EvidenceDir     string `json:"evidence_dir,omitempty"`
	Agreement       string `json:"interface_agreement,omitempty"`
	Profile         string `json:"profile"`
	URL             string `json:"url"`
	ServerIdentity  string `json:"server_identity"`
	GatewayIdentity string `json:"gateway_identity"`
	GatewayMaster   string `json:"gateway_master"`
	GatewaySlave    string `json:"gateway_slave"`
	Role            string `json:"role"`
	RemoteKMEID     string `json:"remote_kme_id"`
	PKIDir          string `json:"pki_dir"`
	CertificateName string `json:"certificate_name"`
	StateDir        string `json:"state_dir"`
	LifetimeSeconds int    `json:"lifetime_seconds"`
}

func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return core.ErrInvalid
	}
	if (c.Profile != Profile && (c.Agreement == "" || (c.Profile != LinkProfile && (c.Profile != FinalProfile || c.EvidenceDir == "")))) || (c.Role != "master" && c.Role != "slave") || c.StateDir == "" || c.PKIDir == "" || c.CertificateName == "" || strings.ContainsAny(c.CertificateName, "/\\") || c.CertificateName == "." || c.CertificateName == ".." || c.RemoteKMEID == "" || c.LifetimeSeconds < 1 || c.LifetimeSeconds > 86400 {
		return core.ErrInvalid
	}
	if !(core.Association{Master: c.GatewayMaster, Slave: c.GatewaySlave}).Valid() {
		return core.ErrInvalid
	}
	for _, s := range []string{c.ServerIdentity, c.GatewayIdentity} {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "urn" || u.Opaque == "" {
			return core.ErrInvalid
		}
	}
	return nil
}
