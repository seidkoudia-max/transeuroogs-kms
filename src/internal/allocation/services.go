package allocation

import (
	"slices"
	"strconv"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

// ServiceConfig is locally provisioned authority, not a controller-supplied
// catalog. A missing physical adapter is represented explicitly as pending.
type ServiceConfig struct {
	Links []LinkCatalog `json:"links"`
}
type LinkCatalog struct {
	ID                    core.KeyID       `json:"link_id"`
	Association           core.Association `json:"association"`
	LocalInterface        uint32           `json:"local_interface"`
	RemoteInterface       uint32           `json:"remote_interface"`
	RemoteNode            core.KeyID       `json:"remote_node_id"`
	Model                 string           `json:"model"`
	Technology            string           `json:"technology"`
	AdapterIdentity       string           `json:"adapter_identity"`
	Mode                  string           `json:"mode"` // synthetic | adapter | pending
	Agreement             string           `json:"interface_agreement,omitempty"`
	ObservationTTLSeconds uint32           `json:"observation_ttl_seconds"`
}
type ApplicationService struct {
	Registered bool         `json:"registered"`
	Created    time.Time    `json:"created_at"`
	Expires    *time.Time   `json:"expires_at,omitempty"`
	Links      []core.KeyID `json:"backing_links"`
}
type LinkService struct {
	Present  bool        `json:"present"`
	Enabled  bool        `json:"enabled"`
	Revision uint64      `json:"desired_revision"`
	Report   *LinkReport `json:"report,omitempty"`
}
type LinkReport struct {
	Sequence        uint64    `json:"sequence"`
	DesiredRevision uint64    `json:"desired_revision"`
	Observed        time.Time `json:"observed_at"`
	Status          string    `json:"status"`           // ACTIVE | PASSIVE | PENDING | OFF
	InterfaceStatus string    `json:"interface_status"` // ENABLED | DISABLED | FAILED
	SKR             *uint32   `json:"skr,omitempty"`
	ESKR            *uint32   `json:"eskr,omitempty"`
	QBER            *string   `json:"qber,omitempty"` // decimal64, three fractional digits
}
type ServiceState struct {
	Applications map[core.KeyID]ApplicationService `json:"applications"`
	Links        map[core.KeyID]LinkService        `json:"links"`
}
type ServiceCommand struct {
	Operation string       `json:"operation"` // application_create/update/delete | link_create/update/delete/report
	ID        core.KeyID   `json:"resource_id"`
	TTL       *uint32      `json:"ttl,omitempty"`
	Expires   *time.Time   `json:"expires_at,omitempty"`
	Links     []core.KeyID `json:"backing_links,omitempty"`
	Enabled   *bool        `json:"enabled,omitempty"`
	Report    *LinkReport  `json:"report,omitempty"`
}

func (c *ServiceConfig) valid(config Config) bool {
	if c == nil {
		return true
	}
	if len(c.Links) > 64 {
		return false
	}
	ids, interfaces := map[core.KeyID]bool{}, map[uint32]bool{}
	for _, link := range c.Links {
		if !link.ID.Valid() || ids[link.ID] || interfaces[link.LocalInterface] || !link.RemoteNode.Valid() || !Name(link.Model) || !slices.Contains([]string{"CV-QKD", "DV-QKD", "DV-QKD-COW", "DV-QKD-2Ws"}, link.Technology) || !URI(link.AdapterIdentity) || !slices.Contains([]string{"synthetic", "adapter", "pending"}, link.Mode) || link.ObservationTTLSeconds < 1 || link.ObservationTTLSeconds > 3600 || (link.Mode == "adapter" && !Name(link.Agreement)) {
			return false
		}
		found := false
		for _, app := range config.Apps {
			if app.Association == link.Association && app.RemoteNodeID == link.RemoteNode {
				found = true
			}
		}
		p, ok := config.Principals[link.AdapterIdentity]
		if !found || !ok || !p.Telemetry || !slices.Contains(p.Pairs, link.Association) {
			return false
		}
		ids[link.ID], interfaces[link.LocalInterface] = true, true
	}
	return true
}
func newServices(c *ServiceConfig) *ServiceState {
	if c == nil {
		return nil
	}
	return &ServiceState{Applications: map[core.KeyID]ApplicationService{}, Links: map[core.KeyID]LinkService{}}
}
func (c *ServiceConfig) Link(id core.KeyID) (LinkCatalog, bool) {
	if c != nil {
		for _, link := range c.Links {
			if link.ID == id {
				return link, true
			}
		}
	}
	return LinkCatalog{}, false
}
func (v *ServiceCommand) Valid() bool {
	if v == nil || !v.ID.Valid() {
		return false
	}
	if !slices.Contains([]string{"application_create", "application_update", "application_delete", "link_create", "link_update", "link_delete", "link_report"}, v.Operation) {
		return false
	}
	if v.TTL != nil && (*v.TTL < 1 || *v.TTL > 2678400) {
		return false
	}
	if len(v.Links) > 64 {
		return false
	}
	for i, id := range v.Links {
		if !id.Valid() || slices.Contains(v.Links[:i], id) {
			return false
		}
	}
	switch v.Operation {
	case "application_create", "application_update":
		return v.TTL != nil && v.Enabled == nil && v.Report == nil
	case "application_delete", "link_delete":
		return v.TTL == nil && v.Expires == nil && len(v.Links) == 0 && v.Enabled == nil && v.Report == nil
	case "link_create", "link_update":
		return v.TTL == nil && v.Expires == nil && len(v.Links) == 0 && v.Enabled != nil && v.Report == nil
	case "link_report":
		return v.TTL == nil && v.Expires == nil && len(v.Links) == 0 && v.Enabled == nil && v.Report != nil && v.Report.Valid()
	}
	return false
}
func (r LinkReport) Valid() bool {
	if r.Sequence == 0 || r.DesiredRevision == 0 || r.Observed.IsZero() || !slices.Contains([]string{"ACTIVE", "PASSIVE", "PENDING", "OFF"}, r.Status) || !slices.Contains([]string{"ENABLED", "DISABLED", "FAILED"}, r.InterfaceStatus) {
		return false
	}
	if r.SKR != nil && r.ESKR != nil && *r.ESKR > *r.SKR {
		return false
	}
	if r.QBER != nil {
		s := *r.QBER
		if len(s) < 5 || len(s) > 7 || s[len(s)-4] != '.' {
			return false
		}
		for i, b := range s {
			if i == len(s)-4 {
				continue
			}
			if b < '0' || b > '9' {
				return false
			}
		}
		n, e := strconv.ParseFloat(s, 64)
		if e != nil || n < 0 || n > 100 {
			return false
		}
	}
	return true
}
func (s *State) ServiceGate(a core.Association, now time.Time) string {
	if s == nil || s.Services == nil {
		return ""
	}
	for _, app := range s.Apps {
		if app.Association != a {
			continue
		}
		v := s.Services.Applications[app.AppID]
		if !v.Registered {
			return "application_unregistered"
		}
		if v.Expires != nil && !now.Before(*v.Expires) {
			return "application_expired"
		}
		return ""
	}
	return "association_denied"
}
func (s *State) serviceApply(setup *Setup, actor string, command Command, now time.Time) error {
	v := command.Service
	if s.Services == nil || setup.Config.Services == nil || !v.Valid() {
		return core.ErrInvalid
	}
	appID := core.KeyID("")
	for _, app := range s.Apps {
		if app.Association == command.Association {
			appID = app.AppID
		}
	}
	if v.Operation == "application_create" || v.Operation == "application_update" || v.Operation == "application_delete" {
		if appID != v.ID {
			return core.ErrUnauthorized
		}
		old := s.Services.Applications[v.ID]
		if (v.Operation == "application_create" && old.Registered) || (v.Operation != "application_create" && !old.Registered) {
			return ErrConflict
		}
		if v.Operation == "application_delete" {
			old.Registered = false
			s.Services.Applications[v.ID] = old
			return nil
		}
		if v.Expires != nil && (!now.Before(*v.Expires) || v.Expires.Sub(now) > 31*24*time.Hour) {
			return core.ErrInvalid
		}
		for _, id := range v.Links {
			catalog, ok := setup.Config.Services.Link(id)
			link := s.Services.Links[id]
			if !ok || catalog.Association != command.Association || !link.Present || !link.Enabled || !linkReady(catalog, link, now) {
				return core.ErrUnavailable
			}
		}
		if !old.Registered {
			old.Created = now.UTC()
		}
		old.Registered = true
		old.Expires = Clone(v.Expires)
		old.Links = slices.Clone(v.Links)
		s.Services.Applications[v.ID] = old
		for i := range s.Apps {
			if s.Apps[i].AppID == v.ID {
				s.Apps[i].Rule.MaxLocalAgeSeconds = *v.TTL
			}
		}
		return nil
	}
	catalog, ok := setup.Config.Services.Link(v.ID)
	if !ok || catalog.Association != command.Association {
		return core.ErrUnauthorized
	}
	old := s.Services.Links[v.ID]
	if v.Operation == "link_report" {
		if actor != catalog.AdapterIdentity || catalog.Mode == "pending" {
			return core.ErrUnauthorized
		}
		r := v.Report
		if r.DesiredRevision != old.Revision || old.Revision == 0 || r.Observed.After(now) || now.Sub(r.Observed) > time.Duration(catalog.ObservationTTLSeconds)*time.Second || (old.Report != nil && (r.Sequence <= old.Report.Sequence || r.Observed.Before(old.Report.Observed))) {
			return ErrConflict
		}
		if (!old.Present || !old.Enabled) && r.Status != "OFF" && r.Status != "PASSIVE" {
			return core.ErrInvalid
		}
		old.Report = Clone(r)
		s.Services.Links[v.ID] = old
		return nil
	}
	if (v.Operation == "link_create" && old.Present) || (v.Operation != "link_create" && !old.Present) {
		return ErrConflict
	}
	if v.Operation == "link_delete" {
		for _, app := range s.Services.Applications {
			if app.Registered && slices.Contains(app.Links, v.ID) {
				return ErrConflict
			}
		}
		old.Present = false
		old.Enabled = false
	} else {
		old.Present = true
		old.Enabled = *v.Enabled
	}
	old.Revision = s.Revision + 1
	// A previous observation is not an acknowledgement of a new desired state.
	s.Services.Links[v.ID] = old
	return nil
}
func observationFresh(c LinkCatalog, l LinkService, now time.Time) bool {
	return l.Report != nil && l.Report.DesiredRevision == l.Revision && !l.Report.Observed.After(now) && now.Sub(l.Report.Observed) <= time.Duration(c.ObservationTTLSeconds)*time.Second
}

type ManagedLink struct {
	Catalog LinkCatalog `json:"catalog"`
	State   LinkService `json:"state"`
	Fresh   bool        `json:"observation_fresh"`
	Needed  []string    `json:"needed_input"`
}

func (s *State) serviceView(setup *Setup, out *View, pairs []core.Association, now time.Time) {
	if s.Services == nil {
		return
	}
	for i := range out.Apps {
		v := Clone(s.Services.Applications[out.Apps[i].AppID])
		out.Apps[i].Service = &v
	}
	for _, c := range setup.Config.Services.Links {
		if !slices.Contains(pairs, c.Association) {
			continue
		}
		l := s.Services.Links[c.ID]
		v := ManagedLink{Catalog: c, State: Clone(l), Fresh: observationFresh(c, l, now)}
		if c.Mode == "pending" {
			v.Needed = []string{"DEVICE-M01: control interface agreement", "DEVICE-M02: adapter and device credentials", "DEVICE-M03: telemetry semantics and acceptance"}
		}
		out.Links = append(out.Links, v)
	}
}

type ChangePage struct {
	Revision uint64   `json:"revision"`
	Next     uint64   `json:"next_revision"`
	Changes  []Commit `json:"changes"`
}

func (s *State) Changes(pairs []core.Association, after uint64, limit int) (ChangePage, error) {
	if s == nil || after > s.Revision || limit < 1 || limit > 64 {
		return ChangePage{}, core.ErrInvalid
	}
	v := ChangePage{Revision: s.Revision, Next: after, Changes: []Commit{}}
	for _, c := range s.Commits {
		if c.Revision <= after {
			continue
		}
		if len(v.Changes) == limit {
			break
		}
		v.Next = c.Revision
		if slices.Contains(pairs, c.Command.Association) {
			v.Changes = append(v.Changes, Clone(c))
		}
	}
	return v, nil
}

func linkReady(c LinkCatalog, l LinkService, now time.Time) bool {
	return observationFresh(c, l, now) && l.Report.InterfaceStatus == "ENABLED" && (l.Report.Status == "ACTIVE" || l.Report.Status == "PASSIVE")
}
