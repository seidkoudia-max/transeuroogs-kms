package allocation_test

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"reflect"
	"testing"
	"time"
)

func TestServiceAuthorityAcknowledgementExpiryReplayAndScopedHistory(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	cfg := testallocation.Setup(a)
	testallocation.Services(cfg)
	now := time.Now().UTC()
	s, err := allocation.Open(cfg, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.ServiceGate(a, now) != "application_unregistered" || s.Preflight(a, 1, now) != "application_unregistered" {
		t.Fatal("unregistered delivery")
	}
	link := cfg.Config.Services.Links[0]
	enabled := true
	cmd := allocation.Command{ID: core.NewID(), Association: a, Service: &allocation.ServiceCommand{ID: link.ID, Operation: "link_create", Enabled: &enabled}}
	if err = allocation.Authorize(cfg, testallocation.Adapter, cmd); err != core.ErrUnauthorized {
		t.Fatal("adapter controlled link")
	}
	if _, err = s.Apply(cfg, testallocation.Actor, cmd, now); err != nil {
		t.Fatal(err)
	}
	create := testallocation.Service(cfg, 1, "application_create")
	create.Service.Links = []core.KeyID{link.ID}
	if _, err = s.Apply(cfg, testallocation.Actor, create, now); err != core.ErrUnavailable {
		t.Fatal("unacknowledged link admitted")
	}
	report := allocation.Command{ID: core.NewID(), ExpectedRevision: 1, Association: a, Service: &allocation.ServiceCommand{ID: link.ID, Operation: "link_report", Report: &allocation.LinkReport{Sequence: 1, DesiredRevision: 1, Observed: now, Status: "ACTIVE", InterfaceStatus: "ENABLED"}}}
	if err = allocation.Authorize(cfg, testallocation.Actor, report); err != core.ErrUnauthorized {
		t.Fatal("controller manufactured telemetry")
	}
	if _, err = s.Apply(cfg, testallocation.Actor, report, now); err != core.ErrUnauthorized {
		t.Fatal("adapter pin bypass")
	}
	if _, err = s.Apply(cfg, testallocation.Adapter, report, now); err != nil {
		t.Fatal(err)
	}
	create.ExpectedRevision = 2
	expires := now.Add(30 * time.Second)
	create.Service.Expires = &expires
	if _, err = s.Apply(cfg, testallocation.Actor, create, now); err != nil {
		t.Fatal(err)
	}
	if s.ServiceGate(a, now) != "" || s.ServiceGate(a, expires) != "application_expired" {
		t.Fatal("service lease")
	}
	if _, err = s.Apply(cfg, testallocation.Actor, create, expires); err != nil {
		t.Fatal("exact replay changed")
	}
	stale := allocation.Clone(report)
	stale.ID = core.NewID()
	stale.ExpectedRevision = 3
	if _, err = s.Apply(cfg, testallocation.Adapter, stale, now); err != allocation.ErrConflict {
		t.Fatal("replayed sequence")
	}
	stale.Service.Report.Sequence = 2
	stale.Service.Report.Observed = now.Add(time.Second)
	if _, err = s.Apply(cfg, testallocation.Adapter, stale, now); err != allocation.ErrConflict {
		t.Fatal("future report")
	}
	update := testallocation.Service(cfg, 3, "application_update")
	update.Service.Links = []core.KeyID{link.ID}
	if _, err = s.Apply(cfg, testallocation.Actor, update, now.Add(61*time.Second)); err != core.ErrUnavailable {
		t.Fatal("stale admission")
	}
	view := s.View(cfg, []core.Association{a}, now.Add(61*time.Second))
	if view.Links[0].Fresh {
		t.Fatal("stale observation advertised")
	}
	if _, err = allocation.Open(cfg, allocation.Clone(s), true); err != nil {
		t.Fatal("restart", err)
	}
	mutated := allocation.Clone(s)
	v := mutated.Services.Applications[create.Service.ID]
	v.Registered = false
	mutated.Services.Applications[create.Service.ID] = v
	if _, err = allocation.Open(cfg, mutated, true); err == nil {
		t.Fatal("tampered service snapshot")
	}
	page, err := s.Changes(nil, 0, 4)
	if err != nil || len(page.Changes) != 0 || page.Next != 3 {
		t.Fatal("scoped event leakage")
	}
	page, err = s.Changes([]core.Association{a}, 0, 1)
	if err != nil || page.Next != 1 || !reflect.DeepEqual(page.Changes[0].Command, cmd) {
		t.Fatal("event paging")
	}
}
func TestServiceConfigAndReportValidation(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	base := testallocation.Setup(a)
	testallocation.Services(base)
	for _, change := range []func(*allocation.Setup){
		func(s *allocation.Setup) {
			p := s.Config.Principals[testallocation.Actor]
			p.Telemetry = true
			s.Config.Principals[testallocation.Actor] = p
		},
		func(s *allocation.Setup) { s.Config.Services.Links[0].Mode = "adapter" },
		func(s *allocation.Setup) { s.Config.Services.Links[0].RemoteNode = "invalid" },
		func(s *allocation.Setup) {
			s.Config.Services.Links = append(s.Config.Services.Links, s.Config.Services.Links[0])
		},
	} {
		c := allocation.Clone(base)
		change(c)
		if c.Config.Validate([]core.Association{a}) == nil {
			t.Fatal("invalid catalog")
		}
	}
	c := allocation.Clone(base)
	c.Config.Services.Links[0].Mode = "pending"
	s, err := allocation.Open(c, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	cmd := allocation.Command{ID: core.NewID(), Association: a, Service: &allocation.ServiceCommand{ID: c.Config.Services.Links[0].ID, Operation: "link_create", Enabled: &enabled}}
	now := time.Now()
	if _, err = s.Apply(c, testallocation.Actor, cmd, now); err != nil {
		t.Fatal(err)
	}
	cmd.ID = core.NewID()
	cmd.ExpectedRevision = 1
	cmd.Service.Operation = "link_report"
	cmd.Service.Enabled = nil
	cmd.Service.Report = &allocation.LinkReport{Sequence: 1, DesiredRevision: 1, Observed: now, Status: "ACTIVE", InterfaceStatus: "ENABLED"}
	if _, err = s.Apply(c, testallocation.Adapter, cmd, now); err != core.ErrUnauthorized {
		t.Fatal("pending adapter acknowledged")
	}
	if len(s.View(c, []core.Association{a}, now).Links[0].Needed) != 3 {
		t.Fatal("missing vendor inputs")
	}
	for _, qber := range []string{"NaN", "1.0", "-0.010", "101.000", "1e2"} {
		r := *cmd.Service.Report
		r.QBER = &qber
		if r.Valid() {
			t.Fatal("invalid decimal", qber)
		}
	}
}

func TestBackingLinkMayTerminateAtAnIntermediateTrustedNode(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	s := testallocation.Setup(a)
	testallocation.Services(s)
	s.Config.Services.Links[0].RemoteNode = core.NewID()
	if s.Config.Validate([]core.Association{a}) != nil {
		t.Fatal("locally approved intermediate link rejected")
	}
}
