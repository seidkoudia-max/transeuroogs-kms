package synthetic

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

func TestInputOnlyCountsAndBoundedAcknowledgements(t *testing.T) {
	repo, _ := storage.NewMemory(8, nil)
	pair := core.Association{Master: "A", Slave: "B"}
	var output bytes.Buffer
	err := Input(strings.NewReader("{\"count\":2}\n{\"count\":3}\n"), &output, repo, pair, 5, time.Hour)
	if err != nil || repo.Inventory(pair).Available != 5 {
		t.Fatal("count input failed", err)
	}
	decoder := json.NewDecoder(&output)
	for _, total := range []int{2, 5} {
		var event map[string]any
		if decoder.Decode(&event) != nil || len(event) != 3 || event["total"] != float64(total) {
			t.Fatal("invalid material-free acknowledgement")
		}
	}
}

func TestInputInvalidOrExhaustedCannotProvisionMore(t *testing.T) {
	for _, input := range []string{"{\"count\":0}", "{\"count\":-1}", "{\"count\":9}", "{\"count\":1,\"key\":\"bad\"}", "{\"count\":1}{}", strings.Repeat(" ", 300)} {
		repo, _ := storage.NewMemory(8, nil)
		pair := core.Association{Master: "A", Slave: "B"}
		var output bytes.Buffer
		if Input(strings.NewReader(input), &output, repo, pair, 8, time.Hour) == nil || repo.Inventory(pair).Available != 0 {
			t.Fatal("invalid input minted material")
		}
	}
	repo, _ := storage.NewMemory(8, nil)
	pair := core.Association{Master: "A", Slave: "B"}
	var output bytes.Buffer
	if Input(strings.NewReader("{\"count\":3}\n{\"count\":3}\n"), &output, repo, pair, 4, time.Hour) == nil || repo.Inventory(pair).Available != 3 {
		t.Fatal("session limit bypassed")
	}
}
