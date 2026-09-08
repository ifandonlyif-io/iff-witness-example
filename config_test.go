package witness

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearWitnessEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "WITNESS_") {
			t.Setenv(name, "")
		}
	}
}

func TestWitnessFreshCloneLoadsEmbeddedExampleAndSettingsEnableLive(t *testing.T) {
	clearWitnessEnvironment(t)
	// Neither the repo's examples directory nor an .env is available here.
	t.Chdir(t.TempDir())
	config, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.Example == nil || config.Example.Mode != "live" || config.Example.URL != "https://x402-fixture.ifandonlyif.io/paid-resource" {
		t.Fatalf("public default example missing: %+v", config.Example)
	}
	s, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Error("startup, settings, or rehearsal attempted an external request")
		return nil, errors.New("unexpected external request")
	})
	if s.settingsResponse()["live_ready"] != false {
		t.Fatal("a fresh clone must still require a Router key for live mode")
	}
	w := settingsRequest(s, "POST", `{"api_key":"test-only-router-key"}`, nil)
	if w.Code != http.StatusOK || s.settingsResponse()["live_ready"] != true {
		t.Fatalf("saving a key did not enable live mode: %d %s", w.Code, w.Body.String())
	}
	w = postWitness(s, `{"mode":"rehearsal","scenario":"consistent","nonce":"fresh-clone"}`)
	if w.Code != http.StatusOK || s.remainingLiveChecks() != defaultMaxLiveChecks {
		t.Fatalf("rehearsal failed or spent inference budget: %d", w.Code)
	}
}

func TestWitnessExplicitExampleOverridesEmbeddedDefault(t *testing.T) {
	clearWitnessEnvironment(t)
	example := demoExample()
	example.ID = "custom-example"
	raw, err := json.Marshal(example)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WITNESS_EXAMPLE_FILE", path)
	config, err := ConfigFromEnv()
	if err != nil || config.Example == nil || config.Example.ID != example.ID || config.Example.URL != example.URL {
		t.Fatalf("explicit example was not used: %v", err)
	}
}

func TestWitnessInvalidExplicitExampleNeverFallsBack(t *testing.T) {
	clearWitnessEnvironment(t)
	for _, raw := range []string{"", "not-json", "null", "[]", `{"id":"a","id":"b"}`, strings.Repeat(" ", maxInputBytes+1), `{"url":"https://127.0.0.1/private"}`} {
		t.Run("invalid-example", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("WITNESS_EXAMPLE_FILE", path)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatal("invalid explicit example silently fell back to the default")
			}
		})
	}
	t.Setenv("WITNESS_EXAMPLE_FILE", filepath.Join(t.TempDir(), "missing.json"))
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("missing explicit example silently fell back to the default")
	}
}
