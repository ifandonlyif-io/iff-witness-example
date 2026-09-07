package witness

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func pinSettingsBody(ids []string) string {
	raw, _ := json.Marshal(map[string]any{"iff_key_ids": ids})
	return string(raw)
}

func TestWitnessIFFPinSettingsPartialUpdatesPreserveOtherField(t *testing.T) {
	first := "sha256:" + strings.Repeat("a", 64)
	second := "sha256:" + strings.Repeat("b", 64)
	inputPins := []string{first, first}
	s, err := NewServer(Config{APIKey: "test-only-initial-key", TrustedKeyIDs: inputPins})
	if err != nil {
		t.Fatal(err)
	}
	// The startup slice is copied and the immutable Config is not a fallback.
	inputPins[0] = second
	if len(s.config.TrustedKeyIDs) != 0 {
		t.Fatal("runtime trust was retained as a stale config fallback")
	}
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Error("settings dispatched an upstream request")
		return nil, errors.New("unexpected request")
	})
	s.consumeLiveCheck()
	for _, step := range []struct {
		body, wantSecret, keySource, pinSource string
		pins                                   []string
	}{
		{"", "test-only-initial-key", "environment", "environment", []string{first}},
		{pinSettingsBody([]string{second, first, second}), "test-only-initial-key", "environment", "session", []string{second, first}},
		{`{"api_key":"test-only-replacement"}`, "test-only-replacement", "session", "session", []string{second, first}},
		{`{"iff_key_ids":[]}`, "test-only-replacement", "session", "none", []string{}},
		{pinSettingsBody([]string{first}), "test-only-replacement", "session", "session", []string{first}},
		{`{"api_key":""}`, "", "none", "session", []string{first}},
		{`{"api_key":"test-only-combined","iff_key_ids":[]}`, "test-only-combined", "session", "none", []string{}},
	} {
		method := "POST"
		if step.body == "" {
			method = "GET"
		}
		w := settingsRequest(s, method, step.body, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("settings rejected: %d %s", w.Code, w.Body.String())
		}
		var result struct {
			Pins      []string `json:"iff_key_ids"`
			PinSource string   `json:"iff_key_ids_source"`
			KeySource string   `json:"source"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || !reflect.DeepEqual(result.Pins, step.pins) || result.PinSource != step.pinSource || result.KeySource != step.keySource {
			t.Fatal("incorrect safe settings metadata")
		}
		s.keyMu.RLock()
		secretMatches := s.activeAPIKey == step.wantSecret
		s.keyMu.RUnlock()
		if !secretMatches || s.remainingLiveChecks() != 29 {
			t.Fatal("partial update changed an omitted key or reset the budget")
		}
		if strings.Contains(w.Body.String(), "test-only-") || strings.Contains(w.Body.String(), `"api_key"`) {
			t.Fatal("settings response exposed a secret")
		}
		r := httptest.NewRequest("GET", "http://127.0.0.1:8094/api/config", nil)
		cw := httptest.NewRecorder()
		s.Handler().ServeHTTP(cw, r)
		var config struct {
			Pins []string `json:"trusted_key_ids"`
		}
		if json.Unmarshal(cw.Body.Bytes(), &config) != nil || !reflect.DeepEqual(config.Pins, step.pins) {
			t.Fatal("public config returned stale trust pins")
		}
	}
}

func TestWitnessIFFPinSettingsStrictGrammarAndAtomicValidation(t *testing.T) {
	s := testWitnessServer(t, true)
	validID := "sha256:" + strings.Repeat("a", 64)
	if w := settingsRequest(s, "POST", pinSettingsBody([]string{validID}), nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	badBodies := []string{
		`null`, `[]`, `{}`, `{"iff_key_ids":null}`, `{"iff_key_ids":"text"}`, `{"iff_key_ids":{}}`,
		`{"iff_key_ids":[null]}`, `{"iff_key_ids":[42]}`, `{"iff_key_ids":[[]]}`,
		`{"IFF_KEY_IDS":[]}`, `{"iff_key_ids":[],"IFF_KEY_IDS":[]}`, `{"iff_key_ids":[],"unknown":true}`,
		`{"iff_key_ids":[],"iff_key_ids":[]}`, `{"iff_key_ids":[],"iff\u005fkey_ids":[]}`,
		`{"api_key":"test-only-wrong-replacement","iff_key_ids":["invalid"]}`,
		`{"api_key":null,"iff_key_ids":[]}`, `{"api_key":"bad\nkey","iff_key_ids":[]}`,
		pinSettingsBody(make([]string, maxIFFKeyIDs+1)),
		`{"iff_key_ids":["` + strings.Repeat("a", maxSettingsBodyBytes) + `"]}`,
	}
	for _, invalid := range []string{
		"", "sha256:", "SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), "sha256:" + strings.Repeat("g", 64),
		" " + validID, validID + " ", validID[:70] + "\n", validID[:70] + "\x00", "sha256:" + strings.Repeat("非", 64),
	} {
		badBodies = append(badBodies, pinSettingsBody([]string{invalid}))
		if _, err := NewServer(Config{TrustedKeyIDs: []string{invalid}}); err == nil {
			t.Fatal("startup accepted a noncanonical pin")
		}
	}
	for _, body := range badBodies {
		w := settingsRequest(s, "POST", body, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid settings accepted: status %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "test-only-wrong-replacement") {
			t.Fatal("invalid combined update echoed its secret")
		}
		state := s.runtimeSettingsState()
		s.keyMu.RLock()
		secretPreserved := s.activeAPIKey == "test-only-key"
		s.keyMu.RUnlock()
		if !reflect.DeepEqual(state.iffKeyIDs, []string{validID}) || !secretPreserved || s.remainingLiveChecks() != 30 {
			t.Fatal("invalid combined update partially changed state")
		}
	}
	ids := make([]string, maxIFFKeyIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("sha256:%064x", i)
	}
	maxBody, _ := json.Marshal(map[string]any{"api_key": strings.Repeat("a", maxAPIKeyBytes), "iff_key_ids": ids})
	if len(maxBody) > maxSettingsBodyBytes || settingsRequest(s, "POST", string(maxBody), nil).Code != http.StatusOK {
		t.Fatal("documented maximum-sized settings were rejected")
	}
	if _, err := NewServer(Config{TrustedKeyIDs: append(ids, ids[0])}); err == nil {
		t.Fatal("startup accepted more than 16 submitted IDs")
	}
}

func TestWitnessLiveIFFPolicyIsOneSnapshotDespiteSettingsChanges(t *testing.T) {
	for _, test := range []struct {
		name, initial, updated, pausePath, expectedTrust string
		initialStatus, nextStatus                        int
	}{
		{"pin replaced during card", "good", "bad", "/api/v3/evidence/check", "independently_pinned", 200, 502},
		{"pin cleared after directory", "good", "none", "/api/v3/verify", "independently_pinned", 200, 200},
		{"pin added after directory", "none", "good", "/api/v3/verify", "origin_recognized", 200, 200},
		{"untrusted check stays rejected", "bad", "good", "/api/v3/evidence/check", "", 502, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := testWitnessServer(t, true)
			pins := func(policy string) []string {
				switch policy {
				case "good":
					return []string{s.signer.KeyID()}
				case "bad":
					return []string{"sha256:" + strings.Repeat("0", 64)}
				default:
					return []string{}
				}
			}
			if settingsRequest(s, "POST", pinSettingsBody(pins(test.initial)), nil).Code != 200 {
				t.Fatal("initial pins rejected")
			}
			entered, release := make(chan struct{}), make(chan struct{})
			calls := 0
			base := liveWitnessTransport(t, s, "router_verified", &calls)
			var once sync.Once
			s.client.Transport = witnessTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == test.pausePath {
					once.Do(func() { close(entered); <-release })
				}
				return base(r)
			})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"pin-policy-snapshot"}`)
			}()
			<-entered
			w := settingsRequest(s, "POST", pinSettingsBody(pins(test.updated)), nil)
			close(release)
			if w.Code != 200 {
				t.Fatal("updated pins rejected")
			}
			first := <-done
			if first.Code != test.initialStatus {
				t.Fatalf("inflight policy changed: status %d", first.Code)
			}
			if first.Code == 200 {
				var bundle Bundle
				if json.Unmarshal(first.Body.Bytes(), &bundle) != nil || bundle.IFF.Verification.IssuerTrust != test.expectedTrust {
					t.Fatal("trust claim did not use receipt verification's policy snapshot")
				}
			} else if calls != 0 || s.remainingLiveChecks() != 30 {
				t.Fatal("rejected trust policy still used inference budget")
			}
			second := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"new-pin-policy"}`)
			if second.Code != test.nextStatus {
				t.Fatalf("next check did not use updated policy: status %d", second.Code)
			}
		})
	}
}

func TestWitnessIFFPinSnapshotsAreRaceSafeAndIndependent(t *testing.T) {
	s := testWitnessServer(t, true)
	first := "sha256:" + strings.Repeat("a", 64)
	second := "sha256:" + strings.Repeat("b", 64)
	settingsRequest(s, "POST", pinSettingsBody([]string{first}), nil)
	snapshot := s.runtimeSettingsState()
	snapshot.iffKeyIDs[0] = second
	if s.runtimeSettingsState().iffKeyIDs[0] != first {
		t.Fatal("snapshot aliases the active trust policy")
	}
	var workers sync.WaitGroup
	for index := 0; index < 60; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			if index%2 == 0 {
				settingsRequest(s, "POST", pinSettingsBody([]string{first, second}), nil)
			} else {
				settingsRequest(s, "POST", `{"api_key":"test-only-concurrent","iff_key_ids":[]}`, nil)
			}
			settingsRequest(s, "GET", "", nil)
			state := s.runtimeSettingsState()
			if len(state.iffKeyIDs) != 0 && !reflect.DeepEqual(state.iffKeyIDs, []string{first, second}) {
				t.Error("observed a partially updated trust policy")
			}
			if len(state.iffKeyIDs) == 0 && state.iffKeyIDsSource != "none" || len(state.iffKeyIDs) > 0 && state.iffKeyIDsSource != "session" {
				t.Error("pin source and pins were not an atomic snapshot")
			}
			_, _ = s.reserveComputeKey()
		}(index)
	}
	workers.Wait()
}
