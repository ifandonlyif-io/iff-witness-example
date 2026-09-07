package witness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func settingsRequest(s *Server, method, body string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8094/api/settings", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:56789"
	if method == http.MethodPost {
		r.Header.Set("Origin", "http://127.0.0.1:8094")
		r.Header.Set("Content-Type", "application/json")
	}
	if change != nil {
		change(r)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestWitnessSettingsSaveClearArePrivateMemoryOnlyAndNeverCallUpstream(t *testing.T) {
	s := testWitnessServer(t, true)
	if s.config.APIKey != "" {
		t.Fatal("startup config retained a duplicate active secret")
	}
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("settings dispatched an outbound request")
		return nil, errors.New("unexpected")
	})
	s.consumeLiveCheck()
	for _, step := range []struct {
		method, body, source string
		configured           bool
	}{
		{"GET", "", "environment", true},
		{"POST", `{"api_key":"sk-session-secret-abcdef"}`, "session", true},
		{"GET", "", "session", true},
		{"POST", `{"api_key":""}`, "none", false},
		{"GET", "", "none", false},
	} {
		w := settingsRequest(s, step.method, step.body, nil)
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var data map[string]any
		if json.Unmarshal(w.Body.Bytes(), &data) != nil {
			t.Fatal("invalid settings JSON")
		}
		if data["source"] != step.source || data["storage"] != "memory" || data["compute_configured"] != step.configured || data["live_ready"] != step.configured || data["settings_available"] != true {
			t.Fatalf("wrong safe settings metadata: %v", data)
		}
		if data["remaining_live_checks"] != float64(29) {
			t.Fatal("settings reset or consumed the inference budget")
		}
		for _, secret := range []string{"test-only-key", "sk-session-secret-abcdef", "abcdef", "api_key"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("settings response revealed secret material")
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("settings response may be cached")
		}
	}
	if configured, source := s.runtimeKeyState(); configured || source != "none" {
		t.Fatal("clearing fell back to the startup key")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8094/api/config", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var config map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &config)
	if config["compute_configured"] != false || config["settings_available"] != true {
		t.Fatal("public config did not reflect session clearing/local availability")
	}
}

func TestWitnessSettingsRejectRemotePublicProxyAndWrongOrigins(t *testing.T) {
	s := testWitnessServer(t, false)
	for _, method := range []string{"GET", "POST"} {
		for _, change := range []func(*http.Request){
			func(r *http.Request) { r.RemoteAddr = "192.0.2.1:4444" },
			func(r *http.Request) { r.RemoteAddr = "unparseable" },
			func(r *http.Request) { r.Host = "attacker.example:8094" },
			func(r *http.Request) { r.Host = "127.0.0.1:9999" },
			func(r *http.Request) { r.Header.Set("Forwarded", "for=127.0.0.1") },
			func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") },
			func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
			func(r *http.Request) { r.Header.Set("X-Real-IP", "127.0.0.1") },
			func(r *http.Request) { r.Header.Set("CF-Connecting-IP", "127.0.0.1") },
			func(r *http.Request) { r.Header.Set("Via", "proxy") },
		} {
			if w := settingsRequest(s, method, `{"api_key":"sk-new"}`, change); w.Code != 403 {
				t.Fatalf("accepted remote/proxy/admin request: %s %d", method, w.Code)
			}
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "null") },
		func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") },
		func(r *http.Request) { r.Header.Set("Origin", "http://localhost:8094") },
		func(r *http.Request) { r.Header.Add("Origin", "http://127.0.0.1:8094") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		if w := settingsRequest(s, "POST", `{"api_key":"sk-new"}`, change); w.Code != 403 {
			t.Fatalf("accepted invalid Origin: %d", w.Code)
		}
	}
	public, err := NewServer(Config{ListenAddr: "0.0.0.0:8094", PublicOrigin: "https://labs.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST"} {
		w := settingsRequest(public, method, `{"api_key":"sk-new"}`, func(r *http.Request) { r.Host = "labs.example.com"; r.Header.Set("Origin", "https://labs.example.com") })
		if w.Code != 403 {
			t.Fatal("public deployment exposed settings")
		}
	}
	if configured, _ := s.runtimeKeyState(); configured {
		t.Fatal("rejected settings changed the key")
	}
}

func TestWitnessSettingsRejectMalformedSecretsWithoutEcho(t *testing.T) {
	s := testWitnessServer(t, false)
	for _, body := range []string{
		`{}`, `{"api_key":null}`, `{"api_key":42}`, `{"api_key":"one","api_key":"two"}`, `{"api_key":"one","unknown":true}`,
		`{"API_KEY":"one"}`, `{"api_key":"one","API_KEY":"two"}`,
		`{"api_key":"one\r\nX-Secret: injected"}`, `{"api_key":"one\t"}`, `{"api_key":"one\u0000"}`, `{"api_key":"one two"}`, `{"api_key":"one非ASCII"}`,
		`{"api_key":"one\"two"}`, `{"api_key":"one\\two"}`, `{"api_key":"=one"}`, `{"api_key":"one=two"}`,
		`{"api_key":"` + strings.Repeat("a", maxAPIKeyBytes+1) + `"}`,
		`{"api_key":"` + strings.Repeat("a", maxSettingsBodyBytes+1) + `"}`,
	} {
		w := settingsRequest(s, "POST", body, nil)
		if w.Code != 400 {
			t.Fatalf("accepted malformed settings: %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "injected") || strings.Contains(w.Body.String(), "one two") {
			t.Fatal("invalid key echoed")
		}
	}
	w := settingsRequest(s, "POST", `{"api_key":"sk-key"}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
	if w.Code != 415 {
		t.Fatal("non-JSON settings accepted")
	}
	if configured, _ := s.runtimeKeyState(); configured || s.remainingLiveChecks() != 30 {
		t.Fatal("invalid settings changed state")
	}
}

func TestWitnessClearDuringIFFPreflightStopsInferenceWithoutBudgetCharge(t *testing.T) {
	s := testWitnessServer(t, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	modelCalls := 0
	base := liveWitnessTransport(t, s, "router_verified", &modelCalls)
	s.client.Transport = witnessTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v3/evidence/check" {
			close(entered)
			<-release
		}
		return base(r)
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"clear-before-model"}`) }()
	<-entered
	if w := settingsRequest(s, "POST", `{"api_key":""}`, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	close(release)
	w := <-done
	if w.Code != 503 || modelCalls != 0 || s.remainingLiveChecks() != 30 {
		t.Fatalf("cleared key still dispatched inference: status=%d calls=%d remaining=%d", w.Code, modelCalls, s.remainingLiveChecks())
	}
}

func TestWitnessRotationPreservesInFlightSnapshotAndUsesNewKeyNext(t *testing.T) {
	s := testWitnessServer(t, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s.client.Transport = witnessTransport(func(r *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			close(entered)
			<-release
			if r.Header.Get("Authorization") != "Bearer test-only-key" {
				t.Error("inflight key changed")
			}
		} else if r.Header.Get("Authorization") != "Bearer sk-rotated" {
			t.Error("new inference did not use rotated key")
		}
		return nil, errors.New("simulated transport failure")
	})
	done := make(chan error, 1)
	go func() { _, _, err := s.compute(context.Background(), []byte(`{"verdict":"consistent"}`)); done <- err }()
	<-entered
	if w := settingsRequest(s, "POST", `{"api_key":"sk-rotated"}`, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.compute(context.Background(), []byte(`{"verdict":"consistent"}`)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || s.remainingLiveChecks() != 28 {
		t.Fatal("rotation retried or reset the budget")
	}
}

func TestWitnessSettingsAndInferenceReservationsAreRaceSafe(t *testing.T) {
	s := testWitnessServer(t, true)
	var workers sync.WaitGroup
	for i := 0; i < 40; i++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			if index%3 == 0 {
				settingsRequest(s, "POST", fmt.Sprintf(`{"api_key":"sk-session-%d"}`, index), nil)
			}
			if index%3 == 1 {
				settingsRequest(s, "POST", `{"api_key":""}`, nil)
			}
			if index%3 == 2 {
				_, _ = s.reserveComputeKey()
			}
			settingsRequest(s, "GET", "", nil)
		}(i)
	}
	workers.Wait()
	if s.remainingLiveChecks() < 0 || s.remainingLiveChecks() > 30 {
		t.Fatal("invalid quota after concurrent settings")
	}
}
