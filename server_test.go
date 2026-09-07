package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ifandonlyif-io/iff-witness-example/receipt"
)

type witnessTransport func(*http.Request) (*http.Response, error)

func (f witnessTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testWitnessServer(t *testing.T, live bool) *Server {
	t.Helper()
	config := Config{}
	if live {
		example := demoExample()
		config.Example = &example
		config.APIKey = "test-only-key"
	}
	s, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func postWitness(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8094/api/check", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func upstreamJSON(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestWitnessRehearsalActuallySignsBothScenariosWithoutNetwork(t *testing.T) {
	s := testWitnessServer(t, false)
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("rehearsal performed outbound request")
		return nil, errors.New("unexpected")
	})
	for _, scenario := range []string{"consistent", "payee_changed"} {
		w := postWitness(s, `{"mode":"rehearsal","scenario":"`+scenario+`","nonce":"test-`+scenario+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
		var bundle Bundle
		if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
			t.Fatal(err)
		}
		if !bundle.Simulated || bundle.Mode != "rehearsal" || bundle.Compute.Status != "not_requested" || bundle.Compute.Proof != nil || bundle.Explanation.Source != "rehearsal" {
			t.Fatalf("misleading rehearsal bundle: %+v", bundle)
		}
		if bundle.IFF.Verification.IssuerTrust != "rehearsal" {
			t.Fatal("rehearsal key was misrepresented as production trust")
		}
		if _, err := verifyIFFResponse([]byte(bundle.IFF.Response), []byte(bundle.IFF.RequestProjection), bundle.Request.Receipt.Nonce, demoIssuer, []string{s.signer.KeyID()}, s.now()); err != nil {
			t.Fatal(err)
		}
		var response map[string]json.RawMessage
		_ = json.Unmarshal([]byte(bundle.IFF.Response), &response)
		wanted := `"consistent"`
		if scenario == "payee_changed" {
			wanted = `"diverged"`
		}
		if string(response["verdict"]) != wanted {
			t.Fatalf("verdict=%s", response["verdict"])
		}
		response["verdict"] = json.RawMessage(`"stale"`)
		tampered, _ := json.Marshal(response)
		if _, err := verifyIFFResponse(tampered, []byte(bundle.IFF.RequestProjection), bundle.Request.Receipt.Nonce, demoIssuer, []string{s.signer.KeyID()}, s.now()); err == nil {
			t.Fatal("accepted substituted outer verdict")
		}
	}
}

func TestWitnessLiveNeverFallsBackWhenUnconfigured(t *testing.T) {
	s := testWitnessServer(t, false)
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unconfigured live mode performed outbound request")
		return nil, errors.New("unexpected")
	})
	w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"live-nonce"}`)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "live_not_configured") {
		t.Fatalf("%d: %s", w.Code, w.Body.String())
	}
}

func TestWitnessLivePasswordGateBlocksWrongOrMissingPasswordBeforeAnyRequest(t *testing.T) {
	example := demoExample()
	s, err := NewServer(Config{Example: &example, APIKey: "test-only-key", LivePassword: "let-me-in"})
	if err != nil {
		t.Fatal(err)
	}
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("password-gated live mode performed outbound request")
		return nil, errors.New("unexpected")
	})
	for _, body := range []string{
		`{"mode":"live","scenario":"consistent","nonce":"pw-missing"}`,
		`{"mode":"live","scenario":"consistent","nonce":"pw-wrong","password":"nope"}`,
	} {
		w := postWitness(s, body)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invalid_password") {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
	}
}

func TestWitnessLivePasswordGateAdmitsCorrectPasswordAndIgnoresItForRehearsal(t *testing.T) {
	example := demoExample()
	s, err := NewServer(Config{Example: &example, APIKey: "test-only-key", LivePassword: "let-me-in"})
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		reached = true
		return nil, errors.New("stop before any real upstream call")
	})
	w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"pw-correct","password":"let-me-in"}`)
	if !reached || w.Code == http.StatusForbidden || strings.Contains(w.Body.String(), "invalid_password") {
		t.Fatalf("correct password was not admitted: reached=%v %d: %s", reached, w.Code, w.Body.String())
	}
	reached = false
	if w := postWitness(s, `{"mode":"rehearsal","scenario":"consistent","nonce":"pw-not-needed"}`); w.Code != http.StatusOK || reached {
		t.Fatalf("rehearsal mode must never require the live password: reached=%v %d: %s", reached, w.Code, w.Body.String())
	}
}

func TestWitnessUnknownCardNeverReachesVerifyOrCompute(t *testing.T) {
	for _, reply := range []string{`{"error":true}`, `{"endpoint":{"url":"https://weather.witness.example/forecast"}}`} {
		s := testWitnessServer(t, true)
		calls := 0
		s.client.Transport = witnessTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "GET" || r.URL.Path != "/api/v3/evidence/check" {
				t.Fatalf("unexpected mutating/model request: %s %s", r.Method, r.URL.Path)
			}
			return upstreamJSON(200, reply), nil
		})
		w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"known-only"}`)
		if w.Code != http.StatusConflict || calls != 1 {
			t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
		}
	}
}

func TestWitnessRequestRejectsArbitraryURLsOriginAndDuplicateKeys(t *testing.T) {
	s := testWitnessServer(t, false)
	for _, body := range []string{
		`{"mode":"rehearsal","scenario":"consistent","nonce":"a","url":"https://arbitrary.example/"}`,
		`{"mode":"rehearsal","mode":"live","scenario":"consistent","nonce":"a"}`,
		`{"mode":"rehearsal","scenario":"consistent","nonce":""}`,
	} {
		if got := postWitness(s, body); got.Code != 400 {
			t.Fatalf("accepted invalid request %s: %d", body, got.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8094/api/check", strings.NewReader(`{"mode":"rehearsal","scenario":"consistent","nonce":"a"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("accepted cross-origin request")
	}
	r = httptest.NewRequest("GET", "http://attacker.example:8094/api/config", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("accepted unconfigured Host (DNS rebinding surface)")
	}
}

func TestWitnessConfigAndOutboundRejectUnsafeOrigins(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://127.0.0.1", "https://user:pass@example.com", "https://example.com?token=secret", "https://example.com:8443", "https://[::1]", "https://example.com/path"} {
		if _, err := NewServer(Config{IFFOrigin: origin}); err == nil {
			t.Fatalf("accepted origin %s", origin)
		}
	}
	if _, err := NewServer(Config{RouterURL: "https://attacker.example/v1", APIKey: "must-not-leak"}); err == nil {
		t.Fatal("allowed Router API key exfiltration endpoint")
	}
	s := testWitnessServer(t, false)
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe URL reached transport")
		return nil, errors.New("unexpected")
	})
	if _, _, err := s.fetch(context.Background(), "GET", "https://127.0.0.1/private", nil, nil); err == nil {
		t.Fatal("accepted private outbound URL")
	}
	if s.client.CheckRedirect == nil {
		t.Fatal("safe client redirect policy missing")
	}
	redirect := httptest.NewRequest("GET", "https://example.com/next", nil)
	if err := s.client.CheckRedirect(redirect, nil); err == nil {
		t.Fatal("redirects allowed")
	}
}

func liveWitnessTransport(t *testing.T, s *Server, mode string, calls *int) witnessTransport {
	t.Helper()
	return func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/v3/evidence/check":
			return upstreamJSON(200, `{"success":true,"data":{"endpoint":{"url":"https://weather.witness.example/forecast"},"requirements":{"current":{"set_fingerprint":"exists"}},"freshness":{"status":"fresh","observed_at":"2026-09-05T00:00:00Z"}}}`), nil
		case "/api/v3/receipts/keys":
			keys, _ := json.Marshal(map[string]any{"issuer": s.config.IFFOrigin, "enabled": true, "keys": []any{map[string]string{"key_id": s.signer.KeyID(), "public_key": s.signer.PublicKeyBase64URL(), "algorithm": "Ed25519", "purpose": "service-receipt-signing", "status": "current"}}})
			return upstreamJSON(200, string(keys)), nil
		case "/api/v3/verify":
			var req serviceRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			projection, err := requestProjection(req.URL, req.PaymentRequired)
			if err != nil {
				t.Fatal(err)
			}
			var projected map[string]json.RawMessage
			_ = json.Unmarshal(projection, &projected)
			subject, _ := json.Marshal(map[string]any{"url": req.URL, "received": projected["received"], "verdict": "consistent", "disclaimer": "Test evidence only."})
			payload, err := receipt.NewPayload(s.config.IFFOrigin, "x402-requirement-verification", s.now(), s.now().Add(time.Minute), &req.Receipt.Nonce, projection, subject, nil)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := s.signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			var outer map[string]any
			_ = json.Unmarshal(subject, &outer)
			outer["service_receipt"] = envelope
			if mode == "invalid_iff" {
				outer["verdict"] = "diverged"
			}
			raw, _ := json.Marshal(outer)
			return upstreamJSON(200, string(raw)), nil
		case "/v1/chat/completions":
			*calls++
			if r.Header.Get("Authorization") != "Bearer test-only-key" || r.Header.Get("X-0G-Provider-Trust-Mode") != "private" || r.Header.Get("X-0G-Provider-Allow-Fallbacks") != "false" {
				t.Fatal("missing strict Router headers")
			}
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte(`"max_tokens":600`)) || !bytes.Contains(body, []byte(`"verify_tee":true`)) {
				t.Fatal("missing compute limits/verification")
			}
			if bytes.Contains(body, []byte("service_receipt")) {
				t.Fatal("model input should use authoritative signed subject, not the envelope")
			}
			if mode == "upstream_failed" {
				return nil, errors.New("secret query api_key=must-not-appear")
			}
			flag := "true"
			if mode == "router_failed" {
				flag = "false"
			}
			return upstreamJSON(200, `{"id":"chat-real","model":"0gm-1.0-35b-a3b","choices":[{"index":0,"message":{"role":"assistant","content":"模型的實際說明"},"finish_reason":"stop"}],"x_0g_trace":{"provider":"invalid-address","tee_verified":`+flag+`}}`), nil
		default:
			return nil, errors.New("no provider proof in fixture")
		}
	}
}

func TestWitnessLiveReceiptGateAndHonestComputeStates(t *testing.T) {
	for _, mode := range []string{"invalid_iff", "upstream_failed", "router_failed", "router_verified"} {
		t.Run(mode, func(t *testing.T) {
			s := testWitnessServer(t, true)
			calls := 0
			s.client.Transport = liveWitnessTransport(t, s, mode, &calls)
			w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"live-case"}`)
			if mode == "invalid_iff" {
				if w.Code != 502 || calls != 0 {
					t.Fatalf("invalid IFF receipt reached model: %d/%d", w.Code, calls)
				}
				return
			}
			if w.Code != 200 || calls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
			}
			var bundle Bundle
			if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
				t.Fatal(err)
			}
			if bundle.Simulated || bundle.Mode != "live" || bundle.Explanation.Source != "0g" {
				t.Fatal("live mode silently fell back")
			}
			if bundle.IFF.Verification.IssuerTrust != "origin_recognized" {
				t.Fatal("directory trust was misrepresented as an independent key pin")
			}
			wanted := "router_verified"
			if mode == "upstream_failed" {
				wanted = "unavailable"
			}
			if mode == "router_failed" {
				wanted = "verification_failed"
			}
			if bundle.Compute.Status != wanted {
				t.Fatalf("status %s, wanted %s", bundle.Compute.Status, wanted)
			}
			if strings.Contains(w.Body.String(), "must-not-appear") || strings.Contains(w.Body.String(), "test-only-key") {
				t.Fatal("upstream error/API key leaked")
			}
			if mode == "upstream_failed" && bundle.Explanation.Text != "" {
				t.Fatal("fabricated fallback explanation")
			}
		})
	}
}

func TestWitnessLiveBudgetCountsOnlyRealAttemptsAndStopsBeforeIFF(t *testing.T) {
	s := testWitnessServer(t, true)
	s.config.MaxLiveChecks = 1
	calls := 0
	s.client.Transport = liveWitnessTransport(t, s, "invalid_iff", &calls)
	if w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"invalid-iff"}`); w.Code != 502 {
		t.Fatal(w.Body.String())
	}
	if remaining := s.remainingLiveChecks(); remaining != 1 {
		t.Fatalf("failed receipt consumed inference quota: %d", remaining)
	}
	s.client.Transport = liveWitnessTransport(t, s, "upstream_failed", &calls)
	if w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"failed-compute"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if remaining := s.remainingLiveChecks(); remaining != 0 || calls != 1 {
		t.Fatalf("failed upstream attempt did not consume exactly one slot: %d calls=%d", remaining, calls)
	}
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("exhausted budget reached IFF or Router")
		return nil, errors.New("unexpected")
	})
	w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"over-budget"}`)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "budget_exhausted") {
		t.Fatalf("budget gate: %d %s", w.Code, w.Body.String())
	}
	if w := postWitness(s, `{"mode":"rehearsal","scenario":"consistent","nonce":"still-rehearse"}`); w.Code != 200 {
		t.Fatal("budget blocked rehearsal")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8094/api/config", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var config map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &config)
	if config["max_live_checks"] != float64(1) || config["remaining_live_checks"] != float64(0) {
		t.Fatal("config did not expose budget")
	}
}

func TestWitnessLiveBudgetAtomicReservation(t *testing.T) {
	s := testWitnessServer(t, false)
	s.config.MaxLiveChecks = 3
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 40; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if s.consumeLiveCheck() {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 3 || s.remainingLiveChecks() != 0 {
		t.Fatalf("concurrent budget overspend: %d", accepted.Load())
	}
}

func TestWitnessIndependentIFFPinIsDistinguished(t *testing.T) {
	s := testWitnessServer(t, true)
	if w := settingsRequest(s, "POST", `{"iff_key_ids":["`+s.signer.KeyID()+`"]}`, nil); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	calls := 0
	s.client.Transport = liveWitnessTransport(t, s, "router_verified", &calls)
	w := postWitness(s, `{"mode":"live","scenario":"consistent","nonce":"pinned"}`)
	var bundle Bundle
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &bundle) != nil {
		t.Fatal(w.Body.String())
	}
	if bundle.IFF.Verification.IssuerTrust != "independently_pinned" {
		t.Fatal("configured independent pin was not identified")
	}
}

func TestWitnessLiveBudgetConfigurationBounds(t *testing.T) {
	for _, value := range []string{"0", "-1", "501", "NaN"} {
		t.Setenv("WITNESS_MAX_LIVE_CHECKS", value)
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatalf("accepted budget %s", value)
		}
	}
	t.Setenv("WITNESS_MAX_LIVE_CHECKS", "")
	config, err := normalizeConfig(Config{})
	if err != nil || config.MaxLiveChecks != 30 {
		t.Fatal("default lifetime budget is not 30")
	}
}

func TestWitnessOperatorIdentityPinConfiguration(t *testing.T) {
	provider := "0x1234567890abcdef1234567890abcdef12345678"
	signer := "0xabcdef1234567890abcdef1234567890abcdef12"
	contract := "0x1111111111111111111111111111111111111111"
	for _, config := range []Config{
		{ComputeProvider: provider}, {ComputeSigner: signer},
		{ComputeProvider: provider, ComputeSigner: "0x0000000000000000000000000000000000000000"},
		{ComputeProvider: "https://attacker.example", ComputeSigner: signer},
		{AgentSigner: signer}, {AgentChainID: "16602"},
		{AgentSigner: signer, AgentChainID: "16602", AgentContract: "0x0000000000000000000000000000000000000000"},
		{AgentSigner: "invalid", AgentChainID: "16602", AgentContract: contract},
	} {
		if _, err := NewServer(config); err == nil {
			t.Fatalf("accepted invalid identity configuration: %+v", config)
		}
	}
	for _, chain := range []string{"0", "-1", "+1", "01", "1.2", "1e3", "0x4115", " 1", strings.Repeat("9", 79)} {
		if _, err := NewServer(Config{AgentSigner: signer, AgentChainID: chain, AgentContract: contract}); err == nil {
			t.Fatalf("accepted invalid chain ID %s", chain)
		}
	}
	s, err := NewServer(Config{ComputeProvider: provider, ComputeSigner: signer, AgentSigner: signer, AgentChainID: "9007199254740993", AgentContract: contract, APIKey: "never-in-public-config"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8094/api/config", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var response struct {
		TrustedComputeSigners map[string]string `json:"trusted_compute_signers"`
		AgenticTrust          AgenticTrust      `json:"agentic_trust"`
	}
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || !strings.EqualFold(response.TrustedComputeSigners[provider], signer) {
		t.Fatal("public compute signer pins missing")
	}
	if response.AgenticTrust.ChainID != "9007199254740993" || !strings.EqualFold(response.AgenticTrust.ExpectedSigner, signer) || response.AgenticTrust.ContractAddress != contract {
		t.Fatal("Agentic trust pins lost precision or binding")
	}
	if strings.Contains(w.Body.String(), "never-in-public-config") {
		t.Fatal("API key was exposed with public identity pins")
	}
	unconfigured := testWitnessServer(t, false)
	w = httptest.NewRecorder()
	unconfigured.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "agentic_trust") || strings.Contains(w.Body.String(), "trusted_compute_signers") {
		t.Fatal("unconfigured public identity pins were invented")
	}
}

func TestWitnessOperatorIdentityPinsReadFromEnvironment(t *testing.T) {
	t.Setenv("WITNESS_0G_PROVIDER", "0x1111111111111111111111111111111111111111")
	t.Setenv("WITNESS_0G_SIGNER", "0x2222222222222222222222222222222222222222")
	t.Setenv("WITNESS_AGENT_SIGNER", "0x3333333333333333333333333333333333333333")
	t.Setenv("WITNESS_AGENT_CHAIN_ID", "16602")
	t.Setenv("WITNESS_AGENT_CONTRACT", "0x4444444444444444444444444444444444444444")
	t.Setenv("WITNESS_MAX_LIVE_CHECKS", "")
	t.Setenv("WITNESS_EXAMPLE_FILE", "")
	config, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.ComputeProvider == "" || config.ComputeSigner == "" || config.AgentSigner == "" || config.AgentChainID != "16602" || config.AgentContract == "" {
		t.Fatal("operator pins were not loaded")
	}
}

func TestWitnessResponseAndRateLimits(t *testing.T) {
	s := testWitnessServer(t, false)
	s.client.Transport = witnessTransport(func(*http.Request) (*http.Response, error) {
		return upstreamJSON(200, strings.Repeat("x", maxResponseBytes+1)), nil
	})
	if _, _, err := s.fetch(context.Background(), "GET", DefaultIFFOrigin+"/health", nil, nil); err == nil {
		t.Fatal("accepted oversized upstream response")
	}
	for i := 0; i < 6; i++ {
		if !s.admit("192.0.2.1:1234") {
			t.Fatal("early rate limit")
		}
	}
	if s.admit("192.0.2.1:5678") {
		t.Fatal("port changed to bypass per-IP rate limit")
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if !s.admit("192.0.2.1:1234") {
		t.Fatal("rate window did not expire")
	}
}
