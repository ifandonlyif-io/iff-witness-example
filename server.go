package witness

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ifandonlyif-io/iff-witness-example/receipt"
	"github.com/ifandonlyif-io/iff-witness-example/util"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	config              Config
	client              *http.Client
	signer              *receipt.Signer
	handler             http.Handler
	inflight            chan struct{}
	mu                  sync.Mutex
	clients             map[string]rateWindow
	global              rateWindow
	liveCalls           int
	now                 func() time.Time
	keyMu               sync.RWMutex
	activeAPIKey        string
	keySource           string
	activeTrustedKeyIDs []string
	iffKeyIDsSource     string
}

type rateWindow struct {
	start time.Time
	count int
}

type CheckRequest struct {
	Mode     string `json:"mode"`
	Scenario string `json:"scenario"`
	Nonce    string `json:"nonce"`
	Password string `json:"password,omitempty"`
}

type serviceRequest struct {
	URL             string          `json:"url"`
	PaymentRequired json.RawMessage `json:"payment_required"`
	Receipt         struct {
		Version string `json:"version"`
		Nonce   string `json:"nonce"`
	} `json:"receipt"`
}

type Bundle struct {
	Schema      string         `json:"schema"`
	ID          string         `json:"id"`
	CreatedAt   string         `json:"created_at"`
	Mode        string         `json:"mode"`
	Scenario    string         `json:"scenario"`
	Simulated   bool           `json:"simulated"`
	Request     serviceRequest `json:"request"`
	IFF         IFFBundle      `json:"iff"`
	Explanation Explanation    `json:"explanation"`
	Compute     ComputeBundle  `json:"compute"`
	Agent       any            `json:"agent"`
}

type IFFBundle struct {
	Response          string          `json:"response"`
	RequestProjection string          `json:"request_projection"`
	KeyDirectory      json.RawMessage `json:"key_directory,omitempty"`
	Verification      IFFVerification `json:"verification"`
}

type Explanation struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type ComputeBundle struct {
	Status            string        `json:"status"`
	Model             string        `json:"model,omitempty"`
	RequestJSON       string        `json:"request_json,omitempty"`
	ResponseJSON      string        `json:"response_json,omitempty"`
	ChatID            string        `json:"chat_id,omitempty"`
	Provider          string        `json:"provider,omitempty"`
	Output            string        `json:"output,omitempty"`
	RouterTEEVerified *bool         `json:"router_tee_verified,omitempty"`
	Proof             *ComputeProof `json:"proof,omitempty"`
	Error             string        `json:"error,omitempty"`
}

func NewServer(config Config) (*Server, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, errors.New("cannot create rehearsal signing identity")
	}
	signer, err := receipt.NewSigner(base64.RawURLEncoding.EncodeToString(seed))
	if err != nil {
		return nil, err
	}
	initialKey := config.APIKey
	config.APIKey = "" // Runtime changes never mutate or fall back to Config.
	initialPins := config.TrustedKeyIDs
	config.TrustedKeyIDs = nil
	pinSource := "none"
	if len(initialPins) > 0 {
		pinSource = "environment"
	}
	source := "none"
	if initialKey != "" {
		source = "environment"
	}
	server := &Server{
		config: config, signer: signer,
		client:   util.NewSafeHTTPClient(util.SafeHTTPClientConfig{Timeout: 45 * time.Second}),
		inflight: make(chan struct{}, 2), clients: make(map[string]rateWindow), now: time.Now,
		activeAPIKey: initialKey, keySource: source,
		activeTrustedKeyIDs: initialPins, iffKeyIDsSource: pinSource,
	}
	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/config", server.serveConfig)
	mux.HandleFunc("POST /api/check", server.serveCheck)
	mux.HandleFunc("GET /api/settings", server.serveSettings)
	mux.HandleFunc("POST /api/settings", server.updateSettings)
	mux.Handle("/", http.FileServer(http.FS(assets)))
	server.handler = server.secure(mux)
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }
func (s *Server) ListenAddr() string    { return s.config.ListenAddr }

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !s.allowedHost(r.Host) {
			fail(w, http.StatusForbidden, "host_not_allowed", "此網域尚未設定給 Witness 使用。")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(raw string) bool {
	if s.config.PublicOrigin != "" {
		u, _ := url.Parse(s.config.PublicOrigin)
		if strings.EqualFold(raw, u.Host) {
			return true
		}
	}
	configuredHost, port, _ := net.SplitHostPort(s.config.ListenAddr)
	host, requestPort, err := net.SplitHostPort(raw)
	if err != nil {
		return false
	}
	if requestPort != port {
		return false
	}
	return (configuredHost == "localhost" || configuredHost == "127.0.0.1" || configuredHost == "::1") && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}

func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // JSON-only CLI requests remain supported.
	if s.config.PublicOrigin != "" && origin == s.config.PublicOrigin {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	examples := []Example{demoExample()}
	if s.config.Example != nil {
		examples = append(examples, *s.config.Example)
	}
	state := s.runtimeSettingsState()
	response := map[string]any{
		"mode": "rehearsal", "compute_configured": state.computeConfigured, "example_configured": s.config.Example != nil,
		"live_ready":              state.computeConfigured && s.config.Example != nil,
		"live_password_required": s.config.LivePassword != "",
		"settings_available":     s.localSettingsAvailable(r),
		"max_live_checks":    s.config.MaxLiveChecks, "remaining_live_checks": s.remainingLiveChecks(),
		"iff_origin": s.config.IFFOrigin, "model": s.config.Model, "examples": examples,
		"mutation_pay_to": demoExample().MutationPayTo,
		"demo_key_ids":    []string{s.signer.KeyID()}, "trusted_key_ids": state.iffKeyIDs,
		"limits": map[string]any{"max_output_tokens": maxOutputTokens, "concurrent_checks": 2, "checks_per_ip_per_minute": 6, "checks_per_minute": 20, "request_bytes": maxInputBytes},
	}
	if s.config.ComputeProvider != "" {
		response["trusted_compute_signers"] = map[string]string{strings.ToLower(s.config.ComputeProvider): s.config.ComputeSigner}
	}
	if s.config.AgentSigner != "" {
		response["agentic_trust"] = AgenticTrust{ExpectedSigner: s.config.AgentSigner, ChainID: s.config.AgentChainID, ContractAddress: s.config.AgentContract}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) serveCheck(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		fail(w, http.StatusForbidden, "origin_not_allowed", "請從設定好的 Witness 頁面執行查核。")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "json_required", "請求內容必須是 JSON。")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil || receipt.ValidateUniqueJSON(raw) != nil {
		fail(w, http.StatusBadRequest, "invalid_request", "請求內容無效或超過大小限制。")
		return
	}
	var request CheckRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || (request.Mode != "rehearsal" && request.Mode != "live") || (request.Scenario != "consistent" && request.Scenario != "payee_changed") || request.Nonce == "" || receipt.ValidateNonce(request.Nonce) != nil {
		fail(w, http.StatusBadRequest, "invalid_request", "請選擇有效的模式與情境，並附上一個新的 nonce。")
		return
	}
	if request.Mode == "live" && s.config.LivePassword != "" && !validLivePassword(request.Password, s.config.LivePassword) {
		fail(w, http.StatusForbidden, "invalid_password", "密碼不正確，無法使用真實查核。")
		return
	}
	configured, _ := s.runtimeKeyState()
	if request.Mode == "live" && (!configured || s.config.Example == nil) {
		fail(w, http.StatusServiceUnavailable, "live_not_configured", "真實模式需要 0G 金鑰，以及已列入允許清單的範例檔案。")
		return
	}
	if request.Mode == "live" && s.remainingLiveChecks() == 0 {
		fail(w, http.StatusServiceUnavailable, "budget_exhausted", "本次啟動的 0G 推理次數已用完，請先檢查額度設定。")
		return
	}
	if !s.admit(r.RemoteAddr) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "rate_limited", "查核次數已達上限，請稍候一分鐘再試。")
		return
	}
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		fail(w, http.StatusTooManyRequests, "busy", "目前已有兩個查核在執行中，請稍候再試。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	bundle, err := s.check(ctx, request)
	if err != nil {
		var public *publicError
		if errors.As(err, &public) {
			fail(w, public.status, public.code, public.message)
		} else {
			fail(w, http.StatusInternalServerError, "check_failed", "Witness 無法完成這次查核。")
		}
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) admit(remote string) bool {
	ip, _, err := net.SplitHostPort(remote)
	if err != nil {
		ip = remote
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.global.start) >= time.Minute {
		s.global = rateWindow{start: now}
	}
	if s.global.count >= 20 {
		return false
	}
	for key, window := range s.clients {
		if now.Sub(window.start) >= time.Minute {
			delete(s.clients, key)
		}
	}
	window, exists := s.clients[ip]
	if !exists {
		if len(s.clients) >= 2048 {
			return false
		}
		window = rateWindow{start: now}
	}
	if window.count >= 6 {
		return false
	}
	window.count++
	s.clients[ip] = window
	s.global.count++
	return true
}

func (s *Server) remainingLiveChecks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config.MaxLiveChecks - s.liveCalls
}

// Consume immediately before sending a real Router request, never for
// rehearsal, rejected input, unavailable IFF evidence, or failed receipts.
// Failed Router calls also consume a slot: the upstream may have charged.
func (s *Server) consumeLiveCheck() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveCalls >= s.config.MaxLiveChecks {
		return false
	}
	s.liveCalls++
	return true
}

func (s *Server) check(ctx context.Context, input CheckRequest) (Bundle, error) {
	// One immutable policy snapshot covers the directory, receipt validation,
	// and reported trust classification, even if settings change mid-request.
	trustedPins := s.runtimeSettingsState().iffKeyIDs
	example := demoExample()
	if input.Mode == "live" {
		example = *s.config.Example
	}
	payment := append(json.RawMessage(nil), example.PaymentRequired...)
	var err error
	if input.Scenario == "payee_changed" {
		payment, err = changedPayee(payment)
		if err != nil {
			return Bundle{}, err
		}
	}
	projection, err := requestProjection(example.URL, payment)
	if err != nil {
		return Bundle{}, err
	}
	request := serviceRequest{URL: example.URL, PaymentRequired: payment}
	request.Receipt.Version = "1"
	request.Receipt.Nonce = input.Nonce
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Schema: "iff-witness/bundle/v1", ID: hex.EncodeToString(id), CreatedAt: s.now().UTC().Format(time.RFC3339Nano), Mode: input.Mode, Scenario: input.Scenario, Simulated: input.Mode == "rehearsal", Request: request, Compute: ComputeBundle{Status: "not_requested"}}
	var response, keys []byte
	var trustedIDs []string
	issuer := s.config.IFFOrigin
	if input.Mode == "rehearsal" {
		issuer = demoIssuer
		trustedIDs = []string{s.signer.KeyID()}
		response, keys, err = s.rehearsalResponse(input, request, projection)
	} else {
		response, keys, trustedIDs, err = s.liveIFF(ctx, request, trustedPins)
	}
	if err != nil {
		return Bundle{}, err
	}
	verification, err := verifyIFFResponse(response, projection, input.Nonce, issuer, trustedIDs, s.now())
	if err != nil {
		// The public message stays generic (never exposes which internal
		// check failed to a client); this log line is the only place the
		// specific reason is visible, for operator debugging during a demo.
		log.Printf("iff_verification_failed mode=%s scenario=%s: %v", input.Mode, input.Scenario, err)
		return Bundle{}, &publicError{http.StatusBadGateway, "iff_verification_failed", "IFF 收據無法綁定到這次請求，未送出任何模型請求。"}
	}
	verification.IssuerTrust = "origin_recognized"
	if input.Mode == "rehearsal" {
		verification.IssuerTrust = "rehearsal"
	} else if len(trustedPins) > 0 {
		verification.IssuerTrust = "independently_pinned"
	}
	bundle.IFF = IFFBundle{Response: string(response), RequestProjection: string(projection), KeyDirectory: keys, Verification: verification}
	if input.Mode == "rehearsal" {
		text := "演練中的付款要求與模擬觀測一致。這份收據由本機的臨時示範金鑰簽署，資料皆為模擬，尚未呼叫 0G。比對一致不能保證付款安全。"
		if input.Scenario == "payee_changed" {
			text = "演練只替換了範例的收款地址，付款要求因此與模擬觀測不一致。這是受控測試，不代表發現真實攻擊。收據由本機的臨時示範金鑰簽署，尚未呼叫 0G，也不保證付款安全。"
		}
		bundle.Explanation = Explanation{Source: "rehearsal", Text: text}
		return bundle, nil
	}
	bundle.Explanation = Explanation{Source: "0g"}
	bundle.Compute, bundle.Explanation.Text, err = s.compute(ctx, verification.Subject)
	return bundle, err
}

func (s *Server) rehearsalResponse(input CheckRequest, request serviceRequest, projection []byte) ([]byte, []byte, error) {
	var received struct {
		Received fingerprintSummary `json:"received"`
	}
	if err := json.Unmarshal(projection, &received); err != nil {
		return nil, nil, err
	}
	base := demoExample()
	observedProjection, err := requestProjection(base.URL, base.PaymentRequired)
	if err != nil {
		return nil, nil, err
	}
	var observed struct {
		Received fingerprintSummary `json:"received"`
	}
	if err := json.Unmarshal(observedProjection, &observed); err != nil {
		return nil, nil, err
	}
	verdict := "consistent"
	matches := true
	unmatched := []string{}
	if input.Scenario == "payee_changed" {
		verdict = "diverged"
		matches = false
		unmatched = received.Received.OptionFingerprints
	}
	result := map[string]any{
		"url": request.URL, "verdict": verdict, "tier": "observed", "simulated": true,
		"received": received.Received, "observed": map[string]any{"set_fingerprint": observed.Received.SetFingerprint, "option_fingerprints": observed.Received.OptionFingerprints, "observed_at": s.now().UTC().Format(time.RFC3339Nano), "probe_type": "simulated", "simulated": true},
		"window_seconds": 300, "history": []any{}, "unmatched_received_options": unmatched, "matches_last_observed": matches,
		"ownership": map[string]string{"status": "unverified"}, "inclusion": nil,
		// This exact wording is IFF's own public disclaimer, already shown on
		// its observed-tier evidence cards; reproduced here verbatim for the
		// rehearsal fixture, not derived from anything non-public.
		"disclaimer": "Observed from public sources. Ownership not verified. Not an IFF-verified Evidence Card. Rehearsal only: simulated evidence signed by an ephemeral Witness demo key, not IFF production.",
	}
	if !matches {
		result["divergence_kind"] = "payee"
	}
	subject, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	nonce := input.Nonce
	payload, err := receipt.NewPayload(demoIssuer, "x402-requirement-verification", now, now.Add(5*time.Minute), &nonce, projection, subject, nil)
	if err != nil {
		return nil, nil, err
	}
	envelope, err := s.signer.Sign(payload)
	if err != nil {
		return nil, nil, err
	}
	result["service_receipt"] = envelope
	raw, err := json.Marshal(result)
	keys, _ := json.Marshal(map[string]any{"schema": "https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json", "issuer": demoIssuer, "enabled": true, "simulated": true, "keys": []any{map[string]string{"key_id": s.signer.KeyID(), "algorithm": "Ed25519", "public_key": s.signer.PublicKeyBase64URL(), "purpose": "service-receipt-signing", "status": "current"}}})
	return raw, keys, err
}

func (s *Server) liveIFF(ctx context.Context, request serviceRequest, trustedPins []string) ([]byte, []byte, []string, error) {
	// A GET gates POST /verify because IFF may enqueue discovery for unknown
	// URLs. There is deliberately no endpoint input or discovery route here.
	cardURL := s.config.IFFOrigin + "/api/v3/evidence/check?url=" + url.QueryEscape(request.URL)
	cardRaw, _, err := s.fetch(ctx, http.MethodGet, cardURL, nil, nil)
	if err != nil {
		log.Printf("liveIFF card fetch failed url=%s: %v", request.URL, err)
		return nil, nil, nil, &publicError{http.StatusConflict, "example_not_observed", "設定的範例目前沒有可讀取的公開 IFF 證據卡，未送出任何驗證或模型請求。"}
	}
	// evidenceCard captures only the fields Witness reads from IFF's public
	// evidence-check API response. This is intentionally NOT IFF's internal
	// EvidenceCard type (which also carries proprietary product fields like
	// discovery tier and ownership method) -- Witness only ever sees IFF's
	// public JSON contract, the same as any other external caller would.
	type evidenceCard struct {
		Endpoint struct {
			URL string `json:"url"`
		} `json:"endpoint"`
		Requirements *struct {
			Current struct {
				SetFingerprint string `json:"set_fingerprint"`
			} `json:"current"`
		} `json:"requirements,omitempty"`
		Freshness struct {
			ObservedAt *time.Time `json:"observed_at,omitempty"`
		} `json:"freshness"`
	}
	var envelope struct {
		Data evidenceCard `json:"data"`
	}
	if receipt.ValidateUniqueJSON(cardRaw) != nil || json.Unmarshal(cardRaw, &envelope) != nil {
		log.Printf("liveIFF card unmarshal/validate failed url=%s body=%s", request.URL, truncateForLog(cardRaw))
		return nil, nil, nil, &publicError{http.StatusConflict, "example_not_observed", "設定的範例需要有既有的指紋觀測紀錄，未送出任何驗證或模型請求。"}
	}
	card := envelope.Data
	if card.Endpoint.URL != request.URL || card.Requirements == nil || card.Requirements.Current.SetFingerprint == "" || card.Freshness.ObservedAt == nil {
		log.Printf("liveIFF card missing required fields url=%s cardURL=%s requirements=%v freshness=%v", request.URL, card.Endpoint.URL, card.Requirements, card.Freshness.ObservedAt)
		return nil, nil, nil, &publicError{http.StatusConflict, "example_not_observed", "設定的範例需要有既有的指紋觀測紀錄，未送出任何驗證或模型請求。"}
	}
	keys, _, err := s.fetch(ctx, http.MethodGet, s.config.IFFOrigin+"/api/v3/receipts/keys", nil, nil)
	if err != nil {
		log.Printf("liveIFF keys fetch failed: %v", err)
		return nil, nil, nil, &publicError{http.StatusBadGateway, "iff_keys_unavailable", "IFF 收據簽署金鑰目錄目前無法取得。"}
	}
	trustedIDs, err := trustedDirectoryKeys(keys, s.config.IFFOrigin, trustedPins)
	if err != nil {
		log.Printf("liveIFF keys directory untrusted body=%s: %v", truncateForLog(keys), err)
		return nil, nil, nil, &publicError{http.StatusBadGateway, "iff_keys_untrusted", "IFF 收據金鑰目錄已停用，或不符合設定的信任政策。"}
	}
	body, _ := json.Marshal(request)
	raw, _, err := s.fetch(ctx, http.MethodPost, s.config.IFFOrigin+"/api/v3/verify", body, nil)
	if err != nil {
		log.Printf("liveIFF verify POST failed url=%s: %v", request.URL, err)
		return nil, nil, nil, &publicError{http.StatusBadGateway, "iff_unavailable", "IFF 無法核發所要求的驗證收據，未送出任何模型請求。"}
	}
	return raw, keys, trustedIDs, nil
}

func trustedDirectoryKeys(raw []byte, issuer string, pins []string) ([]string, error) {
	var directory struct {
		Issuer  string `json:"issuer"`
		Enabled bool   `json:"enabled"`
		Keys    []struct {
			KeyID     string `json:"key_id"`
			Algorithm string `json:"algorithm"`
			PublicKey string `json:"public_key"`
			Purpose   string `json:"purpose"`
			Status    string `json:"status"`
		} `json:"keys"`
	}
	if receipt.ValidateUniqueJSON(raw) != nil || json.Unmarshal(raw, &directory) != nil || directory.Issuer != issuer || !directory.Enabled {
		return nil, errors.New("invalid directory")
	}
	ids := []string{}
	for _, key := range directory.Keys {
		parsed, err := receipt.ParsePublicKey(key.PublicKey)
		if err != nil || parsed.KeyID != key.KeyID || key.Algorithm != "Ed25519" || key.Purpose != "service-receipt-signing" || (key.Status != "current" && key.Status != "previous") {
			continue
		}
		if len(pins) > 0 {
			matched := false
			for _, pin := range pins {
				if pin == key.KeyID {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		ids = append(ids, key.KeyID)
	}
	if len(ids) == 0 {
		return nil, errors.New("no trusted keys")
	}
	return ids, nil
}

func (s *Server) fetch(ctx context.Context, method, target string, body []byte, headers map[string]string) ([]byte, http.Header, error) {
	// Queries are constructed exclusively for the public IFF lookup and 0G
	// protocol endpoints. Endpoint examples themselves never permit queries.
	if _, err := util.NormalizePublicHTTPSURL(target, true); err != nil {
		return nil, nil, errors.New("outbound URL rejected")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, errors.New("cannot construct outbound request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, errors.New("upstream unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return nil, nil, errors.New("upstream response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, errors.New("upstream rejected request")
	}
	return raw, resp.Header, nil
}

// validLivePassword runs in constant time so a wrong guess cannot be timed
// against the configured password's length or contents.
func validLivePassword(candidate, configured string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(configured)) == 1
}

// truncateForLog bounds a diagnostic log line so an oversized or malformed
// upstream body cannot flood the process log.
func truncateForLog(body []byte) string {
	const limit = 2048
	if len(body) > limit {
		return string(body[:limit]) + "...(truncated)"
	}
	return string(body)
}

type publicError struct {
	status        int
	code, message string
}

func (e *publicError) Error() string { return e.code }
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": code, "message": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
