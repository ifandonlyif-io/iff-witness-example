package witness

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/ifandonlyif-io/iff-witness-example/receipt"
)

const maxSettingsBodyBytes = 2048
const maxAPIKeyBytes = 512
const maxIFFKeyIDs = 16

// This safe snapshot deliberately excludes the API key. Copies prevent callers
// from mutating the active trust policy after releasing keyMu.
type runtimeSettings struct {
	computeConfigured bool
	keySource         string
	iffKeyIDs         []string
	iffKeyIDsSource   string
}

func (s *Server) runtimeSettingsState() runtimeSettings {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	return runtimeSettings{
		computeConfigured: s.activeAPIKey != "", keySource: s.keySource,
		iffKeyIDs: append([]string{}, s.activeTrustedKeyIDs...), iffKeyIDsSource: s.iffKeyIDsSource,
	}
}

// Matches receipt.KeyID's canonical SHA-256 identifier, not an API secret or
// an encoded public key. The input count is bounded before deduplication.
func normalizeIFFKeyIDs(ids []string) ([]string, error) {
	if len(ids) > maxIFFKeyIDs {
		return nil, errors.New("too many IFF key IDs")
	}
	result := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if len(id) != 71 || !strings.HasPrefix(id, "sha256:") {
			return nil, errors.New("invalid IFF key ID")
		}
		for _, char := range []byte(id[7:]) {
			if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
				return nil, errors.New("invalid IFF key ID")
			}
		}
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	return result, nil
}

// The live key is memory-only. Replacing or clearing it affects subsequent
// inference reservations; requests already admitted retain their own snapshot.
// No setting action makes an inference, resets the budget, or writes a file.
func (s *Server) runtimeKeyState() (configured bool, source string) {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	return s.activeAPIKey != "", s.keySource
}

func (s *Server) reserveComputeKey() (string, error) {
	// Lock order is always keyMu then mu. This makes the nonempty-key check
	// and budget reservation atomic relative to a local settings update.
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	if s.activeAPIKey == "" {
		return "", &publicError{http.StatusServiceUnavailable, "live_not_configured", "0G 金鑰尚未設定。請先在本機設定頁儲存金鑰。"}
	}
	if !s.consumeLiveCheck() {
		return "", &publicError{http.StatusServiceUnavailable, "budget_exhausted", "本次啟動的 0G 推理次數已用完，請先檢查額度設定。"}
	}
	return s.activeAPIKey, nil
}

func validAPIKey(key string) bool {
	if len(key) > maxAPIKeyBytes {
		return false
	}
	padding := false
	for _, char := range []byte(key) {
		if char == '=' {
			padding = true
			continue
		}
		if padding {
			return false
		}
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-._~+/", rune(char)) {
			continue
		}
		return false
	}
	return key == "" || key[0] != '='
}

func (s *Server) localSettingsAvailable(r *http.Request) bool {
	if s.config.PublicOrigin != "" {
		return false
	}
	host, _, err := net.SplitHostPort(s.config.ListenAddr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") || !s.allowedHost(r.Host) {
		return false
	}
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(remote)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	for name := range r.Header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-forwarded-") {
			return false
		}
		switch name {
		case "forwarded", "via", "x-real-ip", "cf-connecting-ip", "true-client-ip", "fly-client-ip", "proxy-connection":
			return false
		}
	}
	return true
}

func (s *Server) settingsResponse() map[string]any {
	state := s.runtimeSettingsState()
	return map[string]any{
		"settings_available": true, "compute_configured": state.computeConfigured, "example_configured": s.config.Example != nil,
		"live_ready": state.computeConfigured && s.config.Example != nil, "model": s.config.Model,
		"remaining_live_checks": s.remainingLiveChecks(), "max_live_checks": s.config.MaxLiveChecks,
		"storage": "memory", "source": state.keySource,
		"iff_key_ids": state.iffKeyIDs, "iff_key_ids_source": state.iffKeyIDsSource,
	}
}

func (s *Server) serveSettings(w http.ResponseWriter, r *http.Request) {
	if !s.localSettingsAvailable(r) || !s.sameOrigin(r) {
		fail(w, http.StatusForbidden, "settings_unavailable", "金鑰設定只適用於直接連線的本機頁面。")
		return
	}
	writeJSON(w, http.StatusOK, s.settingsResponse())
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.localSettingsAvailable(r) {
		fail(w, http.StatusForbidden, "settings_unavailable", "金鑰設定只適用於直接連線的本機頁面。")
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != scheme+"://"+r.Host || !s.sameOrigin(r) {
		fail(w, http.StatusForbidden, "origin_not_allowed", "請從同一個本機 Witness 頁面儲存設定。")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "json_required", "設定必須使用 JSON 傳送。")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSettingsBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil || receipt.ValidateUniqueJSON(raw) != nil {
		fail(w, http.StatusBadRequest, "invalid_settings", "設定格式不正確或超出大小限制。")
		return
	}
	var fields map[string]json.RawMessage
	var apiKey *string
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 || len(fields) > 2 {
		fail(w, http.StatusBadRequest, "invalid_settings", "請提供 0G 金鑰或 IFF 公開指紋設定。")
		return
	}
	for name := range fields {
		if name != "api_key" && name != "iff_key_ids" {
			fail(w, http.StatusBadRequest, "invalid_settings", "設定包含不支援的欄位。")
			return
		}
	}
	if value, present := fields["api_key"]; present && (json.Unmarshal(value, &apiKey) != nil || apiKey == nil || !validAPIKey(*apiKey)) {
		fail(w, http.StatusBadRequest, "invalid_settings", "金鑰必須是不含空白或控制字元的有效 ASCII token，最多 512 字元。")
		return
	}
	var iffKeyIDs []string
	if value, present := fields["iff_key_ids"]; present {
		if json.Unmarshal(value, &iffKeyIDs) != nil || iffKeyIDs == nil {
			fail(w, http.StatusBadRequest, "invalid_settings", "IFF 公開指紋必須是字串陣列；清除時請傳送空陣列。")
			return
		}
		iffKeyIDs, err = normalizeIFFKeyIDs(iffKeyIDs)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalid_settings", "IFF 公開指紋最多 16 個，每個須為 sha256: 加上 64 個小寫十六進位字元。")
			return
		}
	}
	// Validate the entire partial update before applying either field. Omitted
	// values are untouched; clearing never falls back to startup environment.
	s.keyMu.Lock()
	if apiKey != nil {
		s.activeAPIKey = *apiKey
		s.keySource = "session"
		if s.activeAPIKey == "" {
			s.keySource = "none"
		}
	}
	if iffKeyIDs != nil {
		s.activeTrustedKeyIDs = iffKeyIDs
		s.iffKeyIDsSource = "session"
		if len(iffKeyIDs) == 0 {
			s.iffKeyIDsSource = "none"
		}
	}
	s.keyMu.Unlock()
	writeJSON(w, http.StatusOK, s.settingsResponse())
}
