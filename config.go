// Package witness is the isolated IFF Witness hackathon application. It only
// consumes public IFF evidence APIs; it does not start an IFF production role.
package witness

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ifandonlyif-io/iff-witness-example/internal/prober"
	"github.com/ifandonlyif-io/iff-witness-example/receipt"
	"github.com/ifandonlyif-io/iff-witness-example/util"
	preflight "github.com/ifandonlyif-io/iff-x402-transparency/go"
)

const (
	DefaultListenAddr = "127.0.0.1:8094"
	DefaultIFFOrigin  = "https://ifandonlyif.io"
	DefaultRouterURL  = "https://router-api.0g.ai/v1"
	// Confirmed against the public Router model catalog on 2026-09-05.
	DefaultModel         = "0gm-1.0-35b-a3b"
	demoIssuer           = "https://witness.example"
	maxInputBytes        = 32 << 10
	maxResponseBytes     = 1 << 20
	maxOutputTokens      = 600
	defaultMaxLiveChecks = 30
)

// Keep the public default available to a fresh clone and a standalone binary,
// independent of the caller's working directory. Explicit overrides fail closed.
//
//go:embed examples/iff-fixture.json
var defaultExampleJSON []byte

type Example struct {
	ID              string          `json:"id"`
	Mode            string          `json:"mode"`
	Label           string          `json:"label"`
	URL             string          `json:"url"`
	PaymentRequired json.RawMessage `json:"payment_required"`
	MutationPayTo   string          `json:"mutation_pay_to,omitempty"`
}

type Config struct {
	ListenAddr      string
	IFFOrigin       string
	RouterURL       string
	Model           string
	APIKey          string
	PublicOrigin    string
	TrustedKeyIDs   []string
	Example         *Example
	MaxLiveChecks   int
	ComputeProvider string
	ComputeSigner   string
	AgentSigner     string
	AgentChainID    string
	AgentContract   string
	LivePassword    string
}

// AgenticTrust contains independently obtained operator pins. These public
// values are never inferred from an imported evidence bundle.
type AgenticTrust struct {
	ExpectedSigner  string `json:"expectedSigner"`
	ChainID         string `json:"chainId"`
	ContractAddress string `json:"contractAddress"`
}

// ConfigFromEnv reads only Witness settings. It never loads production IFF
// signing keys, database credentials, account wallets, or .env files.
func ConfigFromEnv() (Config, error) {
	config := Config{
		ListenAddr:      envDefault("WITNESS_LISTEN_ADDR", DefaultListenAddr),
		IFFOrigin:       envDefault("WITNESS_IFF_ORIGIN", DefaultIFFOrigin),
		RouterURL:       envDefault("WITNESS_0G_BASE_URL", DefaultRouterURL),
		Model:           envDefault("WITNESS_0G_MODEL", DefaultModel),
		APIKey:          strings.TrimSpace(os.Getenv("WITNESS_0G_API_KEY")),
		PublicOrigin:    strings.TrimSpace(os.Getenv("WITNESS_PUBLIC_ORIGIN")),
		ComputeProvider: strings.TrimSpace(os.Getenv("WITNESS_0G_PROVIDER")),
		ComputeSigner:   strings.TrimSpace(os.Getenv("WITNESS_0G_SIGNER")),
		AgentSigner:     strings.TrimSpace(os.Getenv("WITNESS_AGENT_SIGNER")),
		AgentChainID:    strings.TrimSpace(os.Getenv("WITNESS_AGENT_CHAIN_ID")),
		AgentContract:   strings.TrimSpace(os.Getenv("WITNESS_AGENT_CONTRACT")),
		LivePassword:    strings.TrimSpace(os.Getenv("WITNESS_LIVE_PASSWORD")),
	}
	if value := os.Getenv("WITNESS_MAX_LIVE_CHECKS"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 500 {
			return Config{}, errors.New("WITNESS_MAX_LIVE_CHECKS must be between 1 and 500")
		}
		config.MaxLiveChecks = limit
	}
	for _, value := range strings.Split(os.Getenv("WITNESS_IFF_KEY_IDS"), ",") {
		if value = strings.TrimSpace(value); value != "" {
			config.TrustedKeyIDs = append(config.TrustedKeyIDs, value)
		}
	}
	raw := defaultExampleJSON
	if file := os.Getenv("WITNESS_EXAMPLE_FILE"); file != "" {
		f, err := os.Open(file)
		if err != nil {
			return Config{}, errors.New("cannot open configured Witness example file")
		}
		defer f.Close()
		raw, err = io.ReadAll(io.LimitReader(f, maxInputBytes+1))
		if err != nil {
			return Config{}, errors.New("Witness example file must contain bounded, unique-key JSON")
		}
	}
	if len(raw) > maxInputBytes || receipt.ValidateUniqueJSON(raw) != nil {
		return Config{}, errors.New("Witness example file must contain bounded, unique-key JSON")
	}
	var example Example
	if err := json.Unmarshal(raw, &example); err != nil {
		return Config{}, errors.New("invalid Witness example file")
	}
	config.Example = &example
	return normalizeConfig(config)
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func normalizeConfig(config Config) (Config, error) {
	if (config.ComputeProvider == "") != (config.ComputeSigner == "") {
		return config, errors.New("WITNESS_0G_PROVIDER and WITNESS_0G_SIGNER must be configured together")
	}
	if config.ComputeProvider != "" {
		if !nonzeroEVMAddress(config.ComputeProvider) || !nonzeroEVMAddress(config.ComputeSigner) {
			return config, errors.New("Witness compute identity pins must be nonzero EVM addresses")
		}
		config.ComputeProvider = common.HexToAddress(config.ComputeProvider).Hex()
		config.ComputeSigner = common.HexToAddress(config.ComputeSigner).Hex()
	}
	if config.AgentSigner != "" || config.AgentChainID != "" || config.AgentContract != "" {
		if config.AgentSigner == "" || config.AgentChainID == "" || config.AgentContract == "" {
			return config, errors.New("Witness Agentic signer, chain ID, and contract pins must all be configured together")
		}
		if !nonzeroEVMAddress(config.AgentSigner) || !nonzeroEVMAddress(config.AgentContract) {
			return config, errors.New("Witness Agentic identity pins must be nonzero EVM addresses")
		}
		chain, ok := new(big.Int).SetString(config.AgentChainID, 10)
		if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 || chain.String() != config.AgentChainID {
			return config, errors.New("WITNESS_AGENT_CHAIN_ID must be a positive canonical decimal uint256")
		}
		config.AgentSigner = common.HexToAddress(config.AgentSigner).Hex()
		config.AgentContract = common.HexToAddress(config.AgentContract).Hex()
	}
	if config.MaxLiveChecks == 0 {
		config.MaxLiveChecks = defaultMaxLiveChecks
	}
	if config.MaxLiveChecks < 1 || config.MaxLiveChecks > 500 {
		return config, errors.New("Witness live check budget must be between 1 and 500")
	}
	if config.ListenAddr == "" {
		config.ListenAddr = DefaultListenAddr
	}
	if config.IFFOrigin == "" {
		config.IFFOrigin = DefaultIFFOrigin
	}
	if config.RouterURL == "" {
		config.RouterURL = DefaultRouterURL
	}
	if config.Model == "" {
		config.Model = DefaultModel
	}
	host, _, err := net.SplitHostPort(config.ListenAddr)
	if err != nil {
		return config, errors.New("invalid WITNESS_LISTEN_ADDR")
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && config.PublicOrigin == "" {
		return config, errors.New("non-loopback Witness listener requires WITNESS_PUBLIC_ORIGIN")
	}
	config.IFFOrigin, err = publicOrigin(config.IFFOrigin)
	if err != nil {
		return config, errors.New("WITNESS_IFF_ORIGIN must be a public HTTPS origin")
	}
	if strings.TrimSuffix(config.RouterURL, "/") != DefaultRouterURL {
		return config, errors.New("WITNESS_0G_BASE_URL must be the official HTTPS Router URL")
	}
	config.RouterURL = DefaultRouterURL
	if config.PublicOrigin != "" {
		config.PublicOrigin, err = publicOrigin(config.PublicOrigin)
		if err != nil {
			return config, errors.New("WITNESS_PUBLIC_ORIGIN must be a public HTTPS origin")
		}
	}
	if len(config.Model) > 120 || strings.ContainsAny(config.Model, "\r\n\t ?#") {
		return config, errors.New("invalid Witness model ID")
	}
	if !validAPIKey(config.APIKey) {
		return config, errors.New("invalid Witness API key")
	}
	if len(config.LivePassword) > 256 {
		return config, errors.New("WITNESS_LIVE_PASSWORD is too long")
	}
	config.TrustedKeyIDs, err = normalizeIFFKeyIDs(config.TrustedKeyIDs)
	if err != nil {
		return config, errors.New("Witness IFF key IDs must contain at most 16 canonical sha256 fingerprints")
	}
	if config.Example != nil {
		value := *config.Example
		value.URL, err = util.NormalizePublicHTTPSURL(value.URL, false)
		if err != nil {
			return config, errors.New("configured example must be a public HTTPS endpoint without query or fragment")
		}
		if value.ID == "" {
			value.ID = "configured"
		}
		if value.Label == "" {
			value.Label = "Configured live endpoint"
		}
		if len(value.ID) > 64 || len(value.Label) > 160 || len(value.PaymentRequired) > maxInputBytes {
			return config, errors.New("configured example exceeds limits")
		}
		if receipt.ValidateUniqueJSON(value.PaymentRequired) != nil {
			return config, errors.New("invalid configured payment requirement JSON")
		}
		if _, err := requestProjection(value.URL, value.PaymentRequired); err != nil {
			return config, errors.New("configured example is not a valid x402 v2 payment requirement")
		}
		value.MutationPayTo = mutationPayTo(value.PaymentRequired)
		value.Mode = "live"
		value.PaymentRequired = append(json.RawMessage(nil), value.PaymentRequired...)
		config.Example = &value
	}
	return config, nil
}

func nonzeroEVMAddress(raw string) bool {
	return common.IsHexAddress(raw) && common.HexToAddress(raw) != (common.Address{})
}

func publicOrigin(raw string) (string, error) {
	value, err := util.NormalizePublicHTTPSURL(raw, false)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(value)
	if err != nil || u.Path != "/" {
		return "", errors.New("origin must not have a path")
	}
	return strings.TrimSuffix(value, "/"), nil
}

type fingerprintSummary struct {
	SetFingerprint     string   `json:"set_fingerprint"`
	OptionFingerprints []string `json:"option_fingerprints"`
}

func requestProjection(endpoint string, raw json.RawMessage) ([]byte, error) {
	parsed, err := prober.ParsePaymentRequiredBody(raw)
	if err != nil {
		return nil, err
	}
	options, _, err := prober.ValidateAndExtractPaymentOptions(parsed)
	if err != nil {
		return nil, err
	}
	fp, ok := preflight.ComputeFingerprint(options)
	if !ok {
		return nil, errors.New("unfingerprintable requirement")
	}
	return json.Marshal(struct {
		URL      string             `json:"url"`
		Received fingerprintSummary `json:"received"`
	}{endpoint, fingerprintSummary{fp.SetFP, fp.OptionFPs}})
}

func demoExample() Example {
	return Example{
		ID: "rehearsal", Mode: "rehearsal", Label: "Simulated weather API — rehearsal only", URL: "https://weather.witness.example/forecast", MutationPayTo: "0x2222222222222222222222222222222222222222",
		PaymentRequired: json.RawMessage(`{"x402Version":2,"resource":{"url":"https://weather.witness.example/forecast","description":"Simulated weather request","mimeType":"application/json"},"accepts":[{"scheme":"exact","network":"eip155:8453","amount":"1000","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","payTo":"0x1111111111111111111111111111111111111111","maxTimeoutSeconds":60,"extra":{"name":"USD Coin","version":"2"}}]}`),
	}
}

func changedPayee(raw json.RawMessage) (json.RawMessage, error) {
	var requirement map[string]json.RawMessage
	if err := json.Unmarshal(raw, &requirement); err != nil {
		return nil, err
	}
	var accepts []map[string]json.RawMessage
	if err := json.Unmarshal(requirement["accepts"], &accepts); err != nil || len(accepts) == 0 {
		return nil, errors.New("no payment options")
	}
	replacement, _ := json.Marshal(mutationPayTo(raw))
	for _, option := range accepts {
		// Change only payTo, never amount, network, asset, or other options.
		option["payTo"] = replacement
	}
	requirement["accepts"], _ = json.Marshal(accepts)
	return json.Marshal(requirement)
}

func mutationPayTo(raw json.RawMessage) string {
	var requirement struct {
		Accepts []struct {
			PayTo string `json:"payTo"`
		} `json:"accepts"`
	}
	_ = json.Unmarshal(raw, &requirement)
	for _, digit := range "23456789abcdef" {
		candidate := "0x" + strings.Repeat(string(digit), 40)
		found := false
		for _, option := range requirement.Accepts {
			if strings.EqualFold(option.PayTo, candidate) {
				found = true
			}
		}
		if !found {
			return candidate
		}
	}
	return "0x1234567890123456789012345678901234567890"
}
