package witness

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ifandonlyif-io/iff-witness-example/receipt"
)

// A newly generated local fixture, never a production IFF receipt.
func proofIFFFixture(t *testing.T) ([]byte, []byte, *receipt.Signer, time.Time) {
	t.Helper()
	signer, err := receipt.NewSigner(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 2, 0, 0, 0, time.UTC)
	projection := []byte(`{"url":"https://api.example/service","received":{"set_fingerprint":"fixture","option_fingerprints":["fixture"]}}`)
	subject := []byte(`{"url":"https://api.example/service","verdict":"consistent","received":{"set_fingerprint":"fixture","option_fingerprints":["fixture"]},"log_index":9007199254740993}`)
	nonce := "fixture-request-1"
	payload, err := receipt.NewPayload("https://witness.example", "x402-requirement-verification", now, now.Add(5*time.Minute), &nonce, projection, subject, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(subject, &outer); err != nil {
		t.Fatal(err)
	}
	outer["service_receipt"], _ = json.Marshal(envelope)
	raw, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return raw, projection, signer, now
}

func TestProofIFFReceiptBindings(t *testing.T) {
	raw, projection, signer, now := proofIFFFixture(t)
	verify := func(raw, projection []byte, nonce, issuer string, keys []string, at time.Time) (IFFVerification, error) {
		return verifyIFFResponse(raw, projection, nonce, issuer, keys, at)
	}
	base, err := verify(raw, projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now)
	if err != nil || !base.OuterBound || len(base.Subject) == 0 {
		t.Fatalf("valid fixture rejected: %+v %v", base, err)
	}
	tests := []struct {
		name            string
		raw, projection []byte
		nonce, issuer   string
		keys            []string
		now             time.Time
	}{
		{"outer verdict", []byte(strings.Replace(string(raw), `"verdict":"consistent"`, `"verdict":"diverged"`, 1)), projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now},
		{"large numeric token", []byte(strings.Replace(string(raw), "9007199254740993", "9007199254740992", 1)), projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now},
		{"foreign key", raw, projection, "fixture-request-1", "https://witness.example", []string{"sha256:" + strings.Repeat("0", 64)}, now},
		{"foreign issuer", raw, projection, "fixture-request-1", "https://ifandonlyif.io", []string{signer.KeyID()}, now},
		{"nonce replay", raw, projection, "different-request", "https://witness.example", []string{signer.KeyID()}, now},
		{"projection substitution", raw, []byte(`{"url":"https://other.example/"}`), "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now},
		{"expired", raw, projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now.Add(5 * time.Minute)},
		{"future", raw, projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now.Add(-time.Second)},
		{"duplicate keys", []byte(strings.Replace(string(raw), `"verdict":"consistent"`, `"verdict":"diverged","verdict":"consistent"`, 1)), projection, "fixture-request-1", "https://witness.example", []string{signer.KeyID()}, now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verify(test.raw, test.projection, test.nonce, test.issuer, test.keys, test.now); err == nil {
				t.Fatal("negative fixture accepted")
			}
		})
	}
}

type proofTestTransport func(*http.Request) (*http.Response, error)

func (f proofTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchComputeProofBindsRegistryAndExactBytes(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	requestJSON := `{"model":"fixture-model","messages":[{"role":"user","content":"fixture"}]}`
	responseJSON := `{"choices":[{"message":{"content":"fixture answer"}}]}`
	rq, rs := sha256.Sum256([]byte(requestJSON)), sha256.Sum256([]byte(responseJSON))
	text := hex.EncodeToString(rq[:]) + ":" + hex.EncodeToString(rs[:])
	signature, err := crypto.Sign(accounts.TextHash([]byte(text)), key)
	if err != nil {
		t.Fatal(err)
	}
	signature[64] += 27
	parsedABI, err := abi.JSON(strings.NewReader(computeServiceABI))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, output, response, serviceURL string
		badSigner, failedSignatureEndpoint bool
		expected                           string
	}{
		{name: "complete fixture", output: "fixture answer", response: responseJSON, serviceURL: "https://provider.example", expected: "independently_verified"},
		{name: "changed output", output: "changed answer", response: responseJSON, serviceURL: "https://provider.example", expected: "unavailable"},
		{name: "router transformed bytes", output: "fixture answer", response: responseJSON + "\n", serviceURL: "https://provider.example", expected: "unavailable"},
		{name: "untrusted signer", output: "fixture answer", response: responseJSON, serviceURL: "https://provider.example", badSigner: true, expected: "verification_failed"},
		{name: "private endpoint", output: "fixture answer", response: responseJSON, serviceURL: "https://127.0.0.1", expected: "unavailable"},
		{name: "signature unavailable", output: "fixture answer", response: responseJSON, serviceURL: "https://provider.example", failedSignatureEndpoint: true, expected: "unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registrySigner := signer
			if test.badSigner {
				registrySigner = common.HexToAddress("0x2222222222222222222222222222222222222222")
			}
			service := computeService{Provider: provider, ServiceType: "chatbot", Url: test.serviceURL, InputPrice: big.NewInt(1), OutputPrice: big.NewInt(1), UpdatedAt: big.NewInt(1), Model: "fixture-model", Verifiability: "TeeML", AdditionalInfo: `{"TargetSeparated":false,"ProviderType":"decentralized"}`, TeeSignerAddress: registrySigner, TeeSignerAcknowledged: true}
			encoded, err := parsedABI.Methods["getService"].Outputs.Pack(service)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: proofTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "" {
					t.Fatal("credential forwarded to proof infrastructure")
				}
				var body []byte
				status := 200
				if r.URL.Host == "evmrpc.0g.ai" {
					var rpcRequest struct {
						Method string `json:"method"`
					}
					if err := json.NewDecoder(r.Body).Decode(&rpcRequest); err != nil {
						t.Fatal(err)
					}
					result := ""
					switch rpcRequest.Method {
					case "eth_chainId":
						result = "0x4115"
					case "eth_blockNumber":
						result = "0x123"
					case "eth_call":
						result = hexutil.Encode(encoded)
					default:
						t.Fatalf("unexpected method %s", rpcRequest.Method)
					}
					body, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
				} else {
					if r.URL.Host != "provider.example" || r.URL.Path != "/v1/proxy/signature/fixture-chat" || r.URL.Query().Get("model") != "fixture-model" {
						t.Fatalf("unexpected provider URL: %s", r.URL)
					}
					if test.failedSignatureEndpoint {
						status = 404
					}
					body, _ = json.Marshal(map[string]string{"text": text, "signature": hexutil.Encode(signature), "signing_algo": "ecdsa"})
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
			})}
			proof, status := fetchComputeProof(context.Background(), client, ComputeProofOptions{Provider: provider.Hex(), ChatID: "fixture-chat", Model: "fixture-model", RequestJSON: requestJSON, ResponseJSON: test.response, Output: test.output})
			if status != test.expected {
				t.Fatalf("status=%s expected=%s proof=%+v", status, test.expected, proof)
			}
			if status == "independently_verified" && (!proof.OutputBound || !proof.IdentityVerified || !proof.SignatureValid) {
				t.Fatalf("incomplete verified proof: %+v", proof)
			}
		})
	}
}

func TestComputeContentBindingRejectsUnsupportedFormats(t *testing.T) {
	for _, value := range []string{"just assistant text", "0g-e2ee:v1:" + strings.Repeat("a", 64), strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":centralized:vendor:missing-fingerprint"} {
		if format, _, _ := computeContentBinding(value, "request", "response", "decentralized"); format != "" {
			t.Fatalf("unsupported signed format accepted: %q", value)
		}
	}
}
