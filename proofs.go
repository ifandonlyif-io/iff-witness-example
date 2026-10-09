package witness

// Witness verifies portable statements, not model correctness or hardware
// attestation. Provider signature formats and registry ABI are sourced from:
// 0gfoundation/0g-serving-broker/api/inference/internal/ctrl/signing.go
// 0gfoundation/0g-compute-ts-sdk/src.ts/sdk/inference/broker/response.ts
// 0gfoundation/0g-compute-ts-sdk/src.ts/sdk/constants.ts (2026-09-05).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ifandonlyif-io/iff-witness-example/receipt"
	"github.com/ifandonlyif-io/iff-witness-example/util"
)

type IFFVerification struct {
	SignatureValid bool   `json:"signature_valid"`
	IssuerTrusted  bool   `json:"issuer_trusted"`
	IssuerTrust    string `json:"issuer_trust,omitempty"`
	Fresh          bool   `json:"fresh"`
	NonceBound     bool   `json:"nonce_bound"`
	RequestBound   bool   `json:"request_bound"`
	OuterBound     bool   `json:"outer_bound"`
	KeyID          string `json:"key_id,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	Subject        []byte `json:"-"`
}

// projection must be derived from the submitted request, never the untrusted
// HTTP response. The backend uses the production x402 parser/fingerprinter.
func verifyIFFResponse(raw, projection []byte, nonce, expectedIssuer string, trustedKeyIDs []string, now time.Time) (IFFVerification, error) {
	result := IFFVerification{}
	if len(raw) > 256<<10 || receipt.ValidateUniqueJSON(raw) != nil || receipt.ValidateUniqueJSON(projection) != nil {
		return result, errors.New("IFF response or request projection is invalid JSON")
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		return result, errors.New("IFF response is not an object")
	}
	envelope, ok := outer["service_receipt"]
	if !ok {
		return result, errors.New("IFF did not return a service receipt")
	}
	verified, err := receipt.VerifyJSON(envelope, receipt.VerifyOptions{ExpectedIssuer: expectedIssuer, TrustedKeyIDs: trustedKeyIDs, Now: now})
	if err != nil {
		return result, fmt.Errorf("IFF receipt: %w", err)
	}
	// Witness only accepts new Service Receipt v2 (ML-DSA-65). Historical v1
	// Ed25519 receipts remain verifiable by the receipt package, not here.
	if verified.Algorithm != receipt.AlgorithmMLDSA65 {
		return result, errors.New("IFF receipt is not an ML-DSA-65 Service Receipt v2")
	}
	result.SignatureValid, result.IssuerTrusted = verified.SignatureValid, verified.IssuerTrusted
	result.Fresh = !verified.Expired && !verified.NotYetValid
	result.KeyID = verified.KeyID
	result.Algorithm = verified.Algorithm
	result.Subject = verified.Subject
	result.NonceBound = nonce != "" && verified.Payload.Nonce != nil && *verified.Payload.Nonce == nonce
	hash := receipt.RequestHash(projection)
	result.RequestBound = verified.Payload.Service == "x402-requirement-verification" && verified.Payload.RequestSHA256 == hex.EncodeToString(hash[:])
	delete(outer, "service_receipt")
	candidate, err := json.Marshal(outer)
	if err != nil {
		return result, errors.New("IFF response cannot be compared")
	}
	result.OuterBound = verified.SubjectMatchesJSON(candidate)
	if !result.IssuerTrusted {
		return result, errors.New("IFF receipt issuer/key is not trusted")
	}
	if !result.Fresh {
		return result, errors.New("IFF receipt is expired or issued in the future")
	}
	if !result.NonceBound {
		return result, errors.New("IFF receipt nonce differs from this request")
	}
	if !result.RequestBound {
		return result, errors.New("IFF receipt does not bind this request projection")
	}
	if !result.OuterBound {
		return result, errors.New("IFF outer response differs from its signed subject")
	}
	return result, nil
}

const computeMainnetRPC = "https://evmrpc.0g.ai"
const computeMainnetRegistry = "0x47340d900bdFec2BD393c626E12ea0656F938d84"
const proofBodyLimit = 512 << 10

var proofDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var proofChatIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,160}$`)

// These fields are evidence for re-verification. Their presence in a downloaded
// bundle is NOT a trust anchor: an offline caller supplies its own signer pin.
type ComputeProof struct {
	Text             string `json:"text,omitempty"`
	Signature        string `json:"signature,omitempty"`
	Provider         string `json:"provider,omitempty"`
	ChatID           string `json:"chat_id,omitempty"`
	Model            string `json:"model,omitempty"`
	SignerAddress    string `json:"signer_address,omitempty"`
	ProviderURL      string `json:"provider_url,omitempty"`
	TrustSource      string `json:"trust_source,omitempty"`
	Registry         string `json:"registry,omitempty"`
	ChainID          string `json:"chain_id,omitempty"`
	BlockNumber      string `json:"block_number,omitempty"`
	ProviderType     string `json:"provider_type,omitempty"`
	Format           string `json:"format,omitempty"`
	SignatureValid   bool   `json:"signature_valid"`
	IdentityVerified bool   `json:"identity_verified"`
	RequestBound     bool   `json:"request_bound"`
	ResponseBound    bool   `json:"response_bound"`
	OutputBound      bool   `json:"output_bound"`
	Reason           string `json:"reason"`
}

type ComputeProofOptions struct {
	Provider, ChatID, Model, RequestJSON, ResponseJSON, Output string
	RPCURL                                                     string
}

type computeService struct {
	Provider              common.Address
	ServiceType           string
	Url                   string
	InputPrice            *big.Int
	OutputPrice           *big.Int
	UpdatedAt             *big.Int
	Model                 string
	Verifiability         string
	AdditionalInfo        string
	TeeSignerAddress      common.Address
	TeeSignerAcknowledged bool
}

const computeServiceABI = `[{"type":"function","name":"getService","stateMutability":"view","inputs":[{"name":"provider","type":"address"}],"outputs":[{"name":"service","type":"tuple","components":[{"name":"provider","type":"address"},{"name":"serviceType","type":"string"},{"name":"url","type":"string"},{"name":"inputPrice","type":"uint256"},{"name":"outputPrice","type":"uint256"},{"name":"updatedAt","type":"uint256"},{"name":"model","type":"string"},{"name":"verifiability","type":"string"},{"name":"additionalInfo","type":"string"},{"name":"teeSignerAddress","type":"address"},{"name":"teeSignerAcknowledged","type":"bool"}]}]}]`

// client must be the safe outbound client used by the Labs backend. Tests may
// inject a transport. No call carries the Router API key to a provider or RPC.
func fetchComputeProof(ctx context.Context, client *http.Client, opts ComputeProofOptions) (*ComputeProof, string) {
	proof := &ComputeProof{Provider: opts.Provider, ChatID: opts.ChatID, Model: opts.Model, Registry: computeMainnetRegistry, ChainID: "16661"}
	unavailable := func(reason string) (*ComputeProof, string) { proof.Reason = reason; return proof, "unavailable" }
	if !common.IsHexAddress(opts.Provider) || common.HexToAddress(opts.Provider) == (common.Address{}) || !proofChatIDPattern.MatchString(opts.ChatID) {
		return unavailable("供應商地址或供應商 chat 識別碼缺漏或無效。")
	}
	if client == nil {
		client = util.NewSafeHTTPClient(util.SafeHTTPClientConfig{Timeout: 12 * time.Second})
	}
	rpcURL := opts.RPCURL
	if rpcURL == "" {
		rpcURL = computeMainnetRPC
	}
	if _, err := util.NormalizePublicHTTPSURL(rpcURL, false); err != nil {
		return unavailable("設定的鏈上 RPC 不是公開的 HTTPS/443。")
	}
	var chainID, block string
	if err := proofRPC(ctx, client, rpcURL, "eth_chainId", []any{}, &chainID); err != nil || chainID != "0x4115" {
		return unavailable("無法透過設定的 RPC 確認 0G mainnet 的 chain ID。")
	}
	if err := proofRPC(ctx, client, rpcURL, "eth_blockNumber", []any{}, &block); err != nil {
		return unavailable("無法取得登記表的快照區塊高度。")
	}
	proof.BlockNumber = block
	parsedABI, err := abi.JSON(strings.NewReader(computeServiceABI))
	if err != nil {
		return unavailable("登記表 ABI 無法使用。")
	}
	callData, err := parsedABI.Pack("getService", common.HexToAddress(opts.Provider))
	if err != nil {
		return unavailable("無法編碼服務查詢請求。")
	}
	var callResult string
	if err := proofRPC(ctx, client, rpcURL, "eth_call", []any{map[string]string{"to": computeMainnetRegistry, "data": hexutil.Encode(callData)}, block}, &callResult); err != nil {
		return unavailable("無法讀取 mainnet 上的供應商服務紀錄。")
	}
	rawService, err := hexutil.Decode(callResult)
	if err != nil {
		return unavailable("服務紀錄編碼無效。")
	}
	values, err := parsedABI.Unpack("getService", rawService)
	if err != nil || len(values) != 1 {
		return unavailable("服務紀錄不符合支援的登記表 ABI。")
	}
	service, ok := abi.ConvertType(values[0], new(computeService)).(*computeService)
	if !ok || service.Provider != common.HexToAddress(opts.Provider) || !service.TeeSignerAcknowledged || service.Verifiability != "TeeML" {
		return unavailable("登記表未提供此供應商已確認的 TeeML 簽署者。")
	}
	var additional struct {
		TargetSeparated  bool
		TargetTeeAddress string
		ProviderType     string
	}
	if receipt.ValidateUniqueJSON([]byte(service.AdditionalInfo)) != nil || json.Unmarshal([]byte(service.AdditionalInfo), &additional) != nil {
		return unavailable("登記表的額外簽署者中繼資料無法使用或無效。")
	}
	providerType := additional.ProviderType
	if providerType == "" {
		providerType = "decentralized"
	}
	if providerType != "decentralized" && providerType != "centralized" {
		return unavailable("登記表中的供應商類型不受支援。")
	}
	signer := service.TeeSignerAddress
	if additional.TargetSeparated && providerType == "decentralized" {
		if !common.IsHexAddress(additional.TargetTeeAddress) {
			return unavailable("分離式供應商的目標簽署者無效。")
		}
		signer = common.HexToAddress(additional.TargetTeeAddress)
	}
	if signer == (common.Address{}) {
		return unavailable("登記表的簽署者地址為空。")
	}
	providerURL, err := util.NormalizePublicHTTPSURL(service.Url, false)
	if err != nil {
		return unavailable("供應商證明端點不符合公開 HTTPS/443 政策。")
	}
	proof.SignerAddress = signer.Hex()
	proof.ProviderURL = providerURL
	proof.ProviderType = providerType
	proof.TrustSource = "0g_mainnet_registry_via_configured_rpc"
	endpoint := strings.TrimRight(providerURL, "/") + "/v1/proxy/signature/" + url.PathEscape(opts.ChatID)
	if opts.Model != "" {
		endpoint += "?" + url.Values{"model": {opts.Model}}.Encode()
	}
	raw, err := proofHTTP(ctx, client, http.MethodGet, endpoint, nil)
	if err != nil {
		return unavailable("供應商簽章端點無法使用；Router 驗證僅剩 Router 自身回報。")
	}
	var document struct {
		Text        string `json:"text"`
		Signature   string `json:"signature"`
		SigningAlgo string `json:"signing_algo"`
	}
	if receipt.ValidateUniqueJSON(raw) != nil || json.Unmarshal(raw, &document) != nil || document.Text == "" || document.Signature == "" {
		return unavailable("供應商未回傳受支援的原始簽章。")
	}
	if document.SigningAlgo != "" && document.SigningAlgo != "ecdsa" {
		return unavailable("不支援的供應商簽署演算法。")
	}
	proof.Text = document.Text
	proof.Signature = document.Signature
	recovered, err := recoverComputeSigner(document.Text, document.Signature)
	if err != nil || recovered != signer {
		proof.Reason = "供應商簽章復原出的地址與登記表簽署者不符。"
		return proof, "verification_failed"
	}
	proof.SignatureValid = true
	proof.IdentityVerified = true
	proof.Format, proof.RequestBound, proof.ResponseBound = computeContentBinding(document.Text, opts.RequestJSON, opts.ResponseJSON, providerType)
	proof.OutputBound = proof.ResponseBound && outputMatchesResponse(opts.ResponseJSON, opts.Output)
	if proof.Format == "" {
		return unavailable("供應商簽署格式不受支援；即使簽章有效，也不代表綁定此輸出內容。")
	}
	if !proof.RequestBound || !proof.ResponseBound || !proof.OutputBound {
		return unavailable("供應商簽章有效，但精確的請求／回應位元組不符。可能是 Router 轉換所致，且無法安全地還原，因此無法獨立綁定。")
	}
	proof.Reason = "EIP-191 簽章、登記表簽署者與精確的請求／回應位元組皆相符。這不代表已驗證模型正確性或硬體認證。"
	return proof, "independently_verified"
}

func recoverComputeSigner(text, signature string) (common.Address, error) {
	raw, err := hexutil.Decode(signature)
	if err != nil || len(raw) != 65 {
		return common.Address{}, errors.New("signature must be 65 hexadecimal bytes")
	}
	if raw[64] >= 27 {
		raw[64] -= 27
	}
	if raw[64] > 1 {
		return common.Address{}, errors.New("invalid signature recovery byte")
	}
	key, err := crypto.SigToPub(accounts.TextHash([]byte(text)), raw)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*key), nil
}

func computeContentBinding(text, requestJSON, responseJSON, providerType string) (format string, requestBound, responseBound bool) {
	parts := strings.Split(text, ":")
	if len(parts) < 2 || !proofDigestPattern.MatchString(parts[0]) || !proofDigestPattern.MatchString(parts[1]) {
		return "", false, false
	}
	if providerType == "decentralized" && len(parts) == 2 {
		format = "0g_plaintext_sha256_pair"
	}
	if providerType == "centralized" && len(parts) == 5 && parts[2] == "centralized" && parts[3] != "" && proofDigestPattern.MatchString(parts[4]) {
		format = "0g_centralized_routing_sha256"
	}
	if format == "" {
		return "", false, false
	}
	requestHash, responseHash := sha256.Sum256([]byte(requestJSON)), sha256.Sum256([]byte(responseJSON))
	return format, requestJSON != "" && hex.EncodeToString(requestHash[:]) == parts[0], responseJSON != "" && hex.EncodeToString(responseHash[:]) == parts[1]
}

func outputMatchesResponse(raw, output string) bool {
	if output == "" || receipt.ValidateUniqueJSON([]byte(raw)) != nil {
		return false
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	return json.Unmarshal([]byte(raw), &response) == nil && len(response.Choices) == 1 && response.Choices[0].Message.Content == output
}

func proofHTTP(ctx context.Context, client *http.Client, method, endpoint string, body []byte) ([]byte, error) {
	if _, err := util.NormalizePublicHTTPSURL(endpoint, true); err != nil {
		return nil, errors.New("proof URL is not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("proof HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("proof endpoint returned a non-200 status")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, proofBodyLimit+1))
	if err != nil || len(raw) > proofBodyLimit {
		return nil, errors.New("proof response exceeds the size limit")
	}
	return raw, nil
}

func proofRPC(ctx context.Context, client *http.Client, endpoint, method string, params []any, destination any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	raw, err := proofHTTP(ctx, client, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	if receipt.ValidateUniqueJSON(raw) != nil {
		return errors.New("RPC JSON is invalid")
	}
	var response struct {
		ID      int             `json:"id"`
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &response) != nil || response.ID != 1 || response.JSONRPC != "2.0" || len(response.Result) == 0 || (len(response.Error) > 0 && string(response.Error) != "null") {
		return errors.New("RPC result is invalid")
	}
	return json.Unmarshal(response.Result, destination)
}
