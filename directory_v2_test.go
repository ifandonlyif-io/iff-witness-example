package witness

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ifandonlyif-io/iff-witness-example/receipt"
)

func TestTrustedDirectoryKeysAcceptsOnlyMLDSA65(t *testing.T) {
	signer, err := receipt.NewSigner(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	edPublic := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	edParsed, err := receipt.ParsePublicKey(edPublic)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://ifandonlyif.io"
	build := func(schema string, mlAlgorithm string) []byte {
		raw, _ := json.Marshal(map[string]any{"schema": schema, "issuer": issuer, "enabled": true, "keys": []any{
			map[string]string{"key_id": signer.KeyID(), "algorithm": mlAlgorithm, "public_key": signer.PublicKeyBase64URL(), "purpose": "service-receipt-signing", "status": "current"},
			map[string]string{"key_id": edParsed.KeyID, "algorithm": receipt.AlgorithmEd25519, "public_key": edPublic, "purpose": "service-receipt-signing", "status": "previous"},
		}})
		return raw
	}
	ids, err := trustedDirectoryKeys(build(receipt.KeyDirectorySchemaV2, receipt.AlgorithmMLDSA65), issuer, nil)
	if err != nil || len(ids) != 1 || ids[0] != signer.KeyID() {
		t.Fatalf("v2 directory must trust only the ML-DSA-65 key: %v, %v", ids, err)
	}
	if _, err := trustedDirectoryKeys(build(receipt.KeyDirectorySchemaV2, receipt.AlgorithmEd25519), issuer, nil); err == nil {
		t.Fatal("a directory entry declaring the wrong algorithm was trusted")
	}
	if _, err := trustedDirectoryKeys(build("https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json", receipt.AlgorithmMLDSA65), issuer, nil); err == nil {
		t.Fatal("a v1 key directory was trusted")
	}
	if _, err := trustedDirectoryKeys(build(receipt.KeyDirectorySchemaV2, receipt.AlgorithmMLDSA65), issuer, []string{edParsed.KeyID}); err == nil {
		t.Fatal("pinning an Ed25519 key id made it trusted for new receipts")
	}
}
