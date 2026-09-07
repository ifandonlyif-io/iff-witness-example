// Package prober parses and validates an x402 v2 PaymentRequired payload
// using the official x402 SDK, and extracts its payment options into the
// normalized shape the fingerprint algorithm consumes.
//
// This is a trimmed extract of IFF's internal x402 prober: the live-probing
// (SSRF-safe HTTP fetch of a target endpoint) and domain-ownership-challenge
// pieces have been removed, since Witness never fetches a target endpoint
// itself — it only parses a payment_required payload the caller already
// obtained independently. What remains is pure parsing/validation logic with
// no network access and no database coupling.
package prober

import (
	"fmt"
	"math/big"

	preflight "github.com/ifandonlyif-io/iff-x402-transparency/go"
	officialx402 "github.com/x402-foundation/x402/go/v2"
	officialtypes "github.com/x402-foundation/x402/go/v2/types"
)

// ParsePaymentRequiredBody parses a raw (non-base64) x402 v2 PaymentRequired
// JSON body into the official SDK type.
func ParsePaymentRequiredBody(body []byte) (*officialtypes.PaymentRequired, error) {
	required, err := officialtypes.ToPaymentRequired(body)
	if err != nil {
		return nil, fmt.Errorf("payment_required is not valid x402 JSON: %w", err)
	}
	return required, nil
}

// validateOfficialRequirement applies the official SDK's structural checks
// plus the additional bounds C1 fingerprinting depends on: a positive
// integer amount, a positive timeout, and a network the SDK can parse.
func validateOfficialRequirement(requirement officialtypes.PaymentRequirements) error {
	if err := officialx402.ValidatePaymentRequirements(requirement); err != nil {
		return err
	}
	if requirement.MaxTimeoutSeconds <= 0 {
		return fmt.Errorf("maxTimeoutSeconds must be positive")
	}
	amount, ok := new(big.Int).SetString(requirement.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return fmt.Errorf("amount must be a positive base-10 integer")
	}
	if _, _, err := officialx402.Network(requirement.Network).Parse(); err != nil {
		return err
	}
	return nil
}

// ValidateAndExtractPaymentOptions validates a parsed x402 v2 PaymentRequired's
// protocol version and each accepted option using the official SDK, and
// converts valid options into the normalized shape the public
// iff-x402-transparency fingerprint algorithm consumes. Identical input must
// always produce an identical set of options and therefore an identical
// fingerprint (C1).
//
// On success it returns the options and the check code "x402_v2_valid". On
// failure it returns a nil slice, a check code describing what failed
// ("unsupported_x402_version" | "payment_options_missing" |
// "invalid_payment_option"), and a non-nil error with more detail.
func ValidateAndExtractPaymentOptions(paymentRequired *officialtypes.PaymentRequired) ([]preflight.PaymentOption, string, error) {
	if paymentRequired.X402Version != officialx402.ProtocolVersion {
		return nil, "unsupported_x402_version", fmt.Errorf("unsupported x402 version %d", paymentRequired.X402Version)
	}
	if len(paymentRequired.Accepts) == 0 {
		return nil, "payment_options_missing", fmt.Errorf("no payment options in accepts")
	}
	options := make([]preflight.PaymentOption, 0, len(paymentRequired.Accepts))
	for _, option := range paymentRequired.Accepts {
		if err := validateOfficialRequirement(option); err != nil {
			return nil, "invalid_payment_option", fmt.Errorf("invalid payment option: %w", err)
		}
		options = append(options, preflight.PaymentOption{
			Scheme: option.Scheme, Network: option.Network, Asset: option.Asset,
			Amount: option.Amount, PayTo: option.PayTo,
			MaxTimeoutSeconds: option.MaxTimeoutSeconds,
		})
	}
	return options, "x402_v2_valid", nil
}
