package revocation

import (
	"errors"
	"sort"
	"strings"
)

// AllowedReasons are the operator-selectable revocation reasons.
var AllowedReasons = []string{
	"key_compromise",
	"ca_compromise",
	"superseded",
	"cessation_of_operation",
	"unspecified",
}

// ValidateReason rejects reasons outside the allowed set.
func ValidateReason(reason string) error {
	for _, allowed := range AllowedReasons {
		if reason == allowed {
			return nil
		}
	}
	return errors.New("unsupported revocation reason")
}

// ListByReason returns the allowed reasons sorted for the console.
func ListByReason() []string {
	out := append([]string(nil), AllowedReasons...)
	sort.Strings(out)
	return out
}

// NormalizeListedReason normalizes and validates an operator-provided reason.
func NormalizeListedReason(reason string) (string, error) {
	normalized := NormalizeReason(strings.TrimSpace(reason))
	if err := ValidateReason(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}
