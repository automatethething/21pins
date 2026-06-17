package hosted

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func VerifyStoredAttestation(a policy.IdentityAttestation, now time.Time) error {
	issuer := strings.TrimSpace(a.Issuer)
	if issuer == "" {
		return fmt.Errorf("missing attestation issuer")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("invalid attestation issuer")
	}
	pub, err := PublicKeyFromEnv(a.KeyID)
	if err != nil {
		return fmt.Errorf("public key lookup failed: %w", err)
	}
	return policy.VerifyIdentityAttestation(a, pub, issuer, now)
}
