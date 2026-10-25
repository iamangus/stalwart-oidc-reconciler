package reconcile

import (
	"errors"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
)

var localPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func validLocal(s string) bool { return len(s) <= 64 && localPattern.MatchString(s) }

func namePart(s string) (string, error) {
	var out strings.Builder
	separator := false
	for _, r := range norm.NFKD.String(strings.ToLower(strings.TrimSpace(s))) {
		switch {
		case unicode.Is(unicode.Mn, r):
			continue
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			if separator && out.Len() > 0 {
				out.WriteByte('-')
			}
			separator = false
			out.WriteRune(r)
		case unicode.IsSpace(r) || r == '-':
			separator = true
		case r == '\'' || r == '’':
			continue
		default:
			// Never silently drop non-Latin names into ambiguous addresses.
			return "", errors.New("name requires an explicit address override")
		}
	}
	if out.Len() == 0 {
		return "", errors.New("given and family names are required (or set address override)")
	}
	return out.String(), nil
}

func address(u identity.User, domain string, overrides map[string]string) (string, error) {
	if local, ok := overrides[u.ID]; ok {
		if !validLocal(local) {
			return "", errors.New("address override must be a lowercase local part, at most 64 characters")
		}
		return local + "@" + domain, nil
	}
	first, err := namePart(u.GivenName)
	if err != nil {
		return "", err
	}
	last, err := namePart(u.FamilyName)
	if err != nil {
		return "", err
	}
	local := first + "." + last
	if !validLocal(local) {
		return "", errors.New("generated address is invalid or exceeds 64 characters")
	}
	return local + "@" + domain, nil
}
