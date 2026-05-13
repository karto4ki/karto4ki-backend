package validator

import (
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}

	if len(email) > 254 {
		return false
	}

	if strings.Count(email, "@") != 1 {
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local := parts[0]
	domain := parts[1]

	if len(local) == 0 {
		return false
	}

	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}

	if len(domain) == 0 {
		return false
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}

	if !strings.Contains(domain, ".") {
		return false
	}

	domainParts := strings.Split(domain, ".")
	for i, part := range domainParts {
		if len(part) == 0 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if i == len(domainParts)-1 && len(part) < 2 {
			return false
		}
	}

	return emailRegex.MatchString(email)
}
