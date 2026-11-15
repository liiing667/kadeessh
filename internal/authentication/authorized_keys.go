package authentication

import (
	"errors"
	"fmt"
	"strings"
)

// bareOptions is the allowlist of authorized_keys options that take no value
// and therefore map onto the session Extensions. It mirrors the option names
// documented in the sshd(8) "AUTHORIZED_KEYS FILE FORMAT" section.
var bareOptions = map[string]struct{}{
	"restrict":            {},
	"no-agent-forwarding": {},
	"no-port-forwarding":  {},
	"no-pty":              {},
	"no-user-rc":          {},
	"no-x11-forwarding":   {},
	"no-verify-required":  {},
	"verify-required":     {},
}

// criticalOptionNames is the allowlist of authorized_keys options that take a
// value and therefore map onto the session CriticalOptions.
var criticalOptionNames = map[string]struct{}{
	"command":      {},
	"environment":  {},
	"expiry-time":  {},
	"from":         {},
	"permitlisten": {},
	"permitopen":   {},
	"principals":   {},
	"tunnel":       {},
}

// multiValuedCriticalOptions are the value-taking options whose occurrences
// accumulate rather than conflict. Their values are joined with commas, which
// is how the SSH protocol serializes multi-valued critical options.
var multiValuedCriticalOptions = map[string]struct{}{
	"environment":  {},
	"permitlisten": {},
	"permitopen":   {},
}

// conflictingExtensionPairs records bare options that are mutually exclusive
// when present on the same authorized_keys entry.
var conflictingExtensionPairs = [][2]string{
	{"no-verify-required", "verify-required"},
}

// ParseAuthorizedKeyOptions splits the option list returned by
// ssh.ParseAuthorizedKey into an SSH-certificate-style pair of maps:
//
//   - criticalOptions receives every recognized "key=value" option. Quoted
//     values are unquoted, honoring backslash escapes, so command="ls -la"
//     yields criticalOptions["command"] == "ls -la".
//   - extensions receives every recognized bare option (no "=") as key with an
//     empty value, e.g. "no-port-forwarding".
//
// Multi-valued options (permitopen, permitlisten, environment) accumulate
// their occurrences, joined with commas. A repeated single-valued option
// (e.g. two command= entries) is ambiguous and rejected.
//
// Unknown options, conflicting bare flags, malformed quoting and malformed
// environment entries produce an error so that callers fail closed instead of
// silently widening the authorization boundary of a key.
func ParseAuthorizedKeyOptions(opts []string) (criticalOptions, extensions map[string]string, err error) {
	criticalOptions = map[string]string{}
	extensions = map[string]string{}
	for _, opt := range opts {
		key, rawValue, hasValue := strings.Cut(opt, "=")
		if key == "" {
			return nil, nil, fmt.Errorf("authorized_keys option with empty name: %q", opt)
		}
		if !hasValue {
			if _, ok := bareOptions[key]; !ok {
				return nil, nil, fmt.Errorf("authorized_keys: unknown or unsupported option %q", key)
			}
			extensions[key] = ""
			continue
		}

		if _, ok := criticalOptionNames[key]; !ok {
			return nil, nil, fmt.Errorf("authorized_keys: unknown or unsupported option %q", key)
		}
		value, err := unquoteOptionValue(rawValue)
		if err != nil {
			return nil, nil, fmt.Errorf("authorized_keys option %q: %w", key, err)
		}
		if key == "environment" {
			if name, _, ok := strings.Cut(value, "="); !ok || name == "" {
				return nil, nil, fmt.Errorf("authorized_keys option %q: value %q is not a NAME=value pair", key, value)
			}
		}

		if _, multi := multiValuedCriticalOptions[key]; multi {
			if existing, ok := criticalOptions[key]; ok {
				criticalOptions[key] = existing + "," + value
				continue
			}
			criticalOptions[key] = value
			continue
		}
		if existing, ok := criticalOptions[key]; ok && existing != value {
			return nil, nil, fmt.Errorf("authorized_keys option %q: conflicting values %q and %q", key, existing, value)
		}
		criticalOptions[key] = value
	}

	for _, pair := range conflictingExtensionPairs {
		_, first := extensions[pair[0]]
		_, second := extensions[pair[1]]
		if first && second {
			return nil, nil, fmt.Errorf("authorized_keys: mutually exclusive options %q and %q", pair[0], pair[1])
		}
	}
	return criticalOptions, extensions, nil
}

// unquoteOptionValue decodes the value half of an option token. Values wrapped
// in a matching pair of double quotes are unwrapped, honoring the backslash
// escapes allowed by sshd's authorized_keys parsing (\\ and \").
func unquoteOptionValue(raw string) (string, error) {
	if len(raw) < 2 || raw[0] != '"' {
		if strings.ContainsRune(raw, '"') {
			return "", errors.New("value contains an unescaped double quote")
		}
		return raw, nil
	}
	if raw[len(raw)-1] != '"' {
		return "", errors.New("quoted value is not properly terminated")
	}

	var builder strings.Builder
	builder.Grow(len(raw) - 2)
	for i := 1; i < len(raw)-1; {
		char := raw[i]
		if char != '\\' {
			if char == '"' {
				return "", errors.New("quoted value contains an unescaped double quote")
			}
			builder.WriteByte(char)
			i++
			continue
		}
		if i+1 >= len(raw)-1 {
			return "", errors.New("dangling backslash in quoted value")
		}
		switch raw[i+1] {
		case '\\', '"':
			builder.WriteByte(raw[i+1])
		default:
			builder.WriteByte('\\')
			builder.WriteByte(raw[i+1])
		}
		i += 2
	}
	return builder.String(), nil
}
