package authentication

import (
	"reflect"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestParseAuthorizedKeyOptions(t *testing.T) {
	tests := []struct {
		name           string
		opts           []string
		wantCritical   map[string]string
		wantExtensions map[string]string
		wantErr        bool
	}{
		{
			name:           "empty",
			opts:           nil,
			wantCritical:   map[string]string{},
			wantExtensions: map[string]string{},
		},
		{
			name:           "bare flags only",
			opts:           []string{"no-port-forwarding", "no-agent-forwarding"},
			wantCritical:   map[string]string{},
			wantExtensions: map[string]string{"no-port-forwarding": "", "no-agent-forwarding": ""},
		},
		{
			name:           "simple key=value",
			opts:           []string{`from="10.0.0.1"`},
			wantCritical:   map[string]string{"from": "10.0.0.1"},
			wantExtensions: map[string]string{},
		},
		{
			name:           "command with spaces",
			opts:           []string{`command="ls -la /tmp"`},
			wantCritical:   map[string]string{"command": "ls -la /tmp"},
			wantExtensions: map[string]string{},
		},
		{
			name:           "value containing equals",
			opts:           []string{`environment="FOO=bar"`},
			wantCritical:   map[string]string{"environment": "FOO=bar"},
			wantExtensions: map[string]string{},
		},
		{
			name:           "unquoted value",
			opts:           []string{"principals=alice"},
			wantCritical:   map[string]string{"principals": "alice"},
			wantExtensions: map[string]string{},
		},
		{
			name:           "empty quoted value",
			opts:           []string{`from=""`},
			wantCritical:   map[string]string{"from": ""},
			wantExtensions: map[string]string{},
		},
		{
			name:    "value that starts with a quote but does not end with one is rejected",
			opts:    []string{`command="unterminated`},
			wantErr: true,
		},
		{
			name:           "repeated multi-valued option joins with commas",
			opts:           []string{`permitopen="host-a:22"`, `permitopen="host-b:80"`},
			wantCritical:   map[string]string{"permitopen": "host-a:22,host-b:80"},
			wantExtensions: map[string]string{},
		},
		{
			name: "mixed flags and options",
			opts: []string{
				"no-pty",
				`command="/usr/bin/rrsync /srv/backup"`,
				`from="10.0.0.0/24"`,
				"restrict",
				`principals="alice,bob"`,
			},
			wantCritical: map[string]string{
				"command":    "/usr/bin/rrsync /srv/backup",
				"from":       "10.0.0.0/24",
				"principals": "alice,bob",
			},
			wantExtensions: map[string]string{
				"no-pty":   "",
				"restrict": "",
			},
		},
		{
			name:           "comma inside a single environment value is preserved",
			opts:           []string{`environment="A=1,2"`},
			wantCritical:   map[string]string{"environment": "A=1,2"},
			wantExtensions: map[string]string{},
		},
		{
			name:           "escaped quotes and backslashes inside quoted value",
			opts:           []string{`command="say \"hi\" && C:\\bin\\sh"`},
			wantCritical:   map[string]string{"command": `say "hi" && C:\bin\sh`},
			wantExtensions: map[string]string{},
		},
		{
			name:           "repeated identical single-valued option is idempotent",
			opts:           []string{`from="10.0.0.1"`, `from="10.0.0.1"`},
			wantCritical:   map[string]string{"from": "10.0.0.1"},
			wantExtensions: map[string]string{},
		},
		{
			name: "all allowlisted bare flags and value options",
			opts: []string{
				"restrict",
				"no-agent-forwarding",
				"no-port-forwarding",
				"no-pty",
				"no-user-rc",
				"no-x11-forwarding",
				"no-verify-required",
				"permitlisten=localhost:80",
				"expiry-time=20300101",
				"tunnel=1",
			},
			wantCritical: map[string]string{
				"permitlisten": "localhost:80",
				"expiry-time":  "20300101",
				"tunnel":       "1",
			},
			wantExtensions: map[string]string{
				"restrict":            "",
				"no-agent-forwarding": "",
				"no-port-forwarding":  "",
				"no-pty":              "",
				"no-user-rc":          "",
				"no-x11-forwarding":   "",
				"no-verify-required":  "",
			},
		},
		{
			name:    "unknown bare flag is rejected",
			opts:    []string{"not-a-real-option"},
			wantErr: true,
		},
		{
			name:    "unknown value option is rejected",
			opts:    []string{`evil="all-the-privileges"`},
			wantErr: true,
		},
		{
			name:    "option with empty name is rejected",
			opts:    []string{"=value"},
			wantErr: true,
		},
		{
			name:    "conflicting repeated single-valued option is rejected",
			opts:    []string{`command="one"`, `command="two"`},
			wantErr: true,
		},
		{
			name:    "conflicting principals values are rejected",
			opts:    []string{`principals="alice"`, `principals="bob"`},
			wantErr: true,
		},
		{
			name:    "mutually exclusive verify flags are rejected",
			opts:    []string{"verify-required", "no-verify-required"},
			wantErr: true,
		},
		{
			name:    "environment value without NAME=value shape is rejected",
			opts:    []string{`environment="NOEQUALS"`},
			wantErr: true,
		},
		{
			name:    "environment value with empty name is rejected",
			opts:    []string{`environment="=bar"`},
			wantErr: true,
		},
		{
			name:    "unquoted value containing a quote is rejected",
			opts:    []string{`command=ls"x`},
			wantErr: true,
		},
		{
			name:    "dangling backslash in quoted value is rejected",
			opts:    []string{`command="foo\`},
			wantErr: true,
		},
		{
			name:    "unescaped quote inside quoted value is rejected",
			opts:    []string{`command="foo"bar"`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCritical, gotExtensions, err := ParseAuthorizedKeyOptions(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got critical=%#v extensions=%#v", gotCritical, gotExtensions)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(gotCritical, tt.wantCritical) {
				t.Errorf("criticalOptions = %#v, want %#v", gotCritical, tt.wantCritical)
			}
			if !reflect.DeepEqual(gotExtensions, tt.wantExtensions) {
				t.Errorf("extensions = %#v, want %#v", gotExtensions, tt.wantExtensions)
			}
		})
	}
}

// TestParseAuthorizedKeyOptions_MatchesUpstreamFormat verifies that the
// helper accepts the exact strings returned by golang.org/x/crypto/ssh.ParseAuthorizedKey,
// so future upstream changes to that format will be caught here.
func TestParseAuthorizedKeyOptions_MatchesUpstreamFormat(t *testing.T) {
	// A minimal authorized_keys line: a set of options followed by a valid key.
	// The key material below is a throwaway ed25519 public key generated for
	// this test; it is never used as a credential.
	const line = `no-port-forwarding,command="echo hi",environment="X=1",environment="Y=2" ` +
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmm3fVj1v0BXCLxYK7BOQpq/hn5V4XvW2eXk3nLKC0e test@example`

	_, _, opts, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}

	critical, extensions, err := ParseAuthorizedKeyOptions(opts)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeyOptions: %v", err)
	}

	if got, want := critical["command"], "echo hi"; got != want {
		t.Errorf("command = %q, want %q (opts=%#v)", got, want, opts)
	}
	if got, want := critical["environment"], "X=1,Y=2"; got != want {
		t.Errorf("environment = %q, want %q (opts=%#v)", got, want, opts)
	}
	if _, ok := extensions["no-port-forwarding"]; !ok {
		t.Errorf("expected bare flag no-port-forwarding in extensions, got %#v", extensions)
	}
}
