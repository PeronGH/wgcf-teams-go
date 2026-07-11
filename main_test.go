package main

import "testing"

func TestExtractToken(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"bare token", "eyJhbGciOiJSUzI1NiJ9.payload.sig\n", "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
		{"callback URL", "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=eyJfoo\n", "eyJfoo"},
		{"URL with token mid-query", "https://example.com/x?a=1&token=eyJbar&b=2", "eyJbar"},
		{
			"redirect button onclick",
			"location.href = 'com.cloudflare.warp://example.cloudflareaccess.com/auth?token=eyJhbGc.pay_lo-ad.sig';\n",
			"eyJhbGc.pay_lo-ad.sig",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extractToken(c.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	if _, err := extractToken("  \n"); err == nil {
		t.Error("expected an error for blank input")
	}
}

func TestValidTeamName(t *testing.T) {
	for _, valid := range []string{"acme", "my-team-2"} {
		if !validTeamName(valid) {
			t.Errorf("%q should be valid", valid)
		}
	}
	for _, invalid := range []string{"", "a.b", "a/b", "a b", "team.cloudflareaccess.com"} {
		if validTeamName(invalid) {
			t.Errorf("%q should be invalid", invalid)
		}
	}
}
