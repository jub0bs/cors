package origins_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/origins"
)

type TestCase struct {
	desc    string
	input   string
	want    origins.Pattern
	failure bool
}

const validHostOf251chars = "a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a234567"

var parsePatternTestCases = []TestCase{
	{
		desc:    "wildcard character sequence followed by 252 chars",
		input:   "https://*.a" + validHostOf251chars,
		failure: true,
	}, {
		desc:  "wildcard character sequence followed by 251 chars",
		input: "https://*." + validHostOf251chars,
		want: origins.Pattern{
			Scheme:      "https",
			HostPattern: "*." + validHostOf251chars,
			Kind:        origins.ArbitrarySubdomains,
		},
	}, {
		desc:    "null origin",
		input:   "null",
		failure: true,
	}, {
		desc:    "userinfo",
		input:   "https://user:password@example.com:6060",
		failure: true,
	}, {
		desc:    "path",
		input:   "https://example.com:6060/foo",
		failure: true,
	}, {
		desc:    "querystring delimiter with empty querystring",
		input:   "https://example.com:6060?",
		failure: true,
	}, {
		desc:    "querystring",
		input:   "https://example.com:6060?foo=bar",
		failure: true,
	}, {
		desc:    "fragment",
		input:   "https://example.com:6060#nav",
		failure: true,
	}, {
		desc:    "short input without scheme-host delimiter",
		input:   "ab",
		failure: true,
	}, {
		desc:    "short input with colon but without double slash",
		input:   "ab:",
		failure: true,
	}, {
		desc:    "whitespace",
		input:   " http://example.com:6060 ",
		failure: true,
	}, {
		desc:  "non-HTTP scheme",
		input: "connector://foo",
		want: origins.Pattern{
			Scheme:      "connector",
			HostPattern: "foo",
			Kind:        origins.Domain,
		},
	}, {
		desc:    "file scheme",
		input:   "file:///foo",
		failure: true,
	}, {
		desc:    "invalid first char in scheme",
		input:   "42-chrome-extension://foo",
		failure: true,
	}, {
		desc:    "invalid later char in scheme",
		input:   "chrome-extension*://foo",
		failure: true,
	}, {
		desc:    "http with explicit port 80",
		input:   "http://foo:80",
		failure: true,
	}, {
		desc:    "https with explicit port 443",
		input:   "https://foo:443",
		failure: true,
	}, {
		desc:    "invalid host char",
		input:   "https://^foo",
		failure: true,
	}, {
		desc:    "single-digit host",
		input:   "http://1:6060",
		failure: true,
	}, {
		desc:    "host containing non-ASCII chars",
		input:   "https://résumé.com",
		failure: true,
	}, {
		desc:    "invalid host char after label sep",
		input:   "https://foo.^bar",
		failure: true,
	}, {
		desc:    "domain with colon but no port",
		input:   "https://foo:",
		failure: true,
	}, {
		desc:    "domain with negative port",
		input:   "https://foo:-1",
		failure: true,
	}, {
		desc:    "domain with 0 port",
		input:   "https://foo:0",
		failure: true,
	}, {
		desc:    "non-numeric port",
		input:   "https://foo:abc",
		failure: true,
	}, {
		desc:    "leading nonzero digit in port",
		input:   "https://foo:06060",
		failure: true,
	}, {
		desc:    "5-digit port followed by junk",
		input:   "https://foo:12345foo",
		failure: true,
	}, {
		desc:    "port longer than five digits",
		input:   "https://foo:123456",
		failure: true,
	}, {
		desc:    "overflow port",
		input:   "https://foo:65536",
		failure: true,
	}, {
		desc:    "valid port followed by junk",
		input:   "https://foo:12390abc",
		failure: true,
	}, {
		desc:    "invalid TLD",
		input:   "http://foo.bar.255:6060",
		failure: true,
	}, {
		desc:    "longer invalid TLD",
		input:   "http://foo.bar.baz.012345678901234567890123456789:6060",
		failure: true,
	}, {
		desc:    "invalid IP address",
		input:   "http://[::1]1:6060",
		failure: true,
	}, {
		desc:    "IP host with colon but no port",
		input:   "http://127.0.0.1:",
		failure: true,
	}, {
		desc:    "IP with negative port",
		input:   "http://127.0.0.1:-1",
		failure: true,
	}, {
		desc:    "IP with 0 port",
		input:   "http://127.0.0.1:0",
		failure: true,
	}, {
		desc:  "https scheme with IPv4 host",
		input: "https://127.0.0.1:90",
		want: origins.Pattern{
			Scheme:      "https",
			HostPattern: "127.0.0.1",
			Kind:        origins.LoopbackIP,
			Port:        90,
		},
	}, {
		desc:    "IPv4 host with trailing full stop",
		input:   "https://127.0.0.1.:90",
		failure: true,
	}, {
		desc:    "malformed ipv4 with one too many octets",
		input:   "http://127.0.0.1.1",
		failure: true,
	}, {
		desc:  "non-loopback IPv4",
		input: "http://69.254.169.254",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "69.254.169.254",
			Kind:        origins.NonLoopbackIP,
		},
	}, {
		desc:  "loopback IPv4",
		input: "http://127.0.0.1:90",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "127.0.0.1",
			Kind:        origins.LoopbackIP,
			Port:        90,
		},
	}, {
		desc:  "https scheme with IPv6 host",
		input: "https://[::1]:90",
		want: origins.Pattern{
			Scheme:      "https",
			HostPattern: "::1",
			Kind:        origins.LoopbackIP,
			Port:        90,
		},
	}, {
		desc:    "junk in brackets",
		input:   "http://[example]:90",
		failure: true,
	}, {
		desc:    "too brackets around IPv6",
		input:   "https://::1:90",
		failure: true,
	}, {
		desc:    "missing closing bracket in IPv6",
		input:   "http://[::1:90",
		failure: true,
	}, {
		desc:    "missing opening bracket in IPv6",
		input:   "https://::1]:90",
		failure: true,
	}, {
		desc:    "IPv6 preceded by junk",
		input:   "https://abc[::1]:90",
		failure: true,
	}, {
		desc:    "IPv6 followed by junk",
		input:   "https://[::1]abc:90",
		failure: true,
	}, {
		desc:  "non-loopback IPv6 with hexadecimal chars",
		input: "http://[2001:db8:aaaa:1111::100]:9090",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "2001:db8:aaaa:1111::100",
			Kind:        origins.NonLoopbackIP,
			Port:        9090,
		},
	}, {
		desc:  "loopback IPv6 address with port",
		input: "http://[::1]:90",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "::1",
			Kind:        origins.LoopbackIP,
			Port:        90,
		},
	}, {
		desc:    "loopback IPv4 in non-standard form",
		input:   "http://127.1:3999",
		failure: true,
	}, {
		desc:    "too many colons in IPv6",
		input:   "http://[::::::::::::::::1]:90",
		failure: true,
	}, {
		desc:    "uncompressed IPv6",
		input:   "http://[2001:4860:4860:0000:0000:0000:0000:8888]:90",
		failure: true,
	}, {
		desc:    "IPv6 with a zone",
		input:   "http://[fe80::1ff:fe23:4567:890a%eth2]:90",
		failure: true,
	}, {
		desc:    "IPv4-mapped IPv6",
		input:   "http://[::ffff:7f7f:7f7f]:90",
		failure: true,
	}, {
		desc:    "host contains uppercase letters",
		input:   "http://exAmplE.coM:3999",
		failure: true,
	}, {
		desc:  "host contains underscores and hyphens",
		input: "http://ex_am-ple.com:3999",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "ex_am-ple.com",
			Kind:        origins.Domain,
			Port:        3999,
		},
	}, {
		desc:  "trailing full stop in host",
		input: "http://example.com.:3999",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "example.com.",
			Kind:        origins.Domain,
			Port:        3999,
		},
	}, {
		desc:    "multiple trailing full stops in host",
		input:   "http://example.com..:3999",
		failure: true,
	}, {
		desc:    "empty label",
		input:   "http://example..com:3999",
		failure: true,
	}, {
		desc:    "host contains invalid Punycode label",
		input:   "http://xn--f",
		failure: true,
	}, {
		desc:  "arbitrary subdomains",
		input: "http://*.example.com:3999",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "*.example.com",
			Kind:        origins.ArbitrarySubdomains,
			Port:        3999,
		},
	}, {
		desc:  "arbitrary subdomains and arbitrary ports",
		input: "http://*.example.com:*",
		want: origins.Pattern{
			Scheme:      "http",
			HostPattern: "*.example.com",
			Kind:        origins.ArbitrarySubdomains,
			Port:        arbitraryPort,
		},
	}, {
		desc:    "leading double asterisk",
		input:   "http://**.example.com:3999",
		failure: true,
	}, {
		desc:    "out-of-place wildcard",
		input:   "http://fooo.*.example.com:3999",
		failure: true,
	}, {
		desc:    "wildcard not followed by a full stop",
		input:   "http://*example.com:3999",
		failure: true,
	}, {
		desc:    "wildcard character sequence with IPv6",
		input:   "http://*.[::1]:3999",
		failure: true,
	}, {
		desc:    "wildcard character sequence with IPv4",
		input:   "http://*.127.0.0.1:3999",
		failure: true,
	},
}

const arbitraryPort = -1 // keep in sync with origins.arbitraryPort

func TestParsePattern(t *testing.T) {
	for _, tc := range parsePatternTestCases {
		f := func(t *testing.T) {
			t.Parallel()
			o, err := origins.ParsePattern(tc.input)
			if err != nil && !tc.failure {
				const tmpl = "origins.ParsePattern(%q): got %v; want nil error"
				t.Errorf(tmpl, tc.input, err)
				return
			}
			if err == nil && tc.failure {
				const tmpl = "origins.ParsePattern(%q): got nil error; want non-nil error"
				t.Errorf(tmpl, tc.input)
				return
			}
			if err == nil && o != tc.want {
				const tmpl = "origins.ParsePattern(%q): got %+v; want %+v"
				t.Errorf(tmpl, tc.input, o, tc.want)
				return
			}
		}
		t.Run(tc.desc, f)
	}
}

func TestIsDeemedInsecure(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{
			pattern: "https://example.com",
			want:    false,
		}, {
			pattern: "https://*.example.com",
			want:    false,
		}, {
			pattern: "http://example.com",
			want:    true,
		}, {
			pattern: "http://*.example.com",
			want:    true,
		}, {
			pattern: "http://127.0.0.1",
			want:    false,
		}, {
			pattern: "http://127.127.127.127",
			want:    false,
		}, {
			pattern: "http://169.254.169.254:90",
			want:    true,
		}, {
			pattern: "http://[::1]:90",
			want:    false,
		}, {
			pattern: "http://[2001:db8:aaaa:1111::100]:9090",
			want:    true,
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			pattern, err := origins.ParsePattern(tc.pattern)
			if err != nil {
				t.Errorf("got %v; want non-nil error", err)
				return
			}
			got := pattern.IsDeemedInsecure()
			if got != tc.want {
				t.Errorf("got %t; want %t", got, tc.want)
			}
		}
		t.Run(tc.pattern, f)
	}
}

func TestHostIsEffectiveTLD(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{
			pattern: "https://*.com",
			want:    true,
		}, {
			pattern: "https://*.github.io",
			want:    true,
		}, {
			pattern: "https://*.github.io",
			want:    true,
		}, {
			pattern: "https://*.example.com",
			want:    false,
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			pattern, err := origins.ParsePattern(tc.pattern)
			if err != nil {
				t.Errorf("got %v; want non-nil error", err)
				return
			}
			got := pattern.HostIsEffectiveTLD()
			if got != tc.want {
				t.Errorf("got %t; want %t", got, tc.want)
			}
		}
		t.Run(tc.pattern, f)
	}
}
