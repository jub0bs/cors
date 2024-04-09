package origins

import (
	"testing"
)

type TestCase struct {
	name    string
	input   string
	want    Pattern
	failure bool
}

const validHostOf251chars = "a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a2345678901234567890123456789012345678901234567890" +
	"1234567890.a234567"

var parsePatternCases = []TestCase{
	{
		name:    "wildcard character sequence followed by 252 chars",
		input:   "https://*.a" + validHostOf251chars,
		failure: true,
	}, {
		name:  "wildcard character sequence followed by 251 chars",
		input: "https://*." + validHostOf251chars,
		want: Pattern{
			Scheme: "https",
			HostPattern: HostPattern{
				Value: "*." + validHostOf251chars,
				Kind:  PatternKindSubdomains,
			},
		},
	}, {
		name:    "null origin",
		input:   "null",
		failure: true,
	}, {
		name:    "userinfo",
		input:   "https://user:password@example.com:6060",
		failure: true,
	}, {
		name:    "path",
		input:   "https://example.com:6060/foo",
		failure: true,
	}, {
		name:    "querystring delimiter with empty querystring",
		input:   "https://example.com:6060?",
		failure: true,
	}, {
		name:    "querystring",
		input:   "https://example.com:6060?foo=bar",
		failure: true,
	}, {
		name:    "fragment",
		input:   "https://example.com:6060#nav",
		failure: true,
	}, {
		name:    "short input without scheme-host delimiter",
		input:   "ab",
		failure: true,
	}, {
		name:    "whitespace",
		input:   " http://example.com:6060 ",
		failure: true,
	}, {
		name:    "short invalid scheme",
		input:   "ab://foo",
		failure: true,
	}, {
		name:    "httpfoo scheme",
		input:   "httpfoo://foo",
		failure: true,
	}, {
		name:    "httpsfoo scheme",
		input:   "httpsfoo://foo",
		failure: true,
	}, {
		name:    "http with explicit port 80",
		input:   "http://foo:80",
		failure: true,
	}, {
		name:    "https with explicit port 443",
		input:   "https://foo:443",
		failure: true,
	}, {
		name:    "invalid host char",
		input:   "https://^foo",
		failure: true,
	}, {
		name:    "single-digit host",
		input:   "http://1:6060",
		failure: true,
	}, {
		name:    "host containing non-ASCII chars",
		input:   "https://résumé.com",
		failure: true,
	}, {
		name:    "invalid host char after label sep",
		input:   "https://foo.^bar",
		failure: true,
	}, {
		name:    "domain with colon but no port",
		input:   "https://foo:",
		failure: true,
	}, {
		name:    "domain with negative port",
		input:   "https://foo:-1",
		failure: true,
	}, {
		name:    "domain with 0 port",
		input:   "https://foo:0",
		failure: true,
	}, {
		name:    "non-numeric port",
		input:   "https://foo:abc",
		failure: true,
	}, {
		name:    "leading nonzero digit in port",
		input:   "https://foo:06060",
		failure: true,
	}, {
		name:    "5-digit port followed by junk",
		input:   "https://foo:12345foo",
		failure: true,
	}, {
		name:    "port longer than five digits",
		input:   "https://foo:123456",
		failure: true,
	}, {
		name:    "overflow port",
		input:   "https://foo:65536",
		failure: true,
	}, {
		name:    "valid port followed by junk",
		input:   "https://foo:12390abc",
		failure: true,
	}, {
		name:    "invalid TLD",
		input:   "http://foo.bar.255:6060",
		failure: true,
	}, {
		name:    "longer invalid TLD",
		input:   "http://foo.bar.baz.012345678901234567890123456789:6060",
		failure: true,
	}, {
		name:    "invalid IP address",
		input:   "http://[::1]1:6060",
		failure: true,
	}, {
		name:    "IP host with colon but no port",
		input:   "http://127.0.0.1:",
		failure: true,
	}, {
		name:    "IP with negative port",
		input:   "http://127.0.0.1:-1",
		failure: true,
	}, {
		name:    "IP with 0 port",
		input:   "http://127.0.0.1:0",
		failure: true,
	}, {
		name:    "https scheme with IPv4 host",
		input:   "https://127.0.0.1:90",
		failure: true,
	}, {
		name:    "IPv4 host with trailing full stop",
		input:   "https://127.0.0.1.:90",
		failure: true,
	}, {
		name:    "malformed ipv4 with one too many octets",
		input:   "http://127.0.0.1.1",
		failure: true,
	}, {
		name:  "non-loopback IPv4",
		input: "http://69.254.169.254",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "69.254.169.254",
				Kind:  PatternKindNonLoopbackIP,
			},
		},
	}, {
		name:  "loopback IPv4",
		input: "http://127.0.0.1:90",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "127.0.0.1",
				Kind:  PatternKindLoopbackIP,
			},
			Port: 90,
		},
	}, {
		name:    "https scheme with IPv6 host",
		input:   "https://[::1]:90",
		failure: true,
	}, {
		name:    "junk in brackets",
		input:   "http://[example]:90",
		failure: true,
	}, {
		name:    "too brackets around IPv6",
		input:   "https://::1:90",
		failure: true,
	}, {
		name:    "missing closing bracket in IPv6",
		input:   "http://[::1:90",
		failure: true,
	}, {
		name:    "missing opening bracket in IPv6",
		input:   "https://::1]:90",
		failure: true,
	}, {
		name:    "IPv6 preceded by junk",
		input:   "https://abc[::1]:90",
		failure: true,
	}, {
		name:    "IPv6 followed by junk",
		input:   "https://[::1]abc:90",
		failure: true,
	}, {
		name:  "non-loopback IPv6 with hexadecimal chars",
		input: "http://[2001:db8:aaaa:1111::100]:9090",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "2001:db8:aaaa:1111::100",
				Kind:  PatternKindNonLoopbackIP,
			},
			Port: 9090,
		},
	}, {
		name:  "loopback IPv6 address with port",
		input: "http://[::1]:90",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "::1",
				Kind:  PatternKindLoopbackIP,
			},
			Port: 90,
		},
	}, {
		name:    "loopback IPv4 in nonstandard form",
		input:   "http://127.1:3999",
		failure: true,
	}, {
		name:    "too many colons in IPv6",
		input:   "http://[::::::::::::::::1]:90",
		failure: true,
	}, {
		name:    "uncompressed IPv6",
		input:   "http://[2001:4860:4860:0000:0000:0000:0000:8888]:90",
		failure: true,
	}, {
		name:    "IPv6 with a zone",
		input:   "http://[fe80::1ff:fe23:4567:890a%eth2]:90",
		failure: true,
	}, {
		name:    "IPv4-mapped IPv6",
		input:   "http://[::ffff:7f7f:7f7f]:90",
		failure: true,
	}, {
		name:    "host contains uppercase letters",
		input:   "http://exAmplE.coM:3999",
		failure: true,
	}, {
		name:  "host contains underscores and hyphens",
		input: "http://ex_am-ple.com:3999",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "ex_am-ple.com",
			},
			Port: 3999,
		},
	}, {
		name:  "trailing full stop in host",
		input: "http://example.com.:3999",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "example.com.",
			},
			Port: 3999,
		},
	}, {
		name:    "multiple trailing full stops in host",
		input:   "http://example.com..:3999",
		failure: true,
	}, {
		name:    "empty label",
		input:   "http://example..com:3999",
		failure: true,
	}, {
		name:    "host contains invalid Punycode label",
		input:   "http://xn--f",
		failure: true,
	}, {
		name:  "arbitrary subdomains of depth one or more",
		input: "http://*.example.com:3999",
		want: Pattern{
			Scheme: "http",
			HostPattern: HostPattern{
				Value: "*.example.com",
				Kind:  PatternKindSubdomains,
			},
			Port: 3999,
		},
	}, {
		name:    "arbitrary subdomains of depth one or more and arbitrary ports",
		input:   "http://*.example.com:*",
		failure: true,
	}, {
		name:    "leading double asterisk",
		input:   "http://**.example.com:3999",
		failure: true,
	}, {
		name:    "out-of-place wildcard",
		input:   "http://fooo.*.example.com:3999",
		failure: true,
	}, {
		name:    "wildcard not followed by a full stop",
		input:   "http://*example.com:3999",
		failure: true,
	}, {
		name:    "wildcard character sequence with IPv6",
		input:   "http://*.[::1]:3999",
		failure: true,
	}, {
		name:    "wildcard character sequence with IPv4",
		input:   "http://*.127.0.0.1:3999",
		failure: true,
	},
}

func TestParseSpec(t *testing.T) {
	for _, c := range parsePatternCases {
		f := func(t *testing.T) {
			o, err := ParsePattern(c.input)
			if err != nil && !c.failure {
				t.Errorf("%q: got %v; want nil error", c.input, err)
				return
			}
			if err == nil && c.failure {
				t.Errorf("%q: got nil error; want non-nil error", c.input)
				return
			}
			if err == nil && o != c.want {
				t.Errorf("%q: got  %+v; want %+v", c.input, o, c.want)
				return
			}
		}
		t.Run(c.name, f)
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
	for _, c := range cases {
		f := func(t *testing.T) {
			spec, err := ParsePattern(c.pattern)
			if err != nil {
				t.Errorf("got %v; want non-nil error", err)
				return
			}
			got := spec.IsDeemedInsecure()
			if got != c.want {
				t.Errorf("got %t; want %t", got, c.want)
			}
		}
		t.Run(c.pattern, f)
	}
}

func TestHostIsEffectiveTLD(t *testing.T) {
	cases := []struct {
		pattern string
		isETLD  bool
		eTLD    string
	}{
		{
			pattern: "https://*.com",
			isETLD:  true,
			eTLD:    "com",
		}, {
			pattern: "https://*.github.io",
			isETLD:  true,
			eTLD:    "github.io",
		}, {
			pattern: "https://*.github.io",
			isETLD:  true,
			eTLD:    "github.io",
		}, {
			pattern: "https://*.example.com",
			isETLD:  false,
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			spec, err := ParsePattern(c.pattern)
			if err != nil {
				t.Errorf("got %v; want non-nil error", err)
				return
			}
			eTLD, isETLD := spec.HostIsEffectiveTLD()
			if eTLD != c.eTLD || isETLD != c.isETLD {
				t.Errorf("got %s, %t; want %s, %t", eTLD, isETLD, c.eTLD, c.isETLD)
			}
		}
		t.Run(c.pattern, f)
	}
}
