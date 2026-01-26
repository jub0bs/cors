package origins

import (
	"math"
	"testing"
)

var parseCases = []struct {
	desc    string
	input   string
	want    Origin
	failure bool
}{
	{
		desc:    "null origin",
		input:   "null",
		failure: true,
	}, {
		desc:  "domain without port",
		input: "https://example.com",
		want: Origin{
			Scheme: "https",
			Host:   "example.com",
		},
	}, {
		desc:  "invalid scheme",
		input: "1ab://example.com",
		want: Origin{
			Scheme: "1ab",
			Host:   "example.com",
		},
	}, {
		desc:    "short input without scheme-host delimiter",
		input:   "ab",
		failure: true,
	}, {
		desc:    "short input with colon but without double slash",
		input:   "ab:",
		failure: true,
	}, {
		desc:    "empty hostport",
		input:   "https://",
		failure: true,
	}, {
		desc:  "non-HTTP scheme",
		input: "connector://localhost",
		want: Origin{
			Scheme: "connector",
			Host:   "localhost",
		},
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[example]:90",
		want: Origin{
			Scheme: "http",
			Host:   "example",
			Port:   90,
		},
	}, {
		desc:    "unmatched left bracket",
		input:   "http://[::1:90",
		failure: true,
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[::1:]",
		want: Origin{
			Scheme: "http",
			Host:   "::1:",
		},
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[::]",
		want: Origin{
			Scheme: "http",
			Host:   "::",
		},
	}, {
		desc:  "valid compressed IPv6",
		input: "http://[::1]:90",
		want: Origin{
			Scheme: "http",
			Host:   "::1",
			Port:   90,
		},
	}, {
		desc:    "valid compressed IPv6 followed by a trailing full stop",
		input:   "http://[::1].:90",
		failure: true,
	}, {
		desc:    "domain with colon but no port",
		input:   "https://example.com:",
		failure: true,
	}, {
		desc:    "IPV6 with colon but no port",
		input:   "http://[::1]:",
		failure: true,
	}, {
		desc:    "domain with 0 port",
		input:   "https://example.com:0",
		failure: true,
	}, {
		desc:  "domain with a leading full stop",
		input: "https://.example.com",
		want: Origin{
			Scheme: "https",
			Host:   ".example.com",
		},
	}, {
		desc:  "domain with illegal char after host",
		input: "https://example.com^8080",
		want: Origin{
			Scheme: "https",
			Host:   "example.com^8080",
		},
	}, {
		desc:  "domain followed by character other than colon",
		input: "https://example.com?",
		want: Origin{
			Scheme: "https",
			Host:   "example.com?",
		},
	}, {
		desc:    "domain with colon but with non-numeric port",
		input:   "https://example.com:abcd",
		failure: true,
	}, {
		desc:    "domain with colon but with non-numeric port starting with digits",
		input:   "https://example.com:123ab",
		failure: true,
	}, {
		desc:  "domain port",
		input: "https://example.com:6060",
		want: Origin{
			Scheme: "https",
			Host:   "example.com",
			Port:   6060,
		},
	}, {
		desc:    "IP host with colon but no port",
		input:   "http://127.0.0.1:",
		failure: true,
	}, {
		desc:    "IP host with 0 port",
		input:   "http://127.0.0.1:0",
		failure: true,
	}, {
		desc:  "ipv4 port",
		input: "http://127.0.0.1:6060",
		want: Origin{
			Scheme: "http",
			Host:   "127.0.0.1",
			Port:   6060,
		},
	}, {
		desc:  "single-digit host",
		input: "http://1:6060",
		want: Origin{
			Scheme: "http",
			Host:   "1",
			Port:   6060,
		},
	}, {
		desc:  "ipv4 with trailing full stop",
		input: "http://127.0.0.1.",
		want: Origin{
			Scheme: "http",
			Host:   "127.0.0.1.",
		},
	}, {
		desc:  "malformed ipv4 with one too many octets",
		input: "http://127.0.0.1.1",
		want: Origin{
			Scheme: "http",
			Host:   "127.0.0.1.1",
		},
	}, {
		desc:  "ipv4 with overflowing octet",
		input: "http://256.0.0.1",
		want: Origin{
			Scheme: "http",
			Host:   "256.0.0.1",
		},
	}, {
		desc:  "ipv4 with trailing full stop and port",
		input: "http://127.0.0.1.:6060",
		want: Origin{
			Scheme: "http",
			Host:   "127.0.0.1.",
			Port:   6060,
		},
	}, {
		desc:  "invalid TLD",
		input: "http://foo.bar.255:6060",
		want: Origin{
			Scheme: "http",
			Host:   "foo.bar.255",
			Port:   6060,
		},
	}, {
		desc:  "longer invalid TLD",
		input: "http://foo.bar.baz.012345678901234567890123456789:6060",
		want: Origin{
			Scheme: "http",
			Host:   "foo.bar.baz.012345678901234567890123456789",
			Port:   6060,
		},
	}, {
		desc:  "valid domain with all-numeric label in the middle",
		input: "http://foo.bar.baz.012345678901234567890123456789.ab:6060",
		want: Origin{
			Scheme: "http",
			Host:   "foo.bar.baz.012345678901234567890123456789.ab",
			Port:   6060,
		},
	}, {
		desc:  "ipv6 with port",
		input: "http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:6060",
		want: Origin{
			Scheme: "http",
			Host:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			Port:   6060,
		},
	}, {
		desc: "deep_subdomain",
		input: "http://foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"example.com:6060",
		failure: true,
	},
}

func TestParse(t *testing.T) {
	for _, c := range parseCases {
		f := func(t *testing.T) {
			t.Parallel()
			o, ok := Parse(c.input)
			if ok == c.failure || ok && o != c.want {
				t.Errorf("%q: got %v, %t; want %v, %t", c.input, o, ok, c.want, !c.failure)
			}
		}
		t.Run(c.desc, f)
	}
}

func BenchmarkParse(b *testing.B) {
	for _, c := range parseCases {
		f := func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				Parse(c.input)
			}
		}
		b.Run(c.desc, f)
	}
}

// If this doesn't compile, maxUint16 doesn't match math.MaxUint16.
var _ = [1]int{}[maxUint16-math.MaxUint16]
