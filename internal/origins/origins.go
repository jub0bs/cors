package origins

import "strings"

const (
	schemeHostSep = "://"     // scheme-host separator
	hostPortSep   = ':'       // host-port separator
	labelSep      = '.'       // DNS-label separator
	maxUint16     = 1<<16 - 1 // maximum value for uint16 type
)

const (
	// maxHostLen is the maximum length of a host, which is dominated by
	// the maximum length of an (absolute) domain name (253);
	// see https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873.
	maxHostLen = 253
	// maxSchemeLen is the maximum tolerated length for schemes.
	// Its value is somewhat arbitrary but chosen so as to cover the great
	// majority of commonly used schemes.
	maxSchemeLen = 64
	// maxPortLen is the maximum length of a port's decimal representation.
	maxPortLen = len("65535")
	// maxHostPortLen is the maximum length of an origin's host-port part.
	maxHostPortLen = maxHostLen + 1 + maxPortLen // 1 for colon character
)

// Origin represents a (tuple) [Web origin].
//
// [Web origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
type Origin struct {
	// Scheme is the origin's scheme.
	Scheme string
	// Host is the origin's host.
	Host
	// Port is the origin's port (if any).
	// The zero value marks the absence of an explicit port.
	Port int
}

var zeroOrigin Origin

// Parse parses str into an [Origin] structure.
// It is lenient insofar as it performs just enough validation for
// [Tree.Contains] to know what to do with the resulting Origin value.
// In particular, the scheme and port of the resulting origin are guaranteed
// to be valid, but its host isn't.
func Parse(str string) (Origin, bool) {
	const maxOriginLen = maxSchemeLen + len(schemeHostSep) + maxHostPortLen
	if len(str) > maxOriginLen {
		return zeroOrigin, false
	}
	scheme, str, ok := parseScheme(str)
	if !ok {
		return zeroOrigin, false
	}
	str, ok = strings.CutPrefix(str, schemeHostSep)
	if !ok {
		return zeroOrigin, false
	}
	host, str, ok := fastParseHost(str)
	if !ok {
		return zeroOrigin, false
	}
	var port int // assume no port at first
	if len(str) > 0 {
		str, ok = strings.CutPrefix(str, string(hostPortSep))
		if !ok {
			return zeroOrigin, false
		}
		port, str, ok = parsePort(str)
		if !ok || str != "" {
			return zeroOrigin, false
		}
	}
	o := Origin{
		Scheme: scheme,
		Host:   host,
		Port:   port,
	}
	return o, true
}

// Host represents a host, whether it be an IP address or a domain.
type Host struct {
	// Value is the origin's raw host.
	Value string
	// AssumeIP indicates whether the origin's host
	// should be treated as an IP address.
	AssumeIP bool
}

var zeroHost Host

// fastParseHost parses a raw host into an [Host] structure.
// It returns the parsed host, the unconsumed part of the input string,
// and a bool that indicates success or failure.
// fastParseHost is lenient insofar as the resulting host is
// not guaranteed to be valid.
func fastParseHost(str string) (Host, string, bool) {
	const (
		minIPv6HostLen = len("[::]")
		maxIPv6HostLen = len("[1111:1111:1111:1111:1111:1111:1111:1111]")
	)
	if len(str) >= minIPv6HostLen && str[0] == '[' { // looks like an IPv6 address
		end := strings.IndexByte(str, ']')
		if end == -1 { // unmatched left bracket
			return zeroHost, str, false
		}
		host := Host{
			Value:    str[1:end],
			AssumeIP: true,
		}
		return host, str[end+1:], true
	}
	// host can neither be empty nor start with a DNS-label separator
	if len(str) == 0 || str[0] == labelSep {
		return zeroHost, str, false
	}
	// host is either an IPv4 or a domain
	var (
		previousByteWasLabelSep bool
		assumeIPv4              bool
		i                       int
	)
	// If the last non-empty label starts with a digit,
	// assume IPv4, since no TLD starts with a digit
	// (see https://www.iana.org/domains/root/db).
	for ; i < len(str); i++ {
		if str[i] == labelSep {
			if previousByteWasLabelSep {
				// "empty" label, which can only occur at the end,
				// in case of an absolute domain name (e.g. "example.com.").
				// see https://www.rfc-editor.org/rfc/rfc1034.html#section-3.1
				return zeroHost, "", false
			}
			previousByteWasLabelSep = true
		} else if isDigit(str[i]) {
			if previousByteWasLabelSep || i == 0 {
				assumeIPv4 = true
			}
			previousByteWasLabelSep = false
		} else if isASCIILabelByte(str[i]) { // but is non-digit byte
			if previousByteWasLabelSep {
				assumeIPv4 = false
			}
			previousByteWasLabelSep = false
		} else {
			break
		}
	}
	host := Host{
		Value:    str[:i],
		AssumeIP: assumeIPv4,
	}
	return host, str[i:], true
}

// parseScheme parses a URI scheme. If successful, it returns the scheme,
// the unconsumed part of str, and true; otherwise, it returns "", "", false.
func parseScheme(str string) (_ string, _ string, _ bool) {
	// See https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1.
	if len(str) == 0 || !isLowerAlpha(str[0]) {
		return
	}
	i := 1
	for end := min(maxSchemeLen, len(str)); i < end && isSubsequentSchemeByte(str[i]); i++ {
		// deliberately empty body
	}
	return str[:i], str[i:], true
}

func isLowerAlpha(b byte) bool {
	// see https://go.googlesource.com/go/+/refs/tags/go1.24.2/src/net/textproto/reader.go#678
	const mask = (1<<26 - 1) << 'a'
	return ((uint64(1)<<b)&(mask&(1<<64-1)) |
		(uint64(1)<<(b-64))&(mask>>64)) != 0
}

func isSubsequentSchemeByte(b byte) bool {
	// see https://go.googlesource.com/go/+/refs/tags/go1.24.2/src/net/textproto/reader.go#678
	const mask = 0 |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		(1<<10-1)<<'0' |
		(1<<26-1)<<'a' |
		1<<'-' |
		1<<'_'
	return ((uint64(1)<<b)&(mask&(1<<64-1)) |
		(uint64(1)<<(b-64))&(mask>>64)) != 0
}

// isASCIILabelByte returns true if b is an (ASCII) lowercase letter, digit,
// hyphen (0x2D), or underscore (0x5F).
func isASCIILabelByte(b byte) bool {
	// see https://go.googlesource.com/go/+/refs/tags/go1.24.2/src/net/textproto/reader.go#678
	const mask = 0 |
		(1<<10-1)<<'0' |
		(1<<26-1)<<'a' |
		1<<'-' |
		1<<'_'
	return ((uint64(1)<<b)&(mask&(1<<64-1)) |
		(uint64(1)<<(b-64))&(mask>>64)) != 0
}

// parsePort parses a port number. It returns the port number, the unconsumed
// part of the input string, and a bool that indicates success or failure.
func parsePort(str string) (int, string, bool) {
	const base = 10
	if len(str) == 0 || !isNonZeroDigit(str[0]) {
		return 0, str, false
	}
	port := intFromDigit(str[0])
	i := 1
	end := min(len(str), maxPortLen)
	_ = str[i:end] // hoist bounds checks out of the loop
	for ; i < end; i++ {
		if !isDigit(str[i]) {
			break
		}
		port = base*port + intFromDigit(str[i])
	}
	if port < 0 || maxUint16 < port {
		return 0, str, false
	}
	return port, str[i:], true
}

// intFromDigit returns the numerical value of ASCII digit b.
// For instance, if b is '9', the result is 9.
func intFromDigit(b byte) int {
	return int(b) - '0'
}

// isDigit returns true if b is in the 0x30-0x39 ASCII range,
// and false otherwise.
func isDigit(b byte) bool {
	// see https://go.googlesource.com/go/+/refs/tags/go1.24.2/src/net/textproto/reader.go#678
	const mask = (1<<10 - 1) << '0'
	return ((uint64(1)<<b)&(mask&(1<<64-1)) |
		(uint64(1)<<(b-64))&(mask>>64)) != 0
}

// isNonZeroDigit returns true if b is in the 0x31-0x39 ASCII range,
// and false otherwise.
func isNonZeroDigit(b byte) bool {
	// see https://go.googlesource.com/go/+/refs/tags/go1.24.2/src/net/textproto/reader.go#678
	const mask = (1<<9 - 1) << '1'
	return ((uint64(1)<<b)&(mask&(1<<64-1)) |
		(uint64(1)<<(b-64))&(mask>>64)) != 0
}
