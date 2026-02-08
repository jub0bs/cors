package origins

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/jub0bs/cors/cfgerrors"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	schemeHostSep = "://" // scheme-host separator
	hostPortSep   = ':'   // host-port separator
	labelSep      = '.'   // DNS-label separator

	subdomainWildcard = "*" // marks one or more period-separated DNS labels
	wildcardSeq       = subdomainWildcard + string(labelSep)
	portWildcard      = "*" // marks an arbitrary (possibly implicit) port number
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
	maxHostPortLen = maxHostLen + len(string(hostPortSep)) + maxPortLen
	// maxOriginLen is the maximum length of an origin.
	maxOriginLen = maxSchemeLen + len(schemeHostSep) + maxHostPortLen
	// maxPatternLen is the maximum length of an origin pattern.
	// It is simply equal to maxOriginLen because *. is a placeholder for at
	// least two bytes (e.g. "a.").
	maxPatternLen = maxOriginLen
)

// Kind represents the kind of a host pattern.
type Kind uint8

const (
	Domain              Kind = iota // exact domain
	ArbitrarySubdomains             // arbitrary subdomains of a domain
	NonLoopbackIP                   // non-loopback IP address
	LoopbackIP                      // loopback IP address
)

// A Pattern represents an origin pattern.
// The zero value does not correspond to a valid pattern.
type Pattern struct {
	// Scheme is the scheme of this origin pattern.
	Scheme string
	// HostPattern is the host pattern of this origin pattern.
	HostPattern string
	// Port is the positive port number (if any) of this origin pattern.
	// The zero value marks the absence of an explicit port.
	// -1 is used as a sentinel value to indicate that all ports are allowed.
	Port int
	// Kind is the kind of this origin pattern's host pattern.
	Kind Kind
}

// ParsePattern parses str into a fully valid [Pattern] structure.
// If it fails, it returns a non-nil error and some invalid pattern.
// Note that origin pattern "*" is handled elsewhere.
func ParsePattern(str string) (p Pattern, err error) {
	// Using [url.Parse] to parse str is tempting, but the impedance
	// mismatch between that function's behavior and our needs is too great;
	// not only does this function allocates too much for our taste, but it
	// is in some ways too permissive and in other ways too strict.
	// Relying on manual scanning and parsing and on [net/netip]
	// and [golang.org/x/net] packages seems like a good alternative.

	// As a defensive measure against maliciously long origin patterns,
	// let's first check the length of str.
	if len(str) > maxPatternLen {
		err = invalidOriginPatternError(str)
		return
	}
	if str == "null" {
		err = prohibitedOriginPatternError(str)
		return
	}
	var (
		rest string
		ok   bool
	)
	p.Scheme, rest, ok = parseScheme(str)
	if !ok {
		err = invalidOriginPatternError(str)
		return
	}
	rest, ok = strings.CutPrefix(rest, schemeHostSep)
	if !ok {
		err = invalidOriginPatternError(str)
		return
	}
	p.HostPattern, p.Kind, rest, err = parseHostPattern(rest, str)
	if err != nil {
		return
	}
	// Note that we tolerate origin patterns consisting of the https scheme and
	// an IP-address host pattern, in order to cater for RFC 8738.
	if rest != "" {
		rest, ok = strings.CutPrefix(rest, string(hostPortSep))
		if !ok {
			err = invalidOriginPatternError(str)
			return
		}
		p.Port, ok = parsePortPattern(rest)
		if !ok {
			err = invalidOriginPatternError(str)
			return
		}
		if isDefaultPortForScheme(p.Scheme, p.Port) {
			err = prohibitedOriginPatternError(str)
			return
		}
	}
	return p, nil
}

func prohibitedOriginPatternError(pattern string) error {
	return &cfgerrors.UnacceptableOriginPatternError{
		Value:  pattern,
		Reason: "prohibited",
	}
}

func invalidOriginPatternError(pattern string) error {
	return &cfgerrors.UnacceptableOriginPatternError{
		Value:  pattern,
		Reason: "invalid",
	}
}

// parseScheme parses a URI scheme. If successful, it returns the scheme,
// the unconsumed part of str, and true; otherwise, its ok result is false.
func parseScheme(str string) (scheme, rest string, ok bool) {
	// See https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1.

	if str == "" || !isLowerAlpha(str[0]) {
		return
	}
	end := min(maxSchemeLen, len(str))
	i := 1
	for ; i < end; i++ {
		if !isSubsequentSchemeByte(str[i]) {
			break
		}
	}
	return str[:i], str[i:], scheme != "file"
}

// isLowerAlpha reports whether c is in the 0x61-0x7A ASCII range.
func isLowerAlpha(c byte) bool {
	return 'a' <= c && c <= 'z'
}

// isSubsequentSchemeByte reports whether c a valid byte at index >= 1 in a scheme.
func isSubsequentSchemeByte(c byte) bool {
	// See https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1.
	const mask = 0 |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		(1<<10-1)<<'0' |
		(1<<26-1)<<'a' |
		1<<'_'
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// parseHostPattern scans and validates a host pattern in str.
// If it succeeds, it returns the host pattern, its kind, the unconsumed part
// of str, and nil; otherwise, its err result is some non-nil error.
func parseHostPattern(str, rawOriginPattern string) (hostPattern string, kind Kind, rest string, err error) {
	var assumeIP, wildcardSubs bool
	if str != "" && str[0] == '[' { // str must be an IPv6 address.
		var ok bool
		hostPattern, rest, ok = strings.Cut(str[1:], "]")
		if !ok { // unmatched left bracket
			err = invalidOriginPatternError(rawOriginPattern)
			return
		}
		assumeIP = true
	} else { // str must be either an IPv4 address or a domain pattern.
		hostPattern, rest, wildcardSubs = scanHostPattern(str)
		if wildcardSubs {
			kind = ArbitrarySubdomains
		}
		// If the last non-empty label starts with a digit,
		// assume an IPv4 address, since no TLD starts with a digit
		// (see https://www.iana.org/domains/root/db).
		var ok bool
		assumeIP, ok = firstByteOfRightmostLabelIsDigit(hostPattern)
		if !ok || assumeIP && wildcardSubs {
			err = invalidOriginPatternError(rawOriginPattern)
			return
		}
	}
	if assumeIP { // hostPattern must be an IPv4 or IPv6 address.
		var ip netip.Addr
		ip, err = netip.ParseAddr(hostPattern)
		if err != nil || ip.Zone() != "" {
			err = invalidOriginPatternError(rawOriginPattern)
			return
		}
		if ip.Is4In6() || hostPattern != ip.String() {
			err = prohibitedOriginPatternError(rawOriginPattern)
			return
		}
		if ip.IsLoopback() {
			kind = LoopbackIP
		} else {
			kind = NonLoopbackIP
		}
		return hostPattern, kind, rest, nil
	}
	// hostPattern must be a domain pattern.
	host, wildcardSubs := strings.CutPrefix(hostPattern, wildcardSeq)
	if wildcardSubs && len(host) > maxHostLen-len(wildcardSeq) {
		err = invalidOriginPatternError(rawOriginPattern)
		return
	}
	profileOnce.Do(initProfile)
	if _, err = profile.ToASCII(host); err != nil {
		err = prohibitedOriginPatternError(rawOriginPattern)
		return
	}
	return hostPattern, kind, rest, nil
}

// scanHostPattern scans a host pattern in str; it does not
// attempt to validate the resulting host pattern.
// It returns the scanned host pattern, the unconsumed part of str, and reports
// whether the host pattern starts with the *. sequence.
func scanHostPattern(str string) (hostPattern, rest string, wildcardSubs bool) {
	var start, i int
	// Skip over "*." if needed.
	if wildcardSubs = strings.HasPrefix(str, wildcardSeq); wildcardSubs {
		start += len(wildcardSeq)
	}
	for i = start; i < len(str) && isDomainByte(str[i]); i++ {
		// deliberately empty
	}
	return str[:i], str[i:], wildcardSubs
}

// isDomainByte reports whether c is an ASCII lowercase letter, an ASCII digit,
// a hyphen (0x2D), a period (0x2E), or an underscore (0x5F).
func isDomainByte(c byte) bool {
	const mask = 0 |
		1<<'-' |
		1<<labelSep |
		(1<<10-1)<<'0' |
		(1<<26-1)<<'a' |
		1<<'_' // see https://stackoverflow.com/q/2180465
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// firstByteOfRightmostLabelIsDigit reports whether the first byte of the
// rightmost DNS label in hostPattern is a digit.
// If it succeeds, it returns the result of that check and true;
// otherwise, its ok result returns false.
func firstByteOfRightmostLabelIsDigit(hostPattern string) (_ bool, ok bool) {
	rest, label, _ := lastCutByte(hostPattern, labelSep)
	if label != "" {
		return isDigit(label[0]), true
	}
	// hostPattern contains a trailing period ("absolute" domain).
	_, label, _ = lastCutByte(rest, labelSep)
	if label != "" {
		return isDigit(label[0]), true
	}
	return
}

// isDigit reports whether c is in the 0x30-0x39 ASCII range.
func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// lastCutByte slices s around the last instance of sep, returning the text
// before and after sep. The found result reports whether sep appears in s.
// If sep does not appear in s, lastCutByte returns "", s, false.
func lastCutByte(s string, sep byte) (before, after string, found bool) {
	if i := strings.LastIndexByte(s, sep); i >= 0 {
		after = s[i+1:] // eliminate one bounds check below
		return s[:i], after, true
	}
	return "", s, false
}

var (
	profileOnce sync.Once     // guards init of profile via initProfile
	profile     *idna.Profile // lazily initialized
)

func initProfile() {
	profile = idna.New(
		idna.BidiRule(),
		idna.ValidateLabels(true),
		idna.StrictDomainName(true),
		idna.VerifyDNSLength(true),
	)
}

// parsePortPattern parses a port pattern.
// It it succeeds, it returns the port number and true;
// otherwise, it returns 0 and false.
func parsePortPattern(str string) (int, bool) {
	if str == portWildcard {
		return arbitraryPort, true
	}
	return parsePort(str)
}

const (
	absentPort = 0
	// arbitraryPort is a sentinel value that subsumes all other port numbers.
	// arbitraryPort is, by design (see patternCmp's doc comment), less than
	// all of the other valid Pattern.Port values.
	arbitraryPort = -1
)

// isDefaultPortForScheme returns true for the following combinations
//   - (https, 443)
//   - (http, 80)
//
// and false otherwise.
func isDefaultPortForScheme(scheme string, port int) bool {
	const (
		portHTTP   = 80
		schemeHTTP = "http"
		portHTTPS  = 443
	)
	return port == portHTTP && scheme == schemeHTTP ||
		port == portHTTPS && scheme == schemeHTTPS
}

const schemeHTTPS = "https"

// IsDeemedInsecure reports whether all of the following conditions are
// fulfilled:
//   - p's scheme is not https,
//   - p's host is not a loopback IP address,
//   - p's host is not localhost.
//
// Note: protocols using a scheme other than https may well encrypt traffic,
// but let's be conservative here.
func (p *Pattern) IsDeemedInsecure() bool {
	return p.Scheme != schemeHTTPS &&
		p.Kind != LoopbackIP &&
		strings.TrimPrefix(p.HostPattern, wildcardSeq) != "localhost"
}

// HostIsEffectiveTLD reports whether p's host is an effective top-level
// domain (eTLD), also known as [public suffix].
//
// [public suffix]: https://publicsuffix.org/list/
func (p *Pattern) HostIsEffectiveTLD() bool {
	host := strings.TrimPrefix(p.HostPattern, wildcardSeq)
	// For cases like of a Web origin that ends with a full stop,
	// we need to trim the latter for this check.
	host = strings.TrimSuffix(host, string(labelSep))
	// We ignore the second (boolean) result because
	// it's false for some listed eTLDs (e.g. github.io)
	etld, _ := publicsuffix.PublicSuffix(host)
	return etld == host
}
