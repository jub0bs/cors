package origins

import (
	"net/netip"
	"strings"

	"github.com/jub0bs/cors/internal/origins/radix"
	"github.com/jub0bs/cors/internal/util"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	portHTTP    = 80
	portHTTPS   = 443
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

const (
	// marks one or more period-separated arbitrary DNS labels
	subdomainWildcard = "*"
	// marks an arbitrary (possibly implicit) port number
	portWildcard = "*"
	// sentinel value indicating that arbitrary port numbers are allowed
	anyPort int = radix.WildcardElem
)

// PatternKind represents the kind of a host pattern.
type PatternKind uint8

const (
	PatternKindDomain        PatternKind = iota // domain
	PatternKindNonLoopbackIP                    // non-loopback IP address
	PatternKindLoopbackIP                       // loopback IP address
	PatternKindSubdomains                       // arbitrary subdomains
)

// A Pattern represents an origin pattern.
type Pattern struct {
	// Scheme is the origin pattern's scheme.
	Scheme string
	// Scheme is the origin pattern's host pattern.
	HostPattern
	// Port is the origin pattern's port number (if any).
	// 0 is used as a sentinel value marking the absence of an explicit port.
	// -1 is used as a sentinel value to indicate that all ports are allowed.
	Port int
}

// IsDeemedInsecure returns true if any of the following conditions is
// fulfilled:
//   - p's scheme is not https,
//   - p's host is not a loopback IP address,
//   - p's host is not localhost.
//
// Otherwise, IsDeemedInsecure returns false.
func (p *Pattern) IsDeemedInsecure() bool {
	return p.Scheme != schemeHTTPS &&
		p.Kind != PatternKindLoopbackIP &&
		p.hostOnly() != "localhost"
}

// HostIsEffectiveTLD, if the host of p is an effective top-level domain
// (eTLD), also known as [public suffix],
// returns the eTLD in question and true.
// Otherwise, HostIsEffectiveTLD returns the empty string and false.
//
// [public suffix]: https://publicsuffix.org/list/
func (p *Pattern) HostIsEffectiveTLD() (string, bool) {
	host := p.HostPattern.hostOnly()
	// For cases like of a Web origin that ends with a full stop,
	// we need to trim the latter for this check.
	host = strings.TrimSuffix(host, string(labelSep))
	// We ignore the second (boolean) result because
	// it's false for some listed eTLDs (e.g. github.io)
	etld, _ := publicsuffix.PublicSuffix(host)
	if etld == host {
		return host, true
	}
	return "", false
}

// ParsePattern parses str into a [Pattern] structure.
func ParsePattern(str string) (Pattern, error) {
	if str == "*" || str == "null" {
		return zeroPattern, util.Errorf(`prohibited origin pattern %q`, str)
	}
	full := str
	scheme, str, ok := scanHttpScheme(str)
	if !ok {
		return zeroPattern, util.InvalidOriginPatternErr(full)
	}
	str, ok = consume(schemeHostSep, str)
	if !ok {
		return zeroPattern, util.InvalidOriginPatternErr(full)
	}
	hp, str, err := parseHostPattern(str, full)
	if err != nil {
		return zeroPattern, err
	}
	if hp.IsIP() && scheme == schemeHTTPS {
		const tmpl = `scheme "https" is incompatible with an IP address: %q`
		return zeroPattern, util.Errorf(tmpl, full)
	}
	var port int // assume no port
	if len(str) > 0 {
		str, ok = consume(string(hostPortSep), str)
		if !ok {
			return zeroPattern, util.InvalidOriginPatternErr(full)
		}
		port, str, ok = parsePortPattern(str)
		if !ok || str != "" {
			return zeroPattern, util.InvalidOriginPatternErr(full)
		}
		if port == anyPort && hp.Kind == PatternKindSubdomains {
			const tmpl = "specifying both arbitrary subdomains " +
				"and arbitrary ports is prohibited: %q"
			return zeroPattern, util.Errorf(tmpl, full)
		}
		if isDefaultPortForScheme(scheme, port) {
			const tmpl = "default port %d for %q scheme " +
				"needlessly specified: %q"
			return zeroPattern, util.Errorf(tmpl, port, scheme, full)
		}
	}
	p := Pattern{
		HostPattern: hp,
		Scheme:      scheme,
		Port:        port,
	}
	return p, nil
}

var zeroPattern Pattern

// A HostPattern represents a host pattern.
type HostPattern struct {
	Value string      // Value is the host pattern's raw value.
	Kind  PatternKind // Kind is the host pattern's kind.
}

// parseHostPattern parses a raw host pattern into an [HostPattern] structure.
// It returns the parsed host pattern, the unconsumed part of the input string,
// and an error.
func parseHostPattern(str, full string) (HostPattern, string, error) {
	pattern := HostPattern{
		Value: str, // temporary value, to be trimmed later
		Kind:  peekKind(str),
	}
	host, str, ok := fastParseHost(pattern.hostOnly())
	if !ok {
		return zeroHostPattern, str, util.InvalidOriginPatternErr(full)
	}
	if pattern.Kind == PatternKindSubdomains {
		// At least two bytes (e.g. "a.") are required for the part
		// corresponding to the wildcard character sequence in a valid origin,
		// hence the subtraction in the following expression.
		if len(host.Value) > maxHostLen-2 {
			return zeroHostPattern, str, util.InvalidOriginPatternErr(full)
		}
		if host.AssumeIP {
			return zeroHostPattern, str, util.InvalidOriginPatternErr(full)
		}
	}
	// trim accordingly
	end := len(host.Value)
	if pattern.Kind == PatternKindSubdomains {
		end += len(subdomainWildcard) + 1 // 1 for label separator
	}
	pattern.Value = pattern.Value[:end]
	if host.AssumeIP {
		ip, err := netip.ParseAddr(host.Value)
		if err != nil {
			return zeroHostPattern, str, util.InvalidOriginPatternErr(full)
		}
		if ip.Zone() != "" {
			return zeroHostPattern, str, util.InvalidOriginPatternErr(full)
		}
		if ip.Is4In6() {
			const tmpl = "prohibited IPv4-mapped IPv6 address: %q"
			return zeroHostPattern, str, util.Errorf(tmpl, full)
		}
		var ipStr = ip.String()
		if ipStr != host.Value {
			const tmpl = "IP address in uncompressed form: %q"
			return zeroHostPattern, str, util.Errorf(tmpl, full)
		}

		if ip.IsLoopback() {
			pattern.Kind = PatternKindLoopbackIP
		} else {
			pattern.Kind = PatternKindNonLoopbackIP
		}
		pattern.Value = ipStr
		return pattern, str, nil
	}
	_, err := profile.ToASCII(host.Value)
	if err != nil {
		const tmpl = "host not in ASCII form: %q"
		return zeroHostPattern, str, util.Errorf(tmpl, full)
	}
	return pattern, str, nil
}

var zeroHostPattern HostPattern

// IsIP reports whether the host of p is an IP address
// (as opposed to a domain).
func (hp *HostPattern) IsIP() bool {
	return hp.Kind == PatternKindLoopbackIP || hp.Kind == PatternKindNonLoopbackIP
}

var profile = idna.New(
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// hostOnly returns strictly the host part of the pattern,
// without any leading wildcard character sequence.
func (hp *HostPattern) hostOnly() string {
	if hp.Kind == PatternKindSubdomains {
		// *.example[.]com => example[.]com
		return hp.Value[len(subdomainWildcard)+1:]
	}
	return hp.Value
}

// parsePortPattern parses a port pattern. It returns the port number,
// the unconsumed part of the input string, and a bool that indicates
// success of failure.
func parsePortPattern(str string) (port int, rest string, ok bool) {
	if rest, ok = consume(portWildcard, str); ok {
		return anyPort, rest, true
	}
	return parsePort(str)
}

// isDefaultPortForScheme returns true for the following combinations
//
//   - https, 443
//   - http, 80
//
// and false otherwise.
func isDefaultPortForScheme(scheme string, port int) bool {
	return port == portHTTP && scheme == schemeHTTP ||
		port == portHTTPS && scheme == schemeHTTPS
}

// peekKind checks for the presence of a wildcard character sequence
// in s and returns the associated pattern kind.
// In the absence of any wildcard character sequence, it defaults to
// [PatternKindDomain].
func peekKind(str string) PatternKind {
	const wildcardSeq = subdomainWildcard + string(labelSep)
	if strings.HasPrefix(str, wildcardSeq) {
		return PatternKindSubdomains
	}
	return PatternKindDomain
}
