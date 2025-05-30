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
	// wildcardPort is used as a sentinel value to indicate that all ports are
	// allowed.
	Port int
}

// IsDeemedInsecure reports whether all of the following conditions are
// fulfilled:
//   - p's scheme is not https,
//   - p's host is not a loopback IP address,
//   - p's host is not localhost.
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
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  str,
			Reason: "prohibited",
		}
		return zeroPattern, err
	}
	full := str
	scheme, str, ok := parseScheme(str)
	if !ok {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "invalid",
		}
		return zeroPattern, err
	}
	if scheme == "file" {
		// The origin of requests issued from "file" origins is always "null".
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "prohibited",
		}
		return zeroPattern, err
	}
	str, ok = strings.CutPrefix(str, schemeHostSep)
	if !ok {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "invalid",
		}
		return zeroPattern, err
	}
	hp, str, err := parseHostPattern(str, full)
	if err != nil {
		return zeroPattern, err
	}
	if hp.IsIP() && scheme == schemeHTTPS {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "invalid",
		}
		return zeroPattern, err
	}
	var port int // assume no port
	if len(str) > 0 {
		str, ok = strings.CutPrefix(str, string(hostPortSep))
		if !ok {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroPattern, err
		}
		port, str, ok = parsePortPattern(str)
		if !ok || str != "" {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroPattern, err
		}
		if isDefaultPortForScheme(scheme, port) {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "prohibited",
			}
			return zeroPattern, err
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
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "invalid",
		}
		return zeroHostPattern, str, err
	}
	if pattern.Kind == PatternKindSubdomains {
		// At least two bytes (e.g. "a.") are required for the part
		// corresponding to the wildcard character sequence in a valid origin,
		// hence the subtraction in the following expression.
		if len(host.Value) > maxHostLen-2 {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroHostPattern, str, err
		}
		if host.AssumeIP {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroHostPattern, str, err
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
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroHostPattern, str, err
		}
		if ip.Zone() != "" {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "invalid",
			}
			return zeroHostPattern, str, err
		}
		if ip.Is4In6() {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "prohibited",
			}
			return zeroHostPattern, str, err
		}
		ipStr := ip.String()
		if ipStr != host.Value {
			err := &cfgerrors.UnacceptableOriginPatternError{
				Value:  full,
				Reason: "prohibited",
			}
			return zeroHostPattern, str, err
		}

		if ip.IsLoopback() {
			pattern.Kind = PatternKindLoopbackIP
		} else {
			pattern.Kind = PatternKindNonLoopbackIP
		}
		pattern.Value = ipStr
		return pattern, str, nil
	}
	profileOnce.Do(initProfile)
	_, err := profile.ToASCII(host.Value)
	if err != nil {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Value:  full,
			Reason: "prohibited",
		}
		return zeroHostPattern, str, err
	}
	return pattern, str, nil
}

var zeroHostPattern HostPattern

// IsIP reports whether the host of p is an IP address
// (as opposed to a domain).
func (hp *HostPattern) IsIP() bool {
	return hp.Kind == PatternKindLoopbackIP || hp.Kind == PatternKindNonLoopbackIP
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
// success or failure.
func parsePortPattern(str string) (port int, rest string, ok bool) {
	if rest, ok = strings.CutPrefix(str, portWildcard); ok {
		return wildcardPort, rest, true
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
