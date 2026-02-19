package origins

import (
	"math"
	"strings"
)

// Origin represents a (tuple) [Web origin].
//
// [Web origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
type Origin struct {
	Scheme string
	Host   string
	// Port is the positive port number (if any) of this origin.
	// The zero value marks the absence of an explicit port.
	Port int
}

// Parse parses str into an [Origin] structure.
// For performance, Parse does not attempt to fully validate the result;
// instead, Parse only breaks the origin down into its constitutive parts,
// simply so it can be used in calls to [Tree.Contains].
func Parse(str string) (o Origin, ok bool) {
	// As a defensive measure against maliciously long Origin-header values,
	// let's first check the length of str.
	const maxOriginLen = maxSchemeLen + len(schemeHostSep) + maxHostPortLen
	if len(str) > maxOriginLen {
		return
	}
	var rest string
	o.Scheme, rest, ok = strings.Cut(str, schemeHostSep)
	if !ok {
		return
	}
	o.Host, rest, ok = splitHostPort(rest)
	if !ok {
		return
	}
	if rest != "" {
		o.Port, ok = parsePort(rest)
		if !ok {
			return
		}
	}
	return o, true
}

// splitHostPort splits hostPort into a host and a port.
// Its semantics somewhat differ from [net.SplitHostPort]'s,
// but it does perform some sanity checks.
func splitHostPort(hostPort string) (host, rawPort string, ok bool) {
	if hostPort == "" {
		return
	}
	if hostPort[0] == '[' { // assume IPv6, e.g. [::1]:6060
		var rest string
		host, rest, ok = lastCutByte(hostPort[1:], ']')
		if !ok {
			return // missing closing bracket
		}
		if rest != "" {
			rawPort, ok = strings.CutPrefix(rest, string(hostPortSep))
			if !ok {
				return // rest is non-empty but doesn't start by a colon
			}
			if ok = rawPort != ""; !ok {
				return // rest consists in a colon not followed by a port
			}
		}
		return host, rawPort, true
	}
	host, rawPort, found := strings.Cut(hostPort, string(hostPortSep))
	if found && rawPort == "" {
		return // trailing colon not followed by a port
	}
	return host, rawPort, true
}

// parsePort parses a positive port number.
// If it succeeds, it returns the port number and true;
// otherwise, it returns 0 and false.
func parsePort(str string) (int, bool) {
	if len(str) > maxPortLen {
		return 0, false
	}
	var port int
	const base = 10
	for i, c := range []byte(str) {
		if i == 0 && c == '0' || !isDigit(c) {
			return 0, false
		}
		port = base*port + intFromDigit(c)
	}
	if port == 0 || math.MaxUint16 < port {
		return 0, false
	}
	return port, true
}

// intFromDigit returns the numerical value of ASCII digit c.
// For instance, if c is '9', the result is 9.
// Precondition: isDigit(c) is true.
func intFromDigit(c byte) int {
	return int(c) - '0'
}
