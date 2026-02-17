/*
Package cors provides [net/http] middleware for
[Cross-Origin Resource Sharing (CORS)].

This package performs extensive configuration validation
in order to prevent you from inadvertently creating
[dysfunctional or insecure CORS middleware].

Even so, care is required for CORS middleware to work as intended.
Be particularly wary of negative interference from other software components
that play a role in processing requests and composing their responses,
including intermediaries (proxies and gateways), routers, other middleware
in the chain, and the ultimate handler. Follow the rules listed below:

  - Because [CORS-preflight requests] use [OPTIONS] as their method,
    you [SHOULD NOT] prevent OPTIONS requests from reaching your CORS
    middleware.
    Otherwise, preflight requests will not get properly handled
    and browser-based clients will likely experience CORS-related errors.
    The [testable examples] associated with the [*Middleware.Wrap] method
    provide more guidance about avoiding such pitfalls when you rely
    on [net/http]'s enhanced routing features, [available since Go 1.22].
  - Because [CORS-preflight requests are not authenticated], authentication
    [SHOULD NOT] take place "ahead of" a CORS middleware
    (e.g. in a reverse proxy or in some middleware further up the chain).
    However, a CORS middleware [MAY] wrap an authentication middleware.
  - Intermediaries [SHOULD NOT] alter or augment the [CORS request headers]
    that are set by browsers.
    Regarding the value of [list-based field] [Access-Control-Request-Headers]
    specifically, intermediaries [MAY] add some [optional whitespace] around
    the value's elements or add (inadvertently, perhaps) some empty elements
    to that value, but they [SHOULD] do so within reason;
    moreover, intermediaries [MAY] split the value of that field across
    multiple header lines of that name, but they [SHOULD NOT] add too many
    empty header lines of that name.
    For performance (and at the cost of some interoperability),
    this library's middleware are indeed stricter in their handling of
    this specific list-based field than required by [RFC 9110 section 5.6.1.2].
  - Intermediaries [SHOULD NOT] alter or augment the [CORS response headers]
    that are set by this library's middleware.
  - Intermediaries [MAY] alter the value of the [Vary] header that is set by
    this library's middleware, but they [MUST] preserve all of its elements.
  - Intermediaries [SHOULD NOT] be configured to cache responses to preflight
    requests; per [RFC 9110 section 9.3.7], responses to [OPTIONS] requests are
    indeed not meant to be cached. If you choose to configure an intermediary
    to cache such responses anyway, you [MUST] make sure (in order to avoid
    [cache poisoning]) that those responses include a [Vary] header listing
    the relevant [CORS request headers].
  - Multiple CORS middleware [MUST NOT] be stacked.

[Access-Control-Request-Headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers
[CORS request headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#the_http_request_headers
[CORS response headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#the_http_response_headers
[CORS-preflight requests are not authenticated]: https://fetch.spec.whatwg.org/#cors-protocol-and-credentials
[CORS-preflight requests]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
[Cross-Origin Resource Sharing (CORS)]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[MAY]: https://www.ietf.org/rfc/rfc2119.txt
[MUST NOT]: https://www.ietf.org/rfc/rfc2119.txt
[MUST]: https://www.ietf.org/rfc/rfc2119.txt
[OPTIONS]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
[RFC 9110 section 5.6.1.2]: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2
[RFC 9110 section 9.3.7]: https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.7
[SHOULD NOT]: https://www.ietf.org/rfc/rfc2119.txt
[SHOULD]: https://www.ietf.org/rfc/rfc2119.txt
[Vary]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
[available since Go 1.22]: https://go.dev/doc/go1.22#enhanced_routing_patterns
[cache poisoning]: https://portswigger.net/web-security/web-cache-poisoning
[dysfunctional or insecure CORS middleware]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[list-based field]: https://httpwg.org/specs/rfc9110.html#abnf.extension
[optional whitespace]: https://httpwg.org/specs/rfc9110.html#whitespace
[testable examples]: https://pkg.go.dev/github.com/jub0bs/cors#pkg-examples
*/
package cors
