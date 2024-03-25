/*
Package cors provides [net/http] middleware for
[Cross-Origin Resource Sharing (CORS)].

This package performs extensive configuration validation
in order to prevent you from inadvertently creating
[dysfunctional or insecure CORS middleware].

Even so, care is required for CORS middleware to work as intended.
Be particularly wary of negative interference from other software components
that play a role in processing requests and composing their responses,
including reverse proxies, routers, other middleware in the chain,
and the ultimate handler. Follow the rules listed below:

  - Because [CORS-preflight requests] use [OPTIONS] as their method,
    you [SHOULD NOT] prevent OPTIONS requests from reaching your CORS
    middleware.
    Otherwise, preflight requests will not get properly handled
    and browser-based clients will likely experience CORS-related errors.
    The testable examples associated with the [*Middleware.Wrap] method
    provide more guidance about avoiding such pitfalls when you rely
    on Go 1.22's enhanced routing features.
  - Because [CORS-preflight requests are not authenticated], authentication
    [SHOULD NOT] take place "ahead of" a CORS middleware
    (e.g. in a reverse proxy or in some middleware further up the chain).
    However, a CORS middleware [MAY] wrap an authentication middleware.
  - The [CORS response headers] that are set by this library's middleware
    [MUST NOT] be altered; moreover, additional CORS response headers
    [MUST NOT] be included in responses.
  - The [Vary] headers that are set by this library's middleware [SHOULD NOT]
    be altered; however, additional Vary headers [MAY] be included in
    responses.
  - Multiple CORS middleware [MUST NOT] be stacked.

[CORS response headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#the_http_response_headers
[CORS-preflight requests are not authenticated]: https://fetch.spec.whatwg.org/#cors-protocol-and-credentials
[CORS-preflight requests]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
[Cross-Origin Resource Sharing (CORS)]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[MAY]: https://www.ietf.org/rfc/rfc2119.txt
[MUST NOT]: https://www.ietf.org/rfc/rfc2119.txt
[OPTIONS]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
[SHOULD NOT]: https://www.ietf.org/rfc/rfc2119.txt
[Vary]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
[dysfunctional or insecure CORS middleware]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
*/
package cors
