# jub0bs/cors

[![tag](https://img.shields.io/github/tag/jub0bs/cors.svg)](https://github.com/jub0bs/cors/tags)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.23-%23007d9c)][go1.23]
[![Go Reference](https://pkg.go.dev/badge/github.com/jub0bs/cors.svg)](https://pkg.go.dev/github.com/jub0bs/cors)
[![license](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://github.com/jub0bs/cors/raw/main/LICENSE)
[![build](https://github.com/jub0bs/cors/actions/workflows/cors.yml/badge.svg)](https://github.com/jub0bs/cors/actions/workflows/cors.yml)
[![codecov](https://codecov.io/gh/jub0bs/cors/branch/main/graph/badge.svg?token=N208BHWQTM)](https://app.codecov.io/gh/jub0bs/cors/tree/main)
[![goreport](https://goreportcard.com/badge/jub0bs/cors)](https://goreportcard.com/report/jub0bs/cors)

A principled [CORS][mdn-cors] middleware library for [Go][golang],
designed to be both easier to use and harder to misuse
than existing alternatives.

## About CORS

The [Same-Origin Policy (SOP)][mdn-sop] is a security mechanism that
Web browsers implement to protect their users.
In particular, the SOP places some restrictions on cross-origin network access,
in terms of both sending and reading.

[Cross-Origin Resource Sharing (CORS)][mdn-cors] is a protocol that
lets servers instruct browsers to relax those restrictions for select clients.

## Features

This library allows you to configure and build [net/http][net-http] middleware
that implement CORS. It distinguishes itself from other CORS middleware
libraries by providing the following features:

- [a simple and coherent API][pkgsite-index];
- [thorough documentation][pkgsite];
- [extensive configuration validation][validation];
- [programmatic handling of configuration errors][cfgerrors];
- [safe-by-default middleware behavior][safe];
- [a useful debug mode][debug];
- [on-the-fly, concurrency-safe middleware reconfigurability][reconfigurable];
- [strong performance guarantees][benchmark-results];
- [support for Private-Network Access][pna];
- full compliance with [the Fetch standard][fetch].

Despite all of this library's goodness, you may still have valid reasons
for favoring libraries like the more popular [rs/cors][rs-cors].
Here is as exhaustive a list as I could come up with:

- You need more flexibility than that afforded by the
  [origin patterns supported by this library][origin-patterns];
  but do bear in mind that
  [excessive flexibility in this regard implies security risks][danger].
- You want to log a message for every single request processed
  by your CORS middleware; [but do you, really?][logging]

## Installation

```shell
go get github.com/jub0bs/cors
```

This library requires [Go 1.23][go1.23] or above.

## Example

The following program demonstrates how to create a CORS middleware that

- allows anonymous access from [Web origin][web-origin] `https://example.com`,
- with requests whose method is either `GET` or `POST` (or `HEAD`), and
- (optionally) with request header `Authorization`,

and how to apply the middleware in question to all the resources accessible
under the `/api/` path:

```go
package main

import (
  "io"
  "log"
  "net/http"

  "github.com/jub0bs/cors"
)

func main() {
  mux := http.NewServeMux()
  mux.HandleFunc("GET /hello", handleHello) // note: not configured for CORS

  // create CORS middleware
  corsMw, err := cors.NewMiddleware(cors.Config{
    Origins:        []string{"https://example.com"},
    Methods:        []string{http.MethodGet, http.MethodPost},
    RequestHeaders: []string{"Authorization"},
  })
  if err != nil {
    log.Fatal(err)
  }
  corsMw.SetDebug(true) // turn debug mode on (optional)

  api := http.NewServeMux()
  api.HandleFunc("GET  /users", handleUsersGet)
  api.HandleFunc("POST /users", handleUsersPost)
  mux.Handle("/api/", http.StripPrefix("/api", corsMw.Wrap(api))) // note: method-less pattern here

  if err := http.ListenAndServe(":8080", mux); err != http.ErrServerClosed {
    log.Fatal(err)
  }
}

func handleHello(w http.ResponseWriter, _ *http.Request) {
  io.WriteString(w, "Hello, World!")
}

func handleUsersGet(_ http.ResponseWriter, _ *http.Request) {
  // omitted
}

func handleUsersPost(_ http.ResponseWriter, _ *http.Request) {
  // omitted
}
```

Try it out yourself by saving this program to a file named `server.go`.
You may need to adjust the port number if port 8080 happens to be unavailable
on your machine. Then build and run your server:

```shell
go build server.go
./server
```

If no error occurred, the server is now running on `localhost:8080` and
the various resources accessible under the `/api/` path are now configured
for CORS as desired.

If you need to handle CORS-configuration errors programmatically,
see [package cfgerrors][cfgerrors].

## A note about testing

Be aware that, for performance reasons, CORS middleware produced by this
library closely adheres to guarantees (provided by [the Fetch standard][fetch])
about the format of some CORS headers. In particular, if you wish to write
tests that exercise CORS middleware via CORS-preflight requests that include an
[`Access-Control-Request-Headers` header][acrh], keep in mind that you should
specify the comma-separated elements in that header value

- in lower case,
- in lexicographical order,
- without repetitions.

Otherwise, the CORS middleware will cause preflight to fail.

## Documentation

The documentation is available on [pkg.go.dev][pkgsite].

Moreover, guidance on how to use this library with popular third-party routers
can be found in [jub0bs/cors-examples][cors-examples].

## Code coverage

![coverage](https://codecov.io/gh/jub0bs/cors/branch/main/graphs/sunburst.svg?token=N208BHWQTM)

## Benchmarks

Some benchmarks pitting this library against [rs/cors][rs-cors]
are available in [jub0bs/cors-benchmarks][cors-benchmarks].

## License

All source code is covered by the [MIT License][license].

## Additional resources

- [_Fearless CORS: a design philosophy for CORS middleware libraries
(and a Go implementation)_][fearless-cors] (blog post)
- [_jub0bs/cors: a better CORS middleware library for Go_][a-better-cors-lib] (blog post)
- [_Reconfigurable CORS middleware with jub0bs/cors_][reconfigurable] (blog post)
- [_Useful Functional-Options Tricks for Better Libraries_
(GopherCon Europe 2023)][funcopts] (video)
- [github.com/jub0bs/fcors][fcors] (this library's predecessor)

[a-better-cors-lib]: https://jub0bs.com/posts/2024-04-27-jub0bs-cors-a-better-cors-middleware-library-for-go/
[acrh]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers
[benchmark-results]: https://github.com/jub0bs/cors-benchmarks#results
[cfgerrors]: https://pkg.go.dev/github.com/jub0bs/cors/cfgerrors
[cors-benchmarks]: https://github.com/jub0bs/cors-benchmarks
[cors-examples]: https://github.com/jub0bs/cors-examples
[danger]: https://jub0bs.com/posts/2023-02-08-fearless-cors/#disallow-dangerous-origin-patterns
[debug]: https://jub0bs.com/posts/2024-04-27-jub0bs-cors-a-better-cors-middleware-library-for-go/#debug-mode
[fcors]: https://github.com/jub0bs/fcors
[fearless-cors]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[fetch]: https://fetch.spec.whatwg.org
[funcopts]: https://www.youtube.com/watch?v=5uM6z7RnReE
[go1.23]: https://tip.golang.org/doc/go1.23
[golang]: https://go.dev/
[license]: https://github.com/jub0bs/cors/blob/main/LICENSE
[logging]: https://jub0bs.com/posts/2024-04-27-jub0bs-cors-a-better-cors-middleware-library-for-go/#debug-mode
[mdn-cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[mdn-sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[net-http]: https://pkg.go.dev/net/http
[origin-patterns]: https://pkg.go.dev/github.com/jub0bs/cors#hdr-Origins-Config
[pkgsite-index]: https://pkg.go.dev/github.com/jub0bs/cors#pkg-index
[pkgsite]: https://pkg.go.dev/github.com/jub0bs/cors
[pna]: https://pkg.go.dev/github.com/jub0bs/cors#hdr-PrivateNetworkAccess-ExtraConfig
[reconfigurable]: https://jub0bs.com/posts/2024-05-14-reconfigurable-cors-middleware/
[rs-cors]: https://github.com/rs/cors
[safe]: https://jub0bs.com/posts/2023-02-08-fearless-cors/#10-render-insecure-configurations-impossible
[validation]: https://jub0bs.com/posts/2023-02-08-fearless-cors/#5-validate-configuration-and-fail-fast
[web-origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
