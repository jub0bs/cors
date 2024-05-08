# jub0bs/cors

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

This package allows you to configure and build [net/http][net-http] middleware
that implement CORS.

## Installation

```shell
go get github.com/jub0bs/cors
```

jub0bs/cors requires Go 1.22 or above.

## Example

The following program demonstrates how to create a CORS middleware that

- allows anonymous access from [Web origin][web-origin] `https://example.com`,
- with requests whose method is either `GET` or `POST`, and
- (optionally) with request header `Authorization`,

and how to apply the middleware in question to all the resources accessible
under some `/api/` path:

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
  api.HandleFunc("GET /users", handleUsersGet)
  api.HandleFunc("POST /users", handleUsersPost)
  mux.Handle("/api/", http.StripPrefix("/api", corsMw.Wrap(api))) // note: method-less pattern here

  log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleHello(w http.ResponseWriter, _ *http.Request) {
  io.WriteString(w, "Hello, World!")
}

func handleUsersGet(w http.ResponseWriter, _ *http.Request) {
  // omitted
}

func handleUsersPost(w http.ResponseWriter, _ *http.Request) {
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

## Documentation

The documentation is available on [pkg.go.dev][pkgsite].

Moreover, guidance on how to use jub0bs/cors with popular third-party routers
can be found in [jub0bs/cors-examples][cors-examples].

## Code coverage

![coverage](https://codecov.io/gh/jub0bs/cors/branch/main/graphs/sunburst.svg?token=N208BHWQTM)

## Benchmarks

Some benchmarks pitting jub0bs/cors against [rs/cors][rs-cors]
are available in [jub0bs/cors-benchmarks][cors-benchmarks].

## License

All source code is covered by the [MIT License][license].

## Additional resources

- [_Fearless CORS: a design philosophy for CORS middleware libraries
(and a Go implementation)_][fearless-cors] (blog post)
- [_jub0bs/cors: a better CORS middleware library for Go_][a-better-cors-lib] (blog post)
- [_Useful Functional-Options Tricks for Better Libraries_
(GopherCon Europe 2023)][funcopts] (video)
- [github.com/jub0bs/fcors][fcors] (this library's predecessor)

## Reasons for favoring rs/cors over jub0bs/cors

Despite all of jub0bs/cors's goodness, you may still have valid reasons
for sticking with [rs/cors][rs-cors], at least for the time being.
Here is as exhaustive a list as I could come up with:

- You cannot yet migrate to Go v1.22
  (whose [semantics][go-directive] are assumed by jub0bs/cors).
- You wish to allow [Web origins][web-origin] whose scheme is neither `http`
  nor `https`.
- You need more flexible origin patterns than those supported by jub0bs/cors;
  but do bear in mind that [excessive flexibility in this regard implies
  security risks][dangerous-patterns].
- You want to log a message for every single request processed
  by your CORS middleware; [but do you, really?][logging]

[a-better-cors-lib]: https://jub0bs.com/posts/2024-04-27-jub0bs-cors-a-better-cors-middleware-library-for-go/
[cors-benchmarks]: https://github.com/jub0bs/cors-benchmarks
[cors-examples]: https://github.com/jub0bs/cors-examples
[dangerous-patterns]: https://jub0bs.com/posts/2023-02-08-fearless-cors/#disallow-dangerous-origin-patterns
[fcors]: https://github.com/jub0bs/fcors
[fearless-cors]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[funcopts]: https://www.youtube.com/watch?v=5uM6z7RnReE
[go-directive]: https://go.dev/ref/mod#go-mod-file-go
[golang]: https://go.dev/
[license]: https://github.com/jub0bs/cors/blob/main/LICENSE
[logging]: https://jub0bs.com/posts/2024-04-27-jub0bs-cors-a-better-cors-middleware-library-for-go/#debug-mode
[mdn-cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[mdn-sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[net-http]: https://pkg.go.dev/net/http
[pkgsite]: https://pkg.go.dev/github.com/jub0bs/cors
[rs-cors]: https://github.com/rs/cors
[web-origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
