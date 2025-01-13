package cors_test

import (
	"io"
	"log"
	"net/http"

	"github.com/jub0bs/cors"
)

func ExampleMiddleware_Wrap() {
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
