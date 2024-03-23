package cors_test

import (
	"log"
	"net/http"

	"github.com/jub0bs/cors"
)

// The example below illustrates a common pitfall.
//
// A good rule of thumb for avoiding this pitfall consists in
// registering the result of Wrap,
// not for a method-full pattern (e.g. "GET /api/dogs"),
// but for a "method-less" pattern; see the other example.
func ExampleMiddleware_Wrap_incorrect() {
	corsMw, err := cors.NewMiddleware(cors.Config{
		Origins: []string{"https://example"},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// Because the pattern for which the result of Wrap is registered
	// unduly specifies a method (other than OPTIONS),
	// CORS-preflight requests to /api/dogs cannot reach the CORS middleware.
	// Therefore, CORS preflight will systematically fail
	// and you'll have a bad day...
	mux.Handle("GET /api/dogs", corsMw.Wrap(http.HandlerFunc(handleDogsGet))) // incorrect!
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleDogsGet(w http.ResponseWriter, _ *http.Request) {
	// omitted
}
