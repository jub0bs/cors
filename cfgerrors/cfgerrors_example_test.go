package cfgerrors_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"

	"github.com/jub0bs/cors"
	"github.com/jub0bs/cors/cfgerrors"
)

// The server below lets tenants configure their own CORS middleware;
// note that it programmatically handles the resulting error (if any)
// in order to inform tenants of their CORS-configuration mistakes
// in a human-friendly way.
func Example() {
	app := TenantApp{id: "jub0bs"}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /configure-cors", app.handleReconfigureCORS)

	api := http.NewServeMux()
	api.HandleFunc("GET /hello", handleHello)
	mux.Handle("/", app.corsMiddleware.Wrap(api))

	if err := http.ListenAndServe(":8080", mux); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

type TenantApp struct {
	id             string
	corsMiddleware cors.Middleware
}

func (app *TenantApp) handleReconfigureCORS(w http.ResponseWriter, r *http.Request) {
	mediatype, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediatype != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var reqData struct {
		Origins          []string `json:"origins"`
		Credentials      bool     `json:"credentials"`
		Methods          []string `json:"methods"`
		RequestHeaders   []string `json:"request_headers"`
		MaxAge           int      `json:"max_age"`
		ResponseHeaders  []string `json:"response_headers"`
		TolerateInsecure bool     `json:"tolerate_insecure"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cfg := cors.Config{
		Origins:         reqData.Origins,
		Credentialed:    reqData.Credentials,
		Methods:         reqData.Methods,
		RequestHeaders:  reqData.RequestHeaders,
		MaxAgeInSeconds: reqData.MaxAge,
		ResponseHeaders: reqData.ResponseHeaders,
		ExtraConfig: cors.ExtraConfig{
			DangerouslyTolerateSubdomainsOfPublicSuffixes: reqData.TolerateInsecure,
			DangerouslyTolerateInsecureOrigins:            reqData.TolerateInsecure,
		},
	}

	if err := app.corsMiddleware.Reconfigure(&cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		var resData = struct {
			Errors []string `json:"errors"`
		}{
			Errors: adaptCORSConfigErrorMessagesForClient(err),
		}
		if err := json.NewEncoder(w).Encode(resData); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func adaptCORSConfigErrorMessagesForClient(err error) []string {
	// Modify the following logic to suit your needs.
	var msgs []string
	for err := range cfgerrors.All(err) {
		switch err := err.(type) {
		case *cfgerrors.UnacceptableOriginPatternError:
			var msg string
			switch err.Reason {
			case "missing":
				msg = "You must allow at least one Web origin."
			case "invalid":
				msg = fmt.Sprintf("%q is not a valid Web origin.", err.Value)
			case "prohibited":
				msg = fmt.Sprintf("For security reasons, you cannot allow Web origin %q.", err.Value)
			default:
				panic("unknown reason")
			}
			msgs = append(msgs, msg)
		case *cfgerrors.UnacceptableMethodError:
			var msg string
			switch err.Reason {
			case "invalid":
				msg = fmt.Sprintf("%q is not a valid HTTP-method name.", err.Value)
			case "forbidden":
				msg = fmt.Sprintf("No browser-based client can send a %s request.", err.Value)
			default:
				panic("unknown reason")
			}
			msgs = append(msgs, msg)
		case *cfgerrors.UnacceptableHeaderNameError:
			var msg string
			switch err.Reason {
			case "invalid":
				const tmpl = "%q is not a valid %s-header name."
				msg = fmt.Sprintf(tmpl, err.Value, err.Type)
			case "prohibited":
				const tmpl = "You cannot allow %q as a %s-header name."
				msg = fmt.Sprintf(tmpl, err.Value, err.Type)
			case "forbidden":
				switch err.Type {
				case "request":
					const tmpl = "No browser-based client can include a header named %q in a request."
					msg = fmt.Sprintf(tmpl, err.Value)
				case "response":
					const tmpl = "No browser-based client can read a header named %q from a response."
					msg = fmt.Sprintf(tmpl, err.Value)
				default:
					panic("unknown message type")
				}
			default:
				panic("unknown reason")
			}
			msgs = append(msgs, msg)
		case *cfgerrors.MaxAgeOutOfBoundsError:
			const tmpl = "Your max-age value, %d, is either negative or too high (max: %d). Alternatively, you can specify %d to disable caching."
			msg := fmt.Sprintf(tmpl, err.Value, err.Max, err.Disable)
			msgs = append(msgs, msg)
		case *cfgerrors.IncompatibleOriginPatternError:
			var msg string
			switch err.Reason {
			case "credentialed":
				if err.Value == "*" {
					msg = "For security reasons, you cannot both allow credentialed access and allow all Web origins."
				} else {
					const tmpl = "For security reasons, you cannot both allow credentialed access allow insecure origins like %q."
					msg = fmt.Sprintf(tmpl, err.Value)
				}
			case "psl":
				const tmpl = "For security reasons, you cannot specify %q as an origin pattern, because it covers all subdomains of a registrable domain."
				msg = fmt.Sprintf(tmpl, err.Value)
			default:
				panic("unknown reason")
			}
			msgs = append(msgs, msg)
		case *cfgerrors.IncompatibleWildcardResponseHeaderNameError:
			msg := "You cannot expose all response headers when credentialed access is allowed."
			msgs = append(msgs, msg)
		default:
			panic("unknown configuration issue")
		}
	}
	return msgs
}

func handleHello(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, "Hello, World!")
}
