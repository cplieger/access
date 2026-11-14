package gate_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/gate"
)

func ExampleNew() {
	authn, err := access.New(accesstest.NewMemStore(), access.Config{})
	if err != nil {
		log.Fatal(err)
	}
	writeError := func(w http.ResponseWriter, _ *http.Request, e access.Error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.Status)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": string(e.Code)})
	}
	g, err := gate.New(gate.Config{Authenticator: authn, Errors: writeError},
		[]gate.Route{{Name: "me", Method: http.MethodGet, Path: "/api/me", Class: gate.Session}},
		map[string]http.Handler{"me": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := gate.Principal(r.Context())
			_ = json.NewEncoder(w).Encode(map[string]string{"user": p.User.Username})
		})})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", g)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	fmt.Println(w.Code, w.Header().Get("WWW-Authenticate"), w.Body.String())
	// Output: 401 Bearer realm="access" {"code":"auth_required"}
}
