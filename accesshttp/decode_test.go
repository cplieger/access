package accesshttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

func decodeBody[T any](t *testing.T, contentType, body string) (T, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return decodeJSON[T](httptest.NewRecorder(), r)
}

func TestDecodeStrict(t *testing.T) {
	refused := []struct {
		name, contentType, body, reason string
	}{
		{"no_content_type", "", `{"username":"a","password":"p"}`, "content_type"},
		{"other_content_type", "text/plain", `{"username":"a","password":"p"}`, "content_type"},
		{"empty_body", "application/json", ``, "malformed_json"},
		{"malformed", "application/json", `{"username":`, "malformed_json"},
		{"unknown_field", "application/json", `{"username":"a","password":"p","admin":true}`, "unknown_field"},
		{"case_variant_name", "application/json", `{"USERNAME":"a","password":"p"}`, "unknown_field"},
		{"trailing_data", "application/json", `{"username":"a","password":"p"} {}`, "trailing_data"},
		{"missing_required", "application/json", `{"password":"p"}`, "username"},
		{"type_mismatch", "application/json", `{"username":7,"password":"p"}`, "username"},
		{"not_an_object", "application/json", `[1]`, "body"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeBody[LoginRequest](t, tc.contentType, tc.body)
			if refusedKey(err) != tc.reason {
				t.Errorf("decode %q = %v, want auth_bad_request %q", tc.body, err, tc.reason)
			}
		})
	}
	t.Run("charset_parameter", func(t *testing.T) {
		got, err := decodeBody[LoginRequest](t, "application/json; charset=utf-8", `{"username":"a","password":"p"}`)
		if err != nil || got != (LoginRequest{Username: "a", Password: "p"}) {
			t.Errorf("decode = %+v, %v", got, err)
		}
	})
	t.Run("over_4_KiB", func(t *testing.T) {
		_, err := decodeBody[LoginRequest](t, "application/json", `{"username":"`+strings.Repeat("a", 4096)+`","password":"p"}`)
		if _, ok := errors.AsType[*http.MaxBytesError](err); !ok {
			t.Errorf("decode = %v, want *http.MaxBytesError", err)
		}
	})
	t.Run("secret_field_absent_is_empty", func(t *testing.T) {
		got, err := decodeBody[PasswordRemoveRequest](t, "application/json", `{}`)
		if err != nil || got.CurrentPassword != "" {
			t.Errorf("decode = %+v, %v; want an empty current_password", got, err)
		}
	})
	t.Run("password_as_number", func(t *testing.T) {
		const literal = "123456789012345"
		var body strings.Builder
		e := newEnv(t, envOptions{writer: func(e *env) ErrorWriter {
			return func(w http.ResponseWriter, _ *http.Request, er Error) {
				e.errs.add(er)
				w.WriteHeader(er.Status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": string(er.Code), "detail": er.Detail, "reason": er.Reason, "err": er.Err.Error()})
			}
		}})
		e.createUser(t, "alice", access.RoleUser)
		rt := e.route(t, "authLoginPassword")
		w := do(rt, request(rt, `{"username":"alice","password":`+literal+`}`))
		body.WriteString(w.Body.String())
		errs := e.errs.all()
		if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Code != CodeBadRequest || errs[0].Reason != "password" {
			t.Fatalf("status %d errors %+v, want 400 auth_bad_request naming password", w.Code, errs)
		}
		for _, rec := range e.logs.Records("") {
			body.WriteString(rec.Message)
			rec.Attrs(func(a slog.Attr) bool { body.WriteString(a.String()); return true })
		}
		for _, ev := range e.audits.all() {
			fmt.Fprintf(&body, "%+v", ev)
		}
		if strings.Contains(body.String(), literal) {
			t.Errorf("the response, the logs or an audit event holds the mistyped password: %s", body.String())
		}
	})
}

func TestPathValuesSession(t *testing.T) {
	const valid = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	for _, tc := range []struct {
		name, id, want string // want is the stored session ID, "" for a refusal naming id
	}{
		{"lowercase_hex_at_the_length", valid, valid},
		{"non_hex_at_the_length", strings.Repeat("z", 32), ""},
		{"uppercase_hex_at_the_length", strings.Repeat("AB", 16), ""},
		{"hex_one_short", valid[1:], ""},
		{"hex_one_long", valid + "0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "/", nil)
			r.SetPathValue("id", tc.id)
			var c call
			err := pathValues(&routeSpec{pathID: pathSession}, r, &c)
			re, refused := errors.AsType[*requestError](err)
			if c.sessionID != tc.want || refused != (tc.want == "") || (refused && re.reason != "id") || (!refused && err != nil) {
				t.Errorf("pathValues(%q) = %v with session %q, want session %q (a bad request naming id when empty)", tc.id, err, c.sessionID, tc.want)
			}
		})
	}
}
