package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"

	"golang.org/x/net/context"
	pubsub "google.golang.org/api/pubsub/v1"
)

type contextKey string

const (
	contextEventKey contextKey = "jwtToken"
	debugHeader                = false
)

type pushRequest struct {
	Message      pubsub.PubsubMessage `json:"message"`
	Subscription string               `json:"subscription"`
}

var (
	allowedIssuer   = flag.String("allowedIssuer", "https://cloud.google.com/iap", "Isssuer to allow")
	allowedAudience = flag.String("allowedAudience", "/projects/453921602732/apps/iap-test-311821", "Audience to allow")
	jwksURL         = flag.String("jwksURL", "https://www.gstatic.com/iap/verify/public_key-jwk", "JWK URL")

	jwtSet   *jwk.Set
	httpport = flag.String("httpport", ":8080", "httpport")
)

type gcpIdentityDoc struct {
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.StandardClaims
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		//fmt.Printf("     Found OIDC KeyID  " + keyID)
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyGoogleIDToken(ctx context.Context, rawToken string) (gcpIdentityDoc, error) {
	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)
	if err != nil {
		fmt.Errorf("     Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}
	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		fmt.Errorf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", claims.Audience, claims.StandardClaims.Issuer, claims.Email)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}
func authMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if debugHeader {
			requestDump, err := httputil.DumpRequest(r, true)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Printf(string(requestDump))
		}
		authHeader := r.Header.Get("X-Goog-Iap-Jwt-Assertion")

		if authHeader == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		idDoc, err := verifyGoogleIDToken(r.Context(), authHeader)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if idDoc.Audience != *allowedAudience {
			http.Error(w, "Audience value not allowed", http.StatusUnauthorized)
			return
		}

		if idDoc.Issuer != *allowedIssuer {
			http.Error(w, "Issuer value not allowed", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextEventKey, idDoc)
		h.ServeHTTP(w, r.WithContext(ctx))
		return

	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("jwtToken")).(gcpIdentityDoc)
	jsonResponse, err := json.Marshal(val)
	if err != nil {
		http.Error(w, "Could not encode JWT", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)

	// fmt.Fprint(w, fmt.Sprintf("%v ok", val))
}

func posthandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("jwtToken")).(gcpIdentityDoc)

	var pr pushRequest
	if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
		http.Error(w, fmt.Sprintf("Could not decode body: %v", err), http.StatusBadRequest)
		return
	}

	var jsonData []byte
	jsonData, err := json.Marshal(val)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not decode body: %v", err), http.StatusBadRequest)
		return
	}

	var jsonRequest []byte
	jsonRequest, err = json.Marshal(pr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not decode jsonRequest: %v", err), http.StatusBadRequest)
		return
	}

	fmt.Println(string(jsonData))
	fmt.Println(string(jsonRequest))
	fmt.Fprint(w, "ok")
}

func main() {

	var err error
	jwtSet, err = jwk.FetchHTTP(*jwksURL)
	if err != nil {
		fmt.Printf("Unable to load JWK Set: %v", err)
		return
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)
	router.Methods(http.MethodPost).Path("/").HandlerFunc(posthandler)
	var server *http.Server
	server = &http.Server{
		Addr:    ":8080",
		Handler: authMiddleware(router),
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServe()
	fmt.Printf("Unable to start Server %v", err)

}
