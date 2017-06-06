/*
 * Minio Cloud Storage, (C) 2016, 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"
)

const (
	jwtAlgorithm = "Bearer "

	// Default JWT token for web handlers is one day.
	defaultJWTExpiry = 24 * time.Hour

	// Inter-node JWT token expiry is 100 years approx.
	defaultInterNodeJWTExpiry = 100 * 365 * 24 * time.Hour
)

var (
	errInvalidAccessKeyID   = errors.New("The access key ID you provided does not exist in our records")
	errChangeCredNotAllowed = errors.New("Changing access key and secret key not allowed")
	errAuthentication       = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken          = errors.New("JWT token missing")
)

func getURL(u *url.URL) string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

func authenticateJWT(accessKey, secretKey string, expiry time.Duration) (string, error) {
	passedCredential, err := createCredential(accessKey, secretKey)
	if err != nil {
		return "", err
	}

	serverCred := globalServerCreds.GetCredential(accessKey)
	if serverCred.IsExpired() {
		return "", errInvalidAccessKeyID
	}
	if serverCred.AccessKey != passedCredential.AccessKey {
		return "", errInvalidAccessKeyID
	}

	if !serverCred.Equal(passedCredential) {
		return "", errAuthentication
	}

	utcNow := UTCNow()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.MapClaims{
		"exp": utcNow.Add(expiry).Unix(),
		"iat": utcNow.Unix(),
		"sub": accessKey,
	})

	tokenStr, err := token.SignedString([]byte(serverCred.SecretKey))
	if err != nil {
		return "", err
	}

	canonicalAuth := func(accessKey, token string) string {
		return fmt.Sprintf("%s:%s", accessKey, token)
	}

	return canonicalAuth(accessKey, tokenStr), nil
}

func authenticateNode(accessKey, secretKey string) (string, error) {
	return authenticateJWT(accessKey, secretKey, defaultInterNodeJWTExpiry)
}

func authenticateWeb(accessKey, secretKey string) (token string, err error) {
	return authenticateJWT(accessKey, secretKey, defaultJWTExpiry)
}

func isAuthTokenValid(tokenStr string) bool {
	token, err := parseJWT(tokenStr)
	if err != nil {
		errorIf(err, "Unable to parse JWT token string")
		return false
	}
	return token.Valid
}

func isHTTPTokenValid(auth string) bool {
	return isAuthTokenValid(auth)
}

func isHTTPRequestValid(req *http.Request) bool {
	return webRequestAuthenticate(req) == nil
}

func extractAccessAndJWT(tok string) (accessKey string, jwtToken string) {
	toks := strings.SplitN(strings.TrimPrefix(tok, jwtAlgorithm), ":", 2)
	if len(toks) == 1 {
		return "", tok
	}
	return toks[0], toks[1]
}

// Extract and parse a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
func parseFromRequest(req *http.Request) (token *jwtgo.Token, err error) {
	auth := req.Header.Get("Authorization")
	return parseJWT(auth)
}

func parseJWT(auth string) (token *jwtgo.Token, err error) {
	accessKey, tokenStr := extractAccessAndJWT(auth)
	if tokenStr == "" {
		return nil, jwtreq.ErrNoTokenInRequest
	}
	return jwtgo.ParseWithClaims(tokenStr, jwtgo.MapClaims{}, func(jwtToken *jwtgo.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
		}
		if accessKey != "" {
			cred := globalServerCreds.GetCredential(accessKey)
			if cred.IsExpired() {
				return nil, errInvalidAccessKeyID
			}
			if cred.AccessKey != accessKey {
				return nil, errInvalidAccessKeyID
			}
			return []byte(cred.SecretKey), nil
		}
		return []byte(serverConfig.GetCredential().SecretKey), nil
	})
}

// Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns errAuthentication for all other errors.
func webRequestAuthenticate(req *http.Request) error {
	jwtToken, err := parseFromRequest(req)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return errNoAuthToken
		}
		return errAuthentication
	}

	if !jwtToken.Valid {
		return errAuthentication
	}
	return nil
}
