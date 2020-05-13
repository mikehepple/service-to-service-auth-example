package s2s

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
)

type AuthClaims struct {
	jwt.StandardClaims
	NextToken *string `json:"next,omitempty"`
}

type AttachmentClaims struct {
	jwt.StandardClaims
	Object json.RawMessage `json:"obj"`
}
