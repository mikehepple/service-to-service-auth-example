package s2s

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
)

type AuthChain struct {
	identity ServiceIdentity
	token    *jwt.Token
	next     *AuthChain
}

func (a AuthChain) Token() *jwt.Token {
	return a.token
}

func ParseAuthChain(tokenString string, identities IdentityProvider, audience ServiceIdentity) (*AuthChain, error) {
	var identity ServiceIdentity
	var claims AuthClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		if serviceName := token.Claims.(*AuthClaims).Issuer; strings.TrimSpace(serviceName) != "" {
			var found bool
			if identity, found = identities.Find(serviceName); !found {
				return nil, errors.New(fmt.Sprintf("unknown service: %s", serviceName))
			}
		} else {
			return nil, errors.New("missing iss claim")
		}

		if tokenAudience := token.Claims.(*AuthClaims).Audience; strings.TrimSpace(tokenAudience) != "" {
			if tokenAudience != audience.name {
				return nil, errors.New(fmt.Sprintf("wrong audience: %s != %s", tokenAudience, audience.name))
			}
		} else {
			return nil, errors.New("missing aud claim")
		}

		return identity.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	chain := AuthChain{
		identity: identity,
		token:    token,
	}

	if nextToken := claims.NextToken; nextToken != nil && strings.TrimSpace(*nextToken) != "" {

		next, err := ParseAuthChain(*nextToken, identities, identity)
		if err != nil {
			return nil, errors.New("unable to verify next token in chain: " + err.Error())
		}
		chain.next = next

	}

	return &chain, nil

}

func (s AuthChain) Stack() Stack {
	stack := Stack{s.identity.name}
	next := s.next
	for {
		if next == nil {
			break
		}
		stack = append(stack, next.identity.name)
		next = next.next
	}
	return stack
}

type Stack []string

func (s Stack) String() string {
	return strings.Join(s, " => ")
}

func (s Stack) Equals(other Stack) bool {
	if len(s) != len(other) {
		return false
	}

	for idx := range s {
		if s[idx] != other[idx] {
			return false
		}
	}

	return true
}

func NewStack(name ...string) Stack {
	return Stack(name)
}
