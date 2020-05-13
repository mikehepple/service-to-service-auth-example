package s2s

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
)

type ServiceIdentity struct {
	name      string
	publicKey *rsa.PublicKey
}

func (s ServiceIdentity) Name() string {
	return s.name
}

func NewServiceIdentity(name string, publicKey *rsa.PublicKey) *ServiceIdentity {
	return &ServiceIdentity{name: name, publicKey: publicKey}
}

type PrivateIdentity struct {
	ServiceIdentity
	privateKey *rsa.PrivateKey
}

func NewPrivateIdentity(name string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *PrivateIdentity {
	return &PrivateIdentity{ServiceIdentity: *NewServiceIdentity(name, publicKey), privateKey: privateKey}
}

func (p PrivateIdentity) SignAuthClaim(claims AuthClaims, chain *AuthChain, audience ServiceIdentity) (string, error) {
	if claims.NextToken != nil {
		return "", errors.New("claims.NextToken must be nil")
	}
	if claims.Issuer != "" {
		return "", errors.New("claims.iss must be blank")
	}
	if chain != nil && chain.token != nil {
		claims.NextToken = &chain.token.Raw
	}
	if audience.name == "" {
		return "", errors.New("audience.name must not be blank")
	}

	claims.Issuer = p.name
	claims.Audience = audience.name

	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return unsignedToken.SignedString(p.privateKey)

}
