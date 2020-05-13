package s2s

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	DefaultJwtHeader = "Authorization"
	DefaultJwtPrefix = "Bearer "
)

type HTTPService struct {
	privateIdentity  PrivateIdentity
	identityProvider IdentityProvider

	header string
	prefix string

	validators []Validator
}

type HTTPOption func(service *HTTPService)

type Validator func(chain *AuthChain) error

func NewService(privateIdentity PrivateIdentity, identityProvider IdentityProvider, options ...HTTPOption) *HTTPService {
	service := &HTTPService{
		privateIdentity:  privateIdentity,
		identityProvider: identityProvider,

		header: DefaultJwtHeader,
		prefix: DefaultJwtPrefix,
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func JWTHeader(header string) HTTPOption {
	return func(service *HTTPService) {
		service.header = header
	}
}

func JWTPrefix(prefix string) HTTPOption {
	return func(service *HTTPService) {
		service.prefix = prefix
	}
}

func Validators(validator ...Validator) HTTPOption {
	return func(service *HTTPService) {
		service.validators = append(service.validators, validator...)
	}
}

func (h HTTPService) Verify(r *http.Request) (*AuthChain, error) {
	if r == nil {
		return nil, errors.New("request was nil")
	}
	tokenHeader := r.Header.Get(h.header)
	if tokenHeader == "" {
		return nil, errors.New(fmt.Sprintf("missing %s header", h.header))
	} else if !strings.HasPrefix(tokenHeader, h.prefix) {
		return nil, errors.New(fmt.Sprintf("missing %s prefix", h.prefix))
	}
	token := strings.TrimSpace(tokenHeader[len(h.prefix):])
	authChain, err := ParseAuthChain(token, h.identityProvider, h.privateIdentity.ServiceIdentity)
	if err != nil {
		return nil, err
	}
	for _, validator := range h.validators {
		validationErr := validator(authChain)
		if validationErr != nil {
			return nil, validationErr
		}
	}
	return authChain, nil
}

type authChainContextKeyType int

const AuthChainContextKey authChainContextKeyType = iota

func (h HTTPService) ServerMiddleware(next http.Handler, errHandler func(w http.ResponseWriter, r *http.Request, err error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authChain, err := h.Verify(r)
		if err != nil {
			if errHandler != nil {
				errHandler(w, r, err)
				return
			} else {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), AuthChainContextKey, authChain)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

type clientMiddleware struct {
	httpService HTTPService
	audience    ServiceIdentity
	next        http.RoundTripper
}

func (c clientMiddleware) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()

	authChain, err := c.httpService.AuthChainFromContext(ctx)

	token, err := c.httpService.privateIdentity.SignAuthClaim(AuthClaims{}, authChain, c.audience)
	if err != nil {
		return nil, errors.New("unable to create s2s token: " + err.Error())
	}
	r.Header.Set(c.httpService.header, fmt.Sprintf("%s%s", c.httpService.prefix, token))

	return c.next.RoundTrip(r)
}

func (h HTTPService) ClientMiddleware(next http.RoundTripper, audience ServiceIdentity) http.RoundTripper {
	return clientMiddleware{
		httpService: h,
		audience:    audience,
		next:        next,
	}
}

func (h HTTPService) AuthChainFromContext(ctx context.Context) (*AuthChain, error) {
	authChain := &AuthChain{}
	if authChainI := ctx.Value(AuthChainContextKey); authChainI != nil {
		var ok bool
		if authChain, ok = authChainI.(*AuthChain); !ok {
			return nil, errors.New(fmt.Sprintf("authChain found in context with unexpected type %T", authChainI))
		}
	}
	return authChain, nil
}
