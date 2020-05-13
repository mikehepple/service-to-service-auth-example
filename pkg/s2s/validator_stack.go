package s2s

import (
	"errors"
	"fmt"
)

// WithStackValidator mandates that the request stack must exactly match one of the stacks required or
// it will be rejected
func (h HTTPService) WithStackValidator(stack ...Stack) *HTTPService {
	h.validators = append(h.validators, func(chain *AuthChain) error {

		chainStack := chain.Stack()

		for _, inStack := range stack {
			if inStack.Equals(chainStack) {
				return nil
			}
		}

		return errors.New("chain did not match any valid stack: " + chainStack.String())
	})
	return &h
}

// WithRequiredFirstService requires that requests must be initiated from a certain service
func (h HTTPService) WithRequiredFirstServices(identity ...ServiceIdentity) *HTTPService {
	h.validators = append(h.validators, func(chain *AuthChain) error {
		chainStack := chain.Stack()
		if len(chainStack) == 0 {
			return errors.New("chain must start with one of the specified identities but this request has no auth chain")
		}
		for _, serviceIdentity := range identity {
			if chainStack[0] == serviceIdentity.Name() {
				return nil
			}
		}
		return fmt.Errorf("chain must start with one of the specified identities and this request starts with %s", chainStack[0])
	})
	return &h
}
