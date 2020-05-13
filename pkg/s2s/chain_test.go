package s2s

import (
	"crypto/rand"
	"crypto/rsa"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestParseAuthChain(t *testing.T) {
	Convey("Given client and 2 servers have private keys and identities", t, func() {
		clientPrivate, clientPublic := generateKey(t)
		server1Private, server1Public := generateKey(t)
		_, server2Public := generateKey(t)

		clientIdentity := ServiceIdentity{
			name:      "client",
			publicKey: clientPublic,
		}

		server1Identity := ServiceIdentity{
			name:      "server1",
			publicKey: server1Public,
		}

		server2Identity := ServiceIdentity{
			name:      "server2",
			publicKey: server2Public,
		}

		identities := ServiceIdentities{clientIdentity, server1Identity, server2Identity}

		Convey("When the client signs the request", func() {
			clientPrivateIdentity := PrivateIdentity{ServiceIdentity: clientIdentity, privateKey: clientPrivate}
			token, err := clientPrivateIdentity.SignAuthClaim(AuthClaims{}, nil, server1Identity)
			So(err, ShouldBeNil)

			Convey("Then the server can verify the caller hierarchy", func() {
				chain, err := ParseAuthChain(token, identities, server1Identity)
				So(err, ShouldBeNil)
				So(chain, ShouldNotBeNil)
				stack := chain.Stack()
				ShouldNotBeEmpty(stack)
				So(stack, ShouldResemble, NewStack(clientIdentity.name))

				Convey("Then server1 can re-sign the request", func() {
					server1PrivateIdentity := PrivateIdentity{ServiceIdentity: server1Identity, privateKey: server1Private}
					token, err := server1PrivateIdentity.SignAuthClaim(AuthClaims{}, chain, server2Identity)
					So(err, ShouldBeNil)

					Convey("Then server2 can verify the caller hierarchy contains client and server1", func() {
						chain, err := ParseAuthChain(token, identities, server2Identity)
						So(err, ShouldBeNil)
						So(chain, ShouldNotBeNil)
						stack := chain.Stack()
						ShouldNotBeEmpty(stack)
						So(stack, ShouldResemble, NewStack(server1Identity.name, clientIdentity.name))
					})
				})

				Convey("Then when a malicious actor tries to masquerade as server1 with an invalid key", func() {
					attackerPrivateKey, _ := generateKey(t)
					attackerIdentity := PrivateIdentity{ServiceIdentity: server1Identity, privateKey: attackerPrivateKey}
					token, err := attackerIdentity.SignAuthClaim(AuthClaims{}, chain, server2Identity)
					So(err, ShouldBeNil)

					Convey("Then server2 cannot verify the authenticity of the request", func() {
						chain, err := ParseAuthChain(token, identities, server2Identity)
						So(err, ShouldNotBeNil)
						So(chain, ShouldBeNil)
					})
				})

				Convey("Then when a malicious actor with client's private key tries to masquerade as server1", func() {
					attackerIdentity := PrivateIdentity{ServiceIdentity: server1Identity, privateKey: clientPrivate}
					token, err := attackerIdentity.SignAuthClaim(AuthClaims{}, chain, server2Identity)
					So(err, ShouldBeNil)

					Convey("Then server2 cannot verify the authenticity of the request", func() {
						chain, err := ParseAuthChain(token, identities, server2Identity)
						So(err, ShouldNotBeNil)
						So(chain, ShouldBeNil)
					})
				})

				Convey("Then when a malicious actor tried to replay a token for server1 to server2", func() {
					Convey("Then server2 cannot verify the authenticitiy of the request", func() {
						chain, err := ParseAuthChain(token, identities, server2Identity)
						So(err, ShouldNotBeNil)
						So(chain, ShouldBeNil)
					})
				})
			})
		})

	})

}

func generateKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, &key.PublicKey
}
