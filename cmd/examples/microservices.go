package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/phayes/freeport"
	"io/ioutil"
	"net/http"
	"os"
	"service-to-service-auth-example/pkg/s2s"
	"time"
)

func main() {

	// Create identities + keys

	const (
		edge   = "edge.local"
		bff    = "bff.local"
		domain = "domain.local"
	)

	edgePrivateIdentity, edgePublicIdentity, bffPrivateIdentity, bffPublicIdentity,
		domainPrivateIdentity, domainPublicIdentity, publicIdentities := createIdentities(edge, bff, domain)

	// Find some free ports

	edgePort, bffPort, domainPort := getFreePorts()
	fmt.Printf("edge: http://127.0.0.1:%d, bff: http://127.0.0.1:%d, domain: http://127.0.0.1:%d\n", edgePort, bffPort, domainPort)

	// Create clients

	// edge -> bff
	edgeToBffClient := createClient(edgePrivateIdentity, publicIdentities, &bffPublicIdentity)
	// bff -> domain
	bffToDomainClient := createClient(bffPrivateIdentity, publicIdentities, &domainPublicIdentity)

	// Create servers

	requestForwarder := func(client http.Client, port int, path string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
			req, err := http.NewRequestWithContext(r.Context(), "GET", url, nil)
			handleErr(err)
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if resp != nil {
				body, err := ioutil.ReadAll(resp.Body)
				handleErr(err)
				w.Write(body)
			}
		})
	}

	edgeMux := http.NewServeMux()
	edgeMux.Handle("/bff", requestForwarder(edgeToBffClient, bffPort, "/"))
	edgeMux.Handle("/domain", requestForwarder(edgeToBffClient, domainPort, "/"))

	bffMux := http.NewServeMux()
	bffMux.Handle("/", requestForwarder(bffToDomainClient, domainPort, "/"))

	domainMux := http.NewServeMux()
	domainMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	}))

	// edge does not require s2s auth, it does user auth (not in this example)
	createServer(edgePrivateIdentity, false, publicIdentities, edgeMux, edgePort, nil)

	// bff - only accepts calls which originate at the edge
	createServer(bffPrivateIdentity, true, publicIdentities, bffMux, bffPort, func(service *s2s.HTTPService) *s2s.HTTPService {
		return service.WithRequiredFirstServices(edgePublicIdentity)
	})

	createServer(domainPrivateIdentity, true, publicIdentities, domainMux, domainPort, nil)

	userClient := http.Client{}

	edgeRequest := func(path string) {
		url := fmt.Sprintf("http://127.0.0.1:%d/%s", edgePort, path)
		resp, err := userClient.Get(url)
		handleErr(err)

		respBody, err := ioutil.ReadAll(resp.Body)
		handleErr(err)
		fmt.Printf("URL: %s, Resp: %s, Status: %d\n", url, string(respBody), resp.StatusCode)
	}

	fmt.Println()
	fmt.Println("--- Valid Request ---")
	edgeRequest("bff")

	fmt.Println()
	fmt.Println("--- SSRF Attack ---")
	edgeRequest("domain")

	fmt.Println()
	fmt.Println("--- Insider Attack ---")
	insiderClient := createClient(domainPrivateIdentity, publicIdentities, &bffPublicIdentity)
	url := fmt.Sprintf("http://127.0.0.1:%d/", bffPort)
	resp, err := insiderClient.Get(url)
	handleErr(err)
	respBody, err := ioutil.ReadAll(resp.Body)
	handleErr(err)
	fmt.Printf("URL: %s, Resp: %s, Status: %d\n", url, string(respBody), resp.StatusCode)

	os.Exit(0)

	//done := make(chan os.Signal, 1)
	//signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	//<-done

}

func getFreePorts() (int, int, int) {
	edgePort, err := freeport.GetFreePort()
	handleErr(err)
	bffPort, err := freeport.GetFreePort()
	handleErr(err)
	domainPort, err := freeport.GetFreePort()
	handleErr(err)
	return edgePort, bffPort, domainPort
}

func createIdentities(edge string, bff string, domain string) (*s2s.PrivateIdentity, s2s.ServiceIdentity, *s2s.PrivateIdentity, s2s.ServiceIdentity, *s2s.PrivateIdentity, s2s.ServiceIdentity, s2s.ServiceIdentities) {
	edgePrivateIdentity := createIdentity(edge)
	edgePublicIdentity := edgePrivateIdentity.ServiceIdentity
	bffPrivateIdentity := createIdentity(bff)
	bffPublicIdentity := bffPrivateIdentity.ServiceIdentity
	domainPrivateIdentity := createIdentity(domain)
	domainPublicIdentity := domainPrivateIdentity.ServiceIdentity

	publicIdentities := s2s.ServiceIdentities{
		edgePublicIdentity, bffPublicIdentity, domainPublicIdentity,
	}
	return edgePrivateIdentity, edgePublicIdentity, bffPrivateIdentity, bffPublicIdentity, domainPrivateIdentity, domainPublicIdentity, publicIdentities
}

func createIdentity(name string) *s2s.PrivateIdentity {
	priv, pub := generateKey()
	return s2s.NewPrivateIdentity(name, pub, priv)
}

func createServer(serverIdentity *s2s.PrivateIdentity, requireAuth bool,
	idp s2s.IdentityProvider, handler http.Handler, port int, callback func(service *s2s.HTTPService) *s2s.HTTPService) {

	s2sService := s2s.NewService(*serverIdentity, idp)
	if callback != nil {
		s2sService = callback(s2sService)
	}

	if requireAuth {
		handler = s2sService.ServerMiddleware(handler, func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Printf("Request to %s failed auth due to %s\n", serverIdentity.ServiceIdentity.Name(), err)
		})
	}

	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authChain, err := s2sService.Verify(r)
		var authChainStr string
		if err != nil {
			authChainStr = "Error: " + err.Error()
		} else {
			authChainStr = authChain.Stack().String()
			fmt.Println(authChain.Token().Raw)
		}
		fmt.Println(fmt.Sprintf("RCVD - Server: %s Method: %s Path: %s, AuthChain: %s",
			serverIdentity.Name(), r.Method, r.URL.Path, authChainStr))

		handler.ServeHTTP(w, r)
	})

	go func() {
		s := &http.Server{
			Addr:         fmt.Sprintf("127.0.0.1:%d", port),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			Handler:      loggingHandler,
		}
		_ = s.ListenAndServe()
	}()
}

func createClient(identity *s2s.PrivateIdentity, idp s2s.IdentityProvider, audience *s2s.ServiceIdentity) http.Client {
	defaultTransport := http.DefaultTransport

	s2sService := s2s.NewService(*identity, idp)

	return http.Client{
		Transport: s2sService.ClientMiddleware(defaultTransport, *audience),
		Timeout:   30 * time.Second,
	}

}

func generateKey() (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	handleErr(err)
	return key, &key.PublicKey
}

func handleErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
