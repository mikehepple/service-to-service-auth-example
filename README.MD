# Motivation

This repository contains a very rough proof of concept for a micro-service authentication pattern
which goes beyond the usual intra-service authentication to allow additional controls. The
approach intends to address the following threat scenarios:

![Auth Chain Motivation Diagram](/docs/img/Auth Chain Motivation Diagram.png)

TA1) A [Server Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf) exists in your edge allowing an 
attacker to make arbitrary calls to internal services

TA2) An attacker has bypassed your perimeter and has access to some authentication mechanisms to allow them to make
arbitrary calls to internal services

Under traditional service-to-service authentication, as long as the calling service is authenticated to the called 
service the request will be processed.

# Mechanisms

This example uses RSA-signed JWT, but the principle could be applied to other authentication protocols. The main change is that
the calling service asserts not only their own identity, but also the identity of all previous services that have 
processed this request.

Each service will have a private key and will be aware of the public key for all other services. 

The HTTP request will contain a single JWT which will be signed by the private key of the calling service. The calling
service may also include the token that was sent by the previous service as a linked list.

![Token Wrapping](/docs/img/Token Wrapping.png)

The following snippet shows the contents of an example token (minus signatures and encoding)

```json
{
  "aud":"domain.local",
  "iss":"api-service.local",
  "next": {
    "aud":"api-service.local",
    "iss":"api-gateway.local"
  }
}
```

In this case the request originated at the `api-gateway` and is currently being requested by `api-service` to `domain`.

Each token will also have an `aud` (audience) property, meaning that an HTTP client configured to make calls to `API Service` 
could not be used to make calls to `Domain Service`

HTTP services can declare rules on what authentication chains they will accept. For example, a domain service may specify
that they will only accept requests which originate at the API gateway. It could even define an exact path
that requests must take to be accepted.

# Example code

To see a working example of this concept, see [cmd/examples/microservices.go](cmd/examples/microservices.go) which uses
the service layout described above and attempts the two documented attacks. 
