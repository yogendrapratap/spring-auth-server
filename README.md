# Spring Auth Server

A minimal Spring Authorization Server (OAuth2/OIDC) example built with Spring Authorization Server.

This repository contains a simple authorization server based on Spring Authorization Server and Spring Boot. 
It exposes OAuth2 and OpenID Connect endpoints and includes an in-memory RegisteredClient repository and an RSA JWK source for signing tokens.

Contents
- Overview
- Prerequisites
- Build & Run
- Configuration
- Important endpoints
- Common flows & examples
  - Client Credentials (machine-to-machine)
  - Authorization Code + OIDC (interactive user)
- Troubleshooting (including `invalid_scope`)
- Notes

Overview

This project demonstrates how to run a self-contained authorization server that supports OAuth2 (client_credentials, authorization_code, refresh_token) 
and OpenID Connect (basic OIDC via the authorization_code flow). The server registers clients in-memory and generates a temporary RSA key pair 
at startup for token signing.

Prerequisites

- Java 17+ installed (the project POM targets Java 17; newer JDKs are usually compatible)
- Maven (or use the included `mvnw` wrapper)
- (Optional) MySQL running if you want to use the configured datasource in `application.properties`. The project currently points to a MySQL datasource but uses only in-memory RegisteredClient and JWK.

Build & Run

From the project root you can build and run the application using Maven:

```bash
# Build the JAR (skip tests to speed up)
mvn -DskipTests package

# Run the packaged JAR
java -jar target/spring-auth-server-0.0.1-SNAPSHOT.jar

# Or run with the Maven Spring Boot plugin
mvn spring-boot:run

# Or using the wrapper (macOS / Linux)
./mvnw spring-boot:run
```

By default the server listens on port 9000 (see `src/main/resources/application.properties`).

Configuration

The key configuration points are:

- `src/main/resources/application.properties` — basic properties (server.port, datasource). You can override these with environment variables or a different profile.
- `com.spring.springauthserver.config.ProjectSecurityConfig` — security configuration, registered clients, JWK source and authorization server settings.

Important endpoints

- OpenID Provider Metadata (well-known):
  - GET http://localhost:9000/.well-known/openid-configuration
- Authorization endpoint (OIDC/OAuth2 interactive flows):
  - GET http://localhost:9000/oauth2/authorize
- Token endpoint:
  - POST http://localhost:9000/oauth2/token
- JSON Web Key Set (JWKs):
  - GET http://localhost:9000/oauth2/jwks
- Login page (default Spring form login):
  - GET http://localhost:9000/login

Common flows & examples

1) Client Credentials (machine-to-machine)

This flow is used by server-to-server clients (no user). The client must be registered with `AuthorizationGrantType.CLIENT_CREDENTIALS` and must request only scopes configured for it (do NOT request `openid` with client_credentials).

Example token request (replace CLIENT_ID and CLIENT_SECRET):

```bash
curl -u eazybankapi:CrCip4kQwpiDQhK9NLJmFlADNjtwLyNw \
  -X POST "http://localhost:9000/oauth2/token" \
  -d 'grant_type=client_credentials&scope=ADMIN'
```

If successful, the response contains an access token. Note: the client in this repository is named `eazybankapi` (client credentials) and has scopes like `ADMIN`, `USER`, `read`, `write`.

2) Authorization Code + OIDC (interactive user)

This flow is used for OpenID Connect (requires a client registered with the `openid` scope and the `authorization_code` grant).

Example authorization request (redirects to login if not authenticated):

GET http://localhost:9000/oauth2/authorize?response_type=code&client_id=eazybank-oidc-client&redirect_uri=http://localhost:8080/login/oauth2/code/eazybank&scope=openid%20profile

After user logs in and consents, the authorization code will be returned to the redirect URI. Exchange the code for tokens at `/oauth2/token`.

Troubleshooting

Problem: "invalid_scope"

- Cause: The token request includes a scope that the requested RegisteredClient is not configured to allow. A common mistake is requesting the `openid` scope while using the `client_credentials` grant. `openid` is an OIDC scope and must only be requested by clients registered for OIDC (typically using `authorization_code` with user interaction).

- Fixes:
  - For machine-to-machine requests (client_credentials), request only scopes that the client has been registered for (for example `ADMIN`, `USER`, `read`, `write`). Do NOT include `openid` in client_credentials requests.
  - If you need OIDC (id_token), register an authorization_code client that includes `OidcScopes.OPENID` and use the authorization code flow.

Example that causes invalid_scope (do NOT do this with client_credentials):

```text
POST /oauth2/token
grant_type=client_credentials&scope=openid
```

Instead, for client_credentials request a non-openid scope:

```bash
curl -u eazybankapi:CrCip4kQwpiDQhK9NLJmFlADNjtwLyNw \
  -X POST "http://localhost:9000/oauth2/token" \
  -d 'grant_type=client_credentials&scope=ADMIN'
```

Other tips
- Enable TRACE/DEBUG logging for Spring Security in `application.properties` (this project already sets `logging.level.org.springframework.security=TRACE`) to see detailed filter chain processing.
- If you get `403` or `Access Denied` on well-known or token endpoints, ensure the `ProjectSecurityConfig` registers an authorization server security filter chain with a higher order (the config in this project uses @Order(1) for the authorization server chain and @Order(2) for the default chain).
- To test endpoints quickly without a real persistence setup, you can keep the in-memory RegisteredClient (no DB needed). If using the configured MySQL datasource, ensure the database is accessible and credentials in `application.properties` are correct.

Security notes

- Client secrets in this example are stored in code for demonstration. Do not store production secrets in source control. Use a secure secret store (HashiCorp Vault, AWS Secrets Manager, environment variables, etc.) in production.
- The JWK in this project is generated at runtime and is ephemeral. For production, use a stable signing key set (e.g., load a PEM/keystore or use an HSM).

Contributing

Feel free to open issues or PRs to improve the sample. If you add persistent storage for clients or keys, update the README with setup instructions.

License

This example is provided as-is for learning purposes. No explicit license is set in this repository.
