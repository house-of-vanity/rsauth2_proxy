# rsauth2-proxy

Auth proxy for [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) with Keycloak OIDC. Single instance protects all services in a Kubernetes cluster. Replaces oauth2-proxy.

## How it works

```
Browser → Traefik → ForwardAuth (/auth) → rsauth2-proxy
                                              ├── no session       → 302 to Keycloak login
                                              ├── valid session    → 200 + user headers
                                              └── expired session  → token refresh → 302 back
```

Traefik calls `/auth` for every request to a protected service. The proxy checks the encrypted session cookie, verifies group membership against the route config, and returns 200 (allow), 403 (deny), or 302 (login required).

Sessions are stored entirely in an AES-256-GCM encrypted cookie. No server-side state. Any number of replicas work without coordination.

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_PROXY_OIDC_ISSUER` | yes | | OIDC issuer URL |
| `AUTH_PROXY_CLIENT_ID` | yes | | Keycloak client ID |
| `AUTH_PROXY_CLIENT_SECRET` | yes | | Keycloak client secret |
| `AUTH_PROXY_COOKIE_SECRET` | yes | | AES-256 key, 32 bytes, base64-encoded |
| `AUTH_PROXY_COOKIE_DOMAIN` | yes | | Cookie domain (e.g. `.example.com`) |
| `AUTH_PROXY_CALLBACK_URL` | yes | | Full callback URL (e.g. `https://auth.example.com/callback`) |
| `AUTH_PROXY_LISTEN` | no | `0.0.0.0:8080` | Listen address |
| `AUTH_PROXY_ROUTES_FILE` | no | `/config/routes.yaml` | Path to routes config |
| `AUTH_PROXY_LOG_LEVEL` | no | `info` | Log level (`debug`, `info`, `warn`, `error`) |

Generate a cookie secret:

```sh
openssl rand -base64 32
```

## Routes file

Defines which hosts are protected and which groups have access.

```yaml
routes:
  grafana.example.com:
    allowed_groups: ["admins", "developers"]

  wiki.example.com:
    allowed_groups: []
    # Empty list = any authenticated user

  secret.example.com:
    allowed_groups: ["admins"]
```

Rules:
- Host in routes, `allowed_groups` empty — any authenticated user is allowed
- Host in routes, `allowed_groups` set — user must be in at least one listed group
- Host not in routes — denied (403)

The file is polled every 5 seconds and reloaded on change. This works reliably with Kubernetes ConfigMap volume mounts.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /auth` | ForwardAuth endpoint (called by Traefik) |
| `GET /callback` | OIDC callback (receives authorization code from Keycloak) |
| `GET /refresh` | Token refresh (transparent redirect when session expires) |
| `GET /sign_out` | Logout (clears cookie, redirects to Keycloak end_session) |
| `GET /health` | Health check (returns 200) |

## Keycloak setup

The proxy reads user groups from the `groups` claim in the ID token. Keycloak does not include this by default. Add a group membership mapper to the client:

```hcl
resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id   = keycloak_realm.main.id
  client_id  = keycloak_openid_client.auth_proxy.id
  name       = "groups"
  claim_name = "groups"
  full_path  = false
}
```

Or manually: Client Scopes → your client → Mappers → Add mapper → "Group Membership", claim name `groups`, full path off.

## Kubernetes deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-proxy
  namespace: auth-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: auth-proxy
  template:
    metadata:
      labels:
        app: auth-proxy
    spec:
      containers:
        - name: auth-proxy
          image: ultradesu/rsauth2-proxy:0.1.0
          ports:
            - containerPort: 8080
          envFrom:
            - secretRef:
                name: auth-proxy-creds
          volumeMounts:
            - name: routes
              mountPath: /config
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
      volumes:
        - name: routes
          configMap:
            name: auth-proxy-routes
---
apiVersion: v1
kind: Service
metadata:
  name: auth-proxy
  namespace: auth-proxy
spec:
  selector:
    app: auth-proxy
  ports:
    - port: 80
      targetPort: 8080
```

### Traefik ForwardAuth middleware

Create in each namespace that has protected services:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: auth-proxy
spec:
  forwardAuth:
    address: http://auth-proxy.auth-proxy.svc:80/auth
    trustForwardHeader: true
    authResponseHeaders:
      - X-Auth-Request-User
      - X-Auth-Request-Email
      - X-Auth-Request-Groups
```

### Ingress for auth-proxy itself

The `/callback`, `/refresh`, and `/sign_out` endpoints must be reachable by browsers:

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: auth-proxy
  namespace: auth-proxy
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`auth.example.com`) && (Path(`/callback`) || Path(`/refresh`) || Path(`/sign_out`))
      kind: Rule
      services:
        - name: auth-proxy
          port: 80
  tls:
    secretName: auth-proxy-tls
```

## Building

```sh
cargo build --release
```

### Docker

```sh
docker build -t rsauth2-proxy .
```

## Security properties

- **Encrypted cookies** — AES-256-GCM, not just signed. Cookie contents cannot be read or tampered with without the key.
- **PKCE (S256)** — protects the authorization code exchange against interception.
- **Stateless PKCE** — the PKCE verifier is encrypted inside the `state` parameter. No server-side storage needed.
- **No open redirect** — the redirect URL after login is encrypted in `state`, not taken from user input.
- **Deny by default** — any host not listed in routes gets 403.
- **JWT validation** — ID tokens are verified against Keycloak's JWKS (keys refreshed hourly).
- **Cookie flags** — `HttpOnly`, `Secure`, `SameSite=Lax`.

## Response headers

On successful authentication, the following headers are set on the request forwarded to the upstream service:

| Header | Value |
|---|---|
| `X-Auth-Request-User` | `preferred_username` from the ID token |
| `X-Auth-Request-Email` | `email` from the ID token |
| `X-Auth-Request-Groups` | Comma-separated list of groups |

## License

WTFPL
