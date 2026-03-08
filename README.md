<p align="center">
  <img src="https://raw.githubusercontent.com/boridon/code-sherpa/main/docs/logo.svg" width="220" alt="CodeSherpa logo">
</p>

<h1 align="center">CodeSherpa</h1>

<p align="center">AI-guided repository exploration over SSH via MCP</p>

---

## What Is CodeSherpa?
CodeSherpa is a remote MCP server that lets AI clients inspect repositories over SSH with a strict read-only toolset.

Supported MCP tools:
- `healthcheck_remote`
- `list_files`
- `read_file`
- `search_code`
- `git_status`
- `git_diff`
- `git_log`

Compatible MCP clients:
- ChatGPT (custom connectors)
- Claude Desktop
- Cursor
- Other MCP-compatible agents

## Quick Start
Clone and start CodeSherpa locally.

```bash
git clone https://github.com/boridon/code-sherpa.git
cd code-sherpa
cp .env.example .env
docker compose up -d
```

Then connect your MCP client to:

```text
https://your-domain.example/mcp
```

## Architecture
```text
MCP Client
    |
    v
CodeSherpa (HTTPS)
    |
    v
SSH (read-only user)
    |
    v
Private repository host
```

Key points:
- Repository data stays on the SSH target host.
- CodeSherpa exposes only read-only MCP tools.
- Path traversal and sensitive path segments are blocked.
- OAuth access tokens and legacy fixed bearer tokens are supported.

## Security Model
- Use a read-only SSH user (no sudo).
- Denied path segments include `.git`, `.env`, `node_modules`, and similar sensitive paths.
- Absolute paths and `..` traversal are rejected.
- `/mcp` requires `mcp:read` scope for OAuth access tokens.
- Legacy fixed bearer token auth can remain enabled for internal testing.

Note: OAuth sessions, authorization codes, and tokens are in-memory in the current implementation. They are reset when the container restarts.

## Docker Deployment
### 1. Clone and prepare
```bash
git clone https://github.com/boridon/code-sherpa.git
cd code-sherpa
cp .env.example .env
mkdir -p secrets
```

### 2. Add SSH secrets
- Put your private key at `secrets/id_ed25519`
- Generate known hosts:

```bash
ssh-keyscan -H <ssh-host> > secrets/known_hosts
chmod 600 secrets/id_ed25519
chmod 644 secrets/known_hosts
```

### 3. Start the service
```bash
docker compose build
docker compose up -d
docker compose ps
curl http://127.0.0.1:8787/health
```

## Cloudflare Tunnel
You can run CodeSherpa with Cloudflare in two ways.

### A. Sidecar container (token mode)
```bash
docker compose -f docker-compose.yml -f docker-compose.cloudflare.yml up -d
```

This mode uses `CLOUDFLARE_TUNNEL_TOKEN` from `.env`.

### B. Config file mode (`cloudflared-config.yml`)
Example ingress:

```yaml
ingress:
  - hostname: code-sherpa.example.com
    service: http://localhost:8787
  - service: http_status:404
```

If `cloudflared` is not installed on your host:
- Debian/Ubuntu: `sudo apt-get install cloudflared`
- RHEL/CentOS/Fedora: `sudo dnf install cloudflared`
- macOS (Homebrew): `brew install cloudflared`

## OAuth for MCP Connectors
CodeSherpa includes a minimal built-in OAuth authorization server for connector setup flows.

OAuth discovery endpoints:
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`

OAuth endpoints:
- `GET /authorize`
- `POST /token`
- `GET /login`
- `POST /login`
- `GET /oauth/consent`
- `POST /oauth/consent`

OAuth profile:
- Grant type: Authorization Code + PKCE (`S256`)
- Scope: `mcp:read`
- Public client support: yes (`token_endpoint_auth_method=none` allowed)
- Refresh token: supported

### ChatGPT Connector Values (Example)
Use example values like these:
- MCP endpoint: `https://code-sherpa.example.com/mcp`
- Issuer: `https://code-sherpa.example.com`
- Authorization endpoint: `https://code-sherpa.example.com/authorize`
- Token endpoint: `https://code-sherpa.example.com/token`
- Scope: `mcp:read`

## Environment Variables
Use `.env.example` as the baseline.

Required:
- `SSH_HOST`
- `SSH_PORT`
- `SSH_USERNAME`
- `REPO_ROOT`
- `MCP_BEARER_TOKEN` (for optional legacy/manual testing)
- `OAUTH_ISSUER_BASE_URL`
- `OAUTH_LOGIN_USERNAME`
- `OAUTH_LOGIN_PASSWORD`
- `OAUTH_SESSION_SECRET`

Optional/common:
- `PORT` (default `8787`)
- `MCP_SERVER_NAME` (default `code-sherpa`)
- `MCP_SERVER_VERSION` (default `0.1.0`)
- `OAUTH_COOKIE_SECURE` (default `true`)
- `MAX_FILE_BYTES`, `MAX_SEARCH_RESULTS`, `MAX_LOG_COMMITS`, `MAX_RESPONSE_CHARS`

Example `.env` snippet (safe placeholders):

```env
PORT=8787
MCP_SERVER_NAME=code-sherpa
SSH_HOST=ssh-host.example.internal
SSH_PORT=22
SSH_USERNAME=repo_reader
REPO_ROOT=/srv/repos/project
OAUTH_ISSUER_BASE_URL=https://code-sherpa.example.com
OAUTH_LOGIN_USERNAME=replace-me
OAUTH_LOGIN_PASSWORD=replace-me
OAUTH_SESSION_SECRET=replace-with-long-random-secret
MCP_BEARER_TOKEN=replace-with-long-random-token
```

## Minimal Verification
### 1. OAuth discovery
```bash
curl -i http://127.0.0.1:8787/.well-known/oauth-authorization-server
curl -i http://127.0.0.1:8787/.well-known/openid-configuration
```

### 2. Legacy bearer test
```bash
curl -i -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer ${MCP_BEARER_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0.0.1"}}}'
```

### 3. OAuth token exchange
After browser login + consent, exchange the authorization code:

```bash
curl -i -X POST http://127.0.0.1:8787/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=<authorization-code>' \
  --data-urlencode 'redirect_uri=<same-redirect-uri-used-at-authorize>' \
  --data-urlencode 'code_verifier=<pkce-code-verifier>' \
  --data-urlencode 'client_id=<client-id>'
```

## Project Structure
```text
code-sherpa
├── src/
│   ├── index.ts
│   ├── oauth.ts
│   ├── pkce.ts
│   ├── session.ts
│   └── token-store.ts
├── docs/
│   └── logo.svg
├── Dockerfile
├── docker-compose.yml
├── docker-compose.cloudflare.yml
├── cloudflared-config.example.yml
├── cloudflared-config.yml
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## License
MIT

## Contributing
Issues and pull requests are welcome.

If CodeSherpa is useful to you, consider giving the repository a star on GitHub.
