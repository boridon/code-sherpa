<p align="center">
  <img src="https://raw.githubusercontent.com/boridon/code-sherpa/main/docs/logo.svg" width="220" alt="CodeSherpa logo">
</p>

<h1 align="center">CodeSherpa</h1>

<p align="center">AI-guided repository exploration over SSH via MCP</p>

---

## What Is CodeSherpa?
CodeSherpa is a remote MCP server that lets AI clients explore and optionally modify repositories over SSH. Multiple repositories can be served from a single instance.

Supported MCP tools:

| Tool | Description | Scope |
|------|-------------|-------|
| `list_repos` | List available repositories | read |
| `healthcheck_remote` | Check SSH connectivity and repo health | read |
| `list_files` | List files/directories with deny-path filtering | read |
| `read_file` | Read file contents with size limit | read |
| `search_code` | Recursive text search (grep) | read |
| `search_files` | File name pattern search (glob) | read |
| `get_symbols` | Extract function/class/type declarations | read |
| `git_status` | Git status | read |
| `git_diff` | Git diff with optional range/path | read |
| `git_log` | Git commit log | read |
| `git_blame` | Per-line commit information | read |
| `write_file` | Create or overwrite a file (atomic) | write |
| `delete_file` | Delete a file | write |
| `patch_file` | Search-and-replace in a file | write |

Write tools are only available when the OAuth token includes the `mcp:write` scope.

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

## Multi-Repository Support
A single CodeSherpa instance can serve multiple repositories. Configure via `REPO_ROOTS`:

```env
REPO_ROOTS=frontend:/srv/repos/frontend,backend:/srv/repos/backend,infra:/srv/repos/infra
```

Format: `name1:/path1,name2:/path2,...`

- All tools accept an optional `repo` parameter to select the target repository.
- If `repo` is omitted, the first configured repository is used as the default.
- Use `list_repos` to discover available repositories.
- For single-repository setups, the legacy `REPO_ROOT` variable still works.

## Architecture
```text
MCP Client
    |
    v
CodeSherpa (HTTPS)
    |
    v
SSH (read-only or read-write user)
    |
    v
Private repository host (one or more repos)
```

Key points:
- Repository data stays on the SSH target host.
- Read-only by default; write tools require `mcp:write` OAuth scope.
- Path traversal and sensitive path segments are blocked.
- OAuth access tokens and legacy fixed bearer tokens are supported.

## Security Model
- Use a dedicated SSH user with minimal permissions (read-only recommended; grant write only if needed).
- Denied path segments include `.git`, `.env`, `node_modules`, and similar sensitive paths.
- Absolute paths and `..` traversal are rejected.
- `/mcp` requires `mcp:read` scope for OAuth access tokens.
- Write tools (`write_file`, `delete_file`, `patch_file`) require `mcp:write` scope.
- Legacy fixed bearer token auth can remain enabled for internal testing (read-only scope only).

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
- Scopes: `mcp:read` (read-only), `mcp:read mcp:write` (read + write)
- Public client support: yes (`token_endpoint_auth_method=none` allowed)
- Refresh token: supported

### ChatGPT Connector Values (Example)
Use example values like these:
- MCP endpoint: `https://code-sherpa.example.com/mcp`
- Issuer: `https://code-sherpa.example.com`
- Authorization endpoint: `https://code-sherpa.example.com/authorize`
- Token endpoint: `https://code-sherpa.example.com/token`
- Scope: `mcp:read` (add `mcp:write` for write access)

## Environment Variables
Use `.env.example` as the baseline.

Required:
- `SSH_HOST`
- `SSH_PORT`
- `SSH_USERNAME`
- `REPO_ROOT` or `REPO_ROOTS` (at least one)
- `MCP_BEARER_TOKEN` (for optional legacy/manual testing)
- `OAUTH_ISSUER_BASE_URL`
- `OAUTH_LOGIN_USERNAME`
- `OAUTH_LOGIN_PASSWORD`
- `OAUTH_SESSION_SECRET`

Repository configuration:
- `REPO_ROOT` — single repository path (legacy)
- `REPO_ROOTS` — multiple repositories as `name1:/path1,name2:/path2` (takes precedence over `REPO_ROOT`)

Optional/common:
- `PORT` (default `8787`)
- `MCP_SERVER_NAME` (default `code-sherpa`)
- `MCP_SERVER_VERSION` (default `0.1.0`)
- `OAUTH_COOKIE_SECURE` (default `true`)
- `MAX_FILE_BYTES`, `MAX_WRITE_BYTES`, `MAX_SEARCH_RESULTS`, `MAX_LOG_COMMITS`, `MAX_RESPONSE_CHARS`

Example `.env` snippet (safe placeholders):

```env
PORT=8787
MCP_SERVER_NAME=code-sherpa
SSH_HOST=ssh-host.example.internal
SSH_PORT=22
SSH_USERNAME=repo_reader
REPO_ROOTS=frontend:/srv/repos/frontend,backend:/srv/repos/backend
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
