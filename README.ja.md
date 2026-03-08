<p align="center">
  <img src="https://raw.githubusercontent.com/boridon/code-sherpa/main/docs/logo.svg" width="220" alt="CodeSherpa logo">
</p>

<h1 align="center">CodeSherpa</h1>

<p align="center">SSH 経由でリポジトリを探索する MCP サーバー</p>
<p align="center"><a href="./README.md">English (README.md)</a> | 日本語</p>

---

## CodeSherpa とは
CodeSherpa は、SSH 越しにリポジトリを安全に参照するためのリモート MCP サーバーです。  
読み取り専用ツールセットで動作します。

対応している MCP ツール:
- `healthcheck_remote`
- `list_files`
- `read_file`
- `search_code`
- `git_status`
- `git_diff`
- `git_log`

対応クライアント例:
- ChatGPT（custom connectors）
- Claude Desktop
- Cursor
- その他 MCP 互換エージェント

## Quick Start
まずはローカルで CodeSherpa を起動します。

```bash
git clone https://github.com/boridon/code-sherpa.git
cd code-sherpa
cp .env.example .env
docker compose up -d
```

その後、MCP クライアントから次の URL に接続します。

```text
https://your-domain.example/mcp
```

補足:

SSH 接続に使用する秘密鍵と `known_hosts` は、`secrets/` ディレクトリに配置する必要があります。  
詳細は「Docker デプロイ」セクションを参照してください。

## アーキテクチャ
```text
MCP クライアント
    |
    v
CodeSherpa (HTTPS)
    |
    v
SSH (読み取り専用ユーザー)
    |
    v
プライベートリポジトリホスト
```

ポイント:
- リポジトリの実体は SSH 接続先ホストに残ります。
- CodeSherpa は read-only の MCP ツールのみ公開します。
- パストラバーサルと機微なパスセグメントをブロックします。
- OAuth アクセストークンと固定 Bearer トークンの両方を利用できます。

## セキュリティモデル
- SSH ユーザーは read-only（sudo なし）を推奨します。
- `.git`、`.env`、`node_modules` など機微なパスは拒否します。
- 絶対パスと `..` を使ったパストラバーサルを拒否します。
- `/mcp` では OAuth 利用時に `mcp:read` スコープを要求します。
- 固定 Bearer 認証は内部テスト用として併用できます。

注記: 現在の OAuth セッション、認可コード、トークンはメモリ保持です。コンテナ再起動で消えます。

## Docker デプロイ
### 1. クローンと初期準備
```bash
git clone https://github.com/boridon/code-sherpa.git
cd code-sherpa
cp .env.example .env
mkdir -p secrets
```

### 2. SSH シークレットを配置
- 秘密鍵を `secrets/id_ed25519` に配置
- known_hosts を作成

```bash
ssh-keyscan -H <ssh-host> > secrets/known_hosts
chmod 600 secrets/id_ed25519
chmod 644 secrets/known_hosts
```

### 3. サービス起動
```bash
docker compose build
docker compose up -d
docker compose ps
curl http://127.0.0.1:8787/health
```

## Cloudflare Tunnel
CodeSherpa は Cloudflare Tunnel を 2 つの方式で利用できます。

### A. Sidecar コンテナ（トークンモード）
```bash
docker compose -f docker-compose.yml -f docker-compose.cloudflare.yml up -d
```

この方式は `.env` の `CLOUDFLARE_TUNNEL_TOKEN` を利用します。

### B. 設定ファイルモード（`cloudflared-config.yml`）
ingress 設定例:

```yaml
ingress:
  - hostname: code-sherpa.example.com
    service: http://localhost:8787
  - service: http_status:404
```

ホストに `cloudflared` がない場合:
- Debian/Ubuntu: `sudo apt-get install cloudflared`
- RHEL/CentOS/Fedora: `sudo dnf install cloudflared`
- macOS (Homebrew): `brew install cloudflared`

## MCP Connector 向け OAuth
CodeSherpa には、Connector セットアップ向けの最小 OAuth 認可サーバーが内蔵されています。

OAuth discovery エンドポイント:
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`

OAuth エンドポイント:
- `GET /authorize`
- `POST /token`
- `GET /login`
- `POST /login`
- `GET /oauth/consent`
- `POST /oauth/consent`

OAuth プロファイル:
- Grant type: Authorization Code + PKCE（`S256`）
- Scope: `mcp:read`
- Public client: 対応（`token_endpoint_auth_method=none` を許可）
- Refresh token: 対応

### ChatGPT Connector 設定例
- MCP endpoint: `https://code-sherpa.example.com/mcp`
- Issuer: `https://code-sherpa.example.com`
- Authorization endpoint: `https://code-sherpa.example.com/authorize`
- Token endpoint: `https://code-sherpa.example.com/token`
- Scope: `mcp:read`

## 環境変数
`.env.example` をベースに設定してください。

必須:
- `SSH_HOST`
- `SSH_PORT`
- `SSH_USERNAME`
- `REPO_ROOT`
- `MCP_BEARER_TOKEN`（任意の legacy/manual テスト用）
- `OAUTH_ISSUER_BASE_URL`
- `OAUTH_LOGIN_USERNAME`
- `OAUTH_LOGIN_PASSWORD`
- `OAUTH_SESSION_SECRET`

任意（よく使うもの）:
- `PORT`（デフォルト `8787`）
- `MCP_SERVER_NAME`（デフォルト `code-sherpa`）
- `MCP_SERVER_VERSION`（デフォルト `0.1.0`）
- `OAUTH_COOKIE_SECURE`（デフォルト `true`）
- `MAX_FILE_BYTES`、`MAX_SEARCH_RESULTS`、`MAX_LOG_COMMITS`、`MAX_RESPONSE_CHARS`

`.env` 例（安全なプレースホルダ）:

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

## 最小動作確認
### 1. OAuth discovery
```bash
curl -i http://127.0.0.1:8787/.well-known/oauth-authorization-server
curl -i http://127.0.0.1:8787/.well-known/openid-configuration
```

### 2. Legacy bearer テスト
```bash
curl -i -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer ${MCP_BEARER_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0.0.1"}}}'
```

### 3. OAuth トークン交換
ブラウザでログインと consent 後、認可コードを交換します。

```bash
curl -i -X POST http://127.0.0.1:8787/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=<authorization-code>' \
  --data-urlencode 'redirect_uri=<same-redirect-uri-used-at-authorize>' \
  --data-urlencode 'code_verifier=<pkce-code-verifier>' \
  --data-urlencode 'client_id=<client-id>'
```

## トラブルシューティング
### ChatGPT Desktop で OAuth が失敗する
ChatGPT Desktop アプリから MCP Connector を作成すると、OAuth 認証は外部ブラウザで実行されます。

このとき、次の 2 つのセッションが一致していないと認証に失敗することがあります。
- ChatGPT Desktop アプリのログインセッション
- ブラウザの `chatgpt.com` ログインセッション

解決方法:

ブラウザで `https://chatgpt.com` にログインしてから、Connector セットアップを再実行してください。

## ディレクトリ構成
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

## ライセンス
MIT

## Contributing
Issue と Pull Request を歓迎します。

CodeSherpa が役立ったら、GitHub で star を付けてもらえると嬉しいです。
