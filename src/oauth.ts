import express, { type Request, type Response } from "express";
import { secureEqual, verifyPkceS256 } from "./pkce.js";
import { extractSignedSessionId, getCookieValue, SessionStore, signedSessionValue } from "./session.js";
import { type OAuthScope, OAuthInMemoryStore } from "./token-store.js";

type Logger = (event: string, data: Record<string, unknown>) => void;

export type CreateOAuthModuleOptions = {
  issuerBaseUrl: string;
  loginUsername: string;
  loginPassword: string;
  sessionSecret: string;
  fixedBearerToken?: string;
  secureCookies: boolean;
  logger: Logger;
};

export type McpAuthResult = {
  ok: boolean;
  source?: "oauth_access_token" | "fixed_bearer_token";
  subject?: string;
  scopes?: OAuthScope[];
};

const COOKIE_NAME = "code_sherpa_session";
const ALLOWED_SCOPES: OAuthScope[] = ["mcp:read"];
const REQUIRED_MCP_SCOPE: OAuthScope = "mcp:read";
const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_SEC = 3600;
const REFRESH_TOKEN_TTL_SEC = 60 * 60 * 24 * 30;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function createOAuthModule(options: CreateOAuthModuleOptions) {
  const issuer = trimTrailingSlash(options.issuerBaseUrl);
  const authorizationEndpoint = `${issuer}/authorize`;
  const tokenEndpoint = `${issuer}/token`;

  const store = new OAuthInMemoryStore();
  const sessions = new SessionStore();

  const router = express.Router();

  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json(buildDiscoveryDocument(issuer, authorizationEndpoint, tokenEndpoint));
  });

  router.get("/.well-known/openid-configuration", (_req, res) => {
    res.json(buildDiscoveryDocument(issuer, authorizationEndpoint, tokenEndpoint));
  });

  router.get("/authorize", (req, res) => {
    const authorizeInputLog = {
      clientId: getFirstString(req.query.client_id),
      redirectUri: getFirstString(req.query.redirect_uri),
      state: getFirstString(req.query.state),
      codeChallenge: getFirstString(req.query.code_challenge),
      codeChallengeMethod: getFirstString(req.query.code_challenge_method),
      scope: getFirstString(req.query.scope),
      responseType: getFirstString(req.query.response_type),
    };
    options.logger("oauth_authorize_received", authorizeInputLog);

    const parsed = parseAuthorizeRequest(req);
    if (!parsed.ok) {
      options.logger("oauth_authorize_rejected", {
        reason: parsed.message,
        ...authorizeInputLog,
      });
      res.status(400).send(errorPage("Invalid authorization request", parsed.message));
      return;
    }

    const authRequest = store.createAuthorizationRequest(
      {
        clientId: parsed.clientId,
        redirectUri: parsed.redirectUri,
        state: parsed.state,
        scopes: parsed.scopes,
        codeChallenge: parsed.codeChallenge,
        codeChallengeMethod: "S256",
      },
      AUTH_REQUEST_TTL_MS,
    );

    const userSession = getUserSession(req, sessions, options.sessionSecret);
    if (!userSession) {
      res.redirect(302, `/login?request_id=${encodeURIComponent(authRequest.id)}`);
      return;
    }

    res.redirect(302, `/oauth/consent?request_id=${encodeURIComponent(authRequest.id)}`);
  });

  router.get("/login", (req, res) => {
    const requestId = getFirstString(req.query.request_id);
    if (!requestId) {
      res.status(400).send(errorPage("Missing request", "request_id is required"));
      return;
    }

    const authRequest = store.getAuthorizationRequest(requestId);
    if (!authRequest) {
      res.status(400).send(errorPage("Expired request", "Authorization request has expired"));
      return;
    }

    res.send(loginPage(requestId, authRequest.clientId));
  });

  router.post("/login", (req, res) => {
    const requestId = asString(req.body?.request_id);
    const username = asString(req.body?.username);
    const password = asString(req.body?.password);

    if (!requestId) {
      res.status(400).send(errorPage("Missing request", "request_id is required"));
      return;
    }

    const authRequest = store.getAuthorizationRequest(requestId);
    if (!authRequest) {
      res.status(400).send(errorPage("Expired request", "Authorization request has expired"));
      return;
    }

    const usernameOk = secureEqual(username, options.loginUsername);
    const passwordOk = secureEqual(password, options.loginPassword);
    if (!usernameOk || !passwordOk) {
      options.logger("oauth_login_failed", { username });
      res.status(401).send(loginPage(requestId, authRequest.clientId, "Invalid username or password"));
      return;
    }

    const session = sessions.create(options.loginUsername, SESSION_TTL_MS);
    const signed = signedSessionValue(session.id, options.sessionSecret);

    res.cookie(COOKIE_NAME, signed, {
      httpOnly: true,
      secure: options.secureCookies,
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_TTL_MS,
    });

    const authorizeUrl = buildAuthorizeUrl(authRequest);
    store.removeAuthorizationRequest(requestId);

    options.logger("oauth_login_success", {
      username,
      returnToAuthorizeRequestId: requestId,
      returnAuthorizeUrl: authorizeUrl,
      clientId: authRequest.clientId,
      redirectUri: authRequest.redirectUri,
      state: authRequest.state,
    });

    res.redirect(302, authorizeUrl);
  });

  router.get("/oauth/consent", (req, res) => {
    const requestId = getFirstString(req.query.request_id);
    if (!requestId) {
      res.status(400).send(errorPage("Missing request", "request_id is required"));
      return;
    }

    const authRequest = store.getAuthorizationRequest(requestId);
    if (!authRequest) {
      res.status(400).send(errorPage("Expired request", "Authorization request has expired"));
      return;
    }

    const userSession = getUserSession(req, sessions, options.sessionSecret);
    if (!userSession) {
      res.redirect(302, `/login?request_id=${encodeURIComponent(requestId)}`);
      return;
    }

    res.send(consentPage(requestId, authRequest.clientId, authRequest.redirectUri, authRequest.scopes));
  });

  router.post("/oauth/consent", (req, res) => {
    const requestId = asString(req.body?.request_id);
    const action = asString(req.body?.action);

    if (!requestId) {
      res.status(400).send(errorPage("Missing request", "request_id is required"));
      return;
    }

    const authRequest = store.getAuthorizationRequest(requestId);
    if (!authRequest) {
      res.status(400).send(errorPage("Expired request", "Authorization request has expired"));
      return;
    }

    const userSession = getUserSession(req, sessions, options.sessionSecret);
    if (!userSession) {
      res.redirect(302, `/login?request_id=${encodeURIComponent(requestId)}`);
      return;
    }

    store.removeAuthorizationRequest(requestId);

    if (action !== "allow") {
      const deniedRedirect = appendQuery(authRequest.redirectUri, {
        error: "access_denied",
        error_description: "User denied consent",
        state: authRequest.state,
      });
      res.redirect(302, deniedRedirect);
      return;
    }

    const authCode = store.issueAuthorizationCode(authRequest, userSession.userId, AUTH_CODE_TTL_MS);
    options.logger("oauth_authorization_code_issued", {
      authorizationCode: authCode.code,
      clientId: authRequest.clientId,
      redirectUri: authRequest.redirectUri,
      codeChallenge: authRequest.codeChallenge,
      codeChallengeMethod: authRequest.codeChallengeMethod,
      expiresAt: new Date(authCode.expiresAt).toISOString(),
    });

    const successRedirect = appendQuery(authRequest.redirectUri, {
      code: authCode.code,
      state: authRequest.state,
      iss: issuer,
    });

    options.logger("oauth_authorize_redirect", {
      redirect_to: successRedirect,
      code: authCode.code,
      state: authRequest.state,
    });

    res.redirect(302, successRedirect);
  });

  router.post("/token", (req, res) => {
    setNoStoreHeaders(res);

    const grantType = asString(req.body?.grant_type);
    options.logger("oauth_token_received", {
      grant_type: grantType || null,
      client_id: asString(req.body?.client_id) || null,
      redirect_uri: asString(req.body?.redirect_uri) || null,
      code: asString(req.body?.code) || null,
      has_code_verifier: Boolean(asString(req.body?.code_verifier)),
      has_authorization_header: Boolean(req.header("authorization")),
      content_type: req.header("content-type") ?? null,
    });

    if (grantType === "authorization_code") {
      handleAuthorizationCodeGrant(req, res, store, options.logger);
      return;
    }

    if (grantType === "refresh_token") {
      handleRefreshTokenGrant(req, res, store, options.logger);
      return;
    }

    options.logger("oauth_token_error", {
      reason: "unsupported_grant_type",
      expected_client_id: null,
      received_client_id: asString(req.body?.client_id) || null,
      expected_redirect_uri: null,
      received_redirect_uri: asString(req.body?.redirect_uri) || null,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
    });
    tokenError(res, 400, "unsupported_grant_type", "grant_type is not supported");
  });

  function authenticateMcpBearer(authHeader: string | undefined): McpAuthResult {
    const token = extractBearerToken(authHeader);
    if (!token) {
      return { ok: false };
    }

    const accessToken = store.getAccessToken(token);
    if (accessToken && hasRequiredScopes(accessToken.scopes, [REQUIRED_MCP_SCOPE])) {
      return {
        ok: true,
        source: "oauth_access_token",
        subject: accessToken.userId,
        scopes: accessToken.scopes,
      };
    }

    if (options.fixedBearerToken && secureEqual(token, options.fixedBearerToken)) {
      return {
        ok: true,
        source: "fixed_bearer_token",
        subject: "legacy-bearer",
        scopes: [REQUIRED_MCP_SCOPE],
      };
    }

    return { ok: false };
  }

  return { router, authenticateMcpBearer };
}

function handleAuthorizationCodeGrant(req: Request, res: Response, store: OAuthInMemoryStore, logger: Logger): void {
  const code = asString(req.body?.code);
  const redirectUri = asString(req.body?.redirect_uri);
  const codeVerifier = asString(req.body?.code_verifier);
  const clientId = asString(req.body?.client_id);

  if (!code || !redirectUri || !codeVerifier) {
    logger("oauth_token_error", {
      reason: "invalid_request_missing_parameters",
      expected_client_id: null,
      received_client_id: clientId || null,
      expected_redirect_uri: null,
      received_redirect_uri: redirectUri || null,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
      code: code || null,
      has_code_verifier: Boolean(codeVerifier),
    });
    tokenError(res, 400, "invalid_request", "code, redirect_uri, and code_verifier are required");
    return;
  }

  const authCode = store.consumeAuthorizationCode(code);
  if (!authCode) {
    logger("oauth_token_error", {
      reason: "invalid_grant",
      expected_client_id: null,
      received_client_id: clientId || null,
      expected_redirect_uri: null,
      received_redirect_uri: redirectUri,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
      code,
      has_code_verifier: true,
    });
    tokenError(res, 400, "invalid_grant", "authorization code is invalid or expired");
    return;
  }

  if (authCode.redirectUri !== redirectUri) {
    logger("oauth_token_error", {
      reason: "redirect_uri_mismatch",
      expected_client_id: authCode.clientId,
      received_client_id: clientId || null,
      expected_redirect_uri: authCode.redirectUri,
      received_redirect_uri: redirectUri,
      expected_code_challenge_method: "S256",
      code_challenge_method: authCode.codeChallengeMethod,
      pkce_verification_result: "not_checked",
      code,
      has_code_verifier: true,
    });
    tokenError(res, 400, "invalid_grant", "redirect_uri does not match authorization request");
    return;
  }

  if (clientId && authCode.clientId !== clientId) {
    logger("oauth_token_error", {
      reason: "client_id_mismatch",
      expected_client_id: authCode.clientId,
      received_client_id: clientId,
      expected_redirect_uri: authCode.redirectUri,
      received_redirect_uri: redirectUri,
      expected_code_challenge_method: "S256",
      code_challenge_method: authCode.codeChallengeMethod,
      pkce_verification_result: "not_checked",
      code,
      has_code_verifier: true,
    });
    tokenError(res, 400, "invalid_client", "client_id does not match authorization request");
    return;
  }

  if (authCode.codeChallengeMethod !== "S256") {
    logger("oauth_token_error", {
      reason: "unsupported_code_challenge_method",
      expected_client_id: authCode.clientId,
      received_client_id: clientId || null,
      expected_redirect_uri: authCode.redirectUri,
      received_redirect_uri: redirectUri,
      expected_code_challenge_method: "S256",
      code_challenge_method: authCode.codeChallengeMethod,
      pkce_verification_result: "not_checked",
      code,
      has_code_verifier: true,
    });
    tokenError(res, 400, "invalid_grant", "unsupported code challenge method");
    return;
  }

  if (!verifyPkceS256(codeVerifier, authCode.codeChallenge)) {
    logger("oauth_token_error", {
      reason: "pkce_mismatch",
      expected_client_id: authCode.clientId,
      received_client_id: clientId || null,
      expected_redirect_uri: authCode.redirectUri,
      received_redirect_uri: redirectUri,
      expected_code_challenge_method: "S256",
      code_challenge_method: authCode.codeChallengeMethod,
      pkce_verification_result: "failed",
      code,
      has_code_verifier: true,
    });
    tokenError(res, 400, "invalid_grant", "PKCE verification failed");
    return;
  }

  const accessToken = store.issueAccessToken(
    {
      clientId: authCode.clientId,
      userId: authCode.userId,
      scopes: authCode.scopes,
    },
    ACCESS_TOKEN_TTL_SEC,
  );

  const refreshToken = store.issueRefreshToken(
    {
      clientId: authCode.clientId,
      userId: authCode.userId,
      scopes: authCode.scopes,
    },
    REFRESH_TOKEN_TTL_SEC,
  );

  logger("oauth_token_issued", {
    client_id: authCode.clientId,
    scope: authCode.scopes.join(" "),
    expires_in: ACCESS_TOKEN_TTL_SEC,
  });

  res.json({
    access_token: accessToken.token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SEC,
    refresh_token: refreshToken.token,
    scope: authCode.scopes.join(" "),
  });
}

function handleRefreshTokenGrant(req: Request, res: Response, store: OAuthInMemoryStore, logger: Logger): void {
  const refreshToken = asString(req.body?.refresh_token);
  if (!refreshToken) {
    logger("oauth_token_error", {
      reason: "invalid_request_missing_refresh_token",
      expected_client_id: null,
      received_client_id: asString(req.body?.client_id) || null,
      expected_redirect_uri: null,
      received_redirect_uri: asString(req.body?.redirect_uri) || null,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
    });
    tokenError(res, 400, "invalid_request", "refresh_token is required");
    return;
  }

  const stored = store.consumeRefreshToken(refreshToken);
  if (!stored) {
    logger("oauth_token_error", {
      reason: "invalid_grant_refresh_token_invalid_or_expired",
      expected_client_id: null,
      received_client_id: asString(req.body?.client_id) || null,
      expected_redirect_uri: null,
      received_redirect_uri: asString(req.body?.redirect_uri) || null,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
    });
    tokenError(res, 400, "invalid_grant", "refresh_token is invalid or expired");
    return;
  }

  const requestedScope = asString(req.body?.scope);
  const nextScopes = requestedScope ? parseScopes(requestedScope) : stored.scopes;

  if (!isValidScopeSet(nextScopes) || !isSubset(nextScopes, stored.scopes)) {
    logger("oauth_token_error", {
      reason: "invalid_scope_on_refresh",
      expected_client_id: stored.clientId,
      received_client_id: asString(req.body?.client_id) || null,
      expected_redirect_uri: null,
      received_redirect_uri: asString(req.body?.redirect_uri) || null,
      expected_code_challenge_method: "S256",
      code_challenge_method: null,
      pkce_verification_result: "not_applicable",
      requested_scope: requestedScope || null,
      stored_scope: stored.scopes.join(" "),
    });
    tokenError(res, 400, "invalid_scope", "scope is invalid for this refresh token");
    return;
  }

  const accessToken = store.issueAccessToken(
    {
      clientId: stored.clientId,
      userId: stored.userId,
      scopes: nextScopes,
    },
    ACCESS_TOKEN_TTL_SEC,
  );

  const nextRefreshToken = store.issueRefreshToken(
    {
      clientId: stored.clientId,
      userId: stored.userId,
      scopes: stored.scopes,
    },
    REFRESH_TOKEN_TTL_SEC,
  );

  res.json({
    access_token: accessToken.token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SEC,
    refresh_token: nextRefreshToken.token,
    scope: accessToken.scopes.join(" "),
  });

  logger("oauth_token_issued", {
    client_id: stored.clientId,
    scope: accessToken.scopes.join(" "),
    expires_in: ACCESS_TOKEN_TTL_SEC,
  });
}

function parseAuthorizeRequest(req: Request):
  | {
      ok: true;
      clientId: string;
      redirectUri: string;
      state: string;
      scopes: OAuthScope[];
      codeChallenge: string;
    }
  | { ok: false; message: string } {
  const responseType = getFirstString(req.query.response_type);
  const clientId = getFirstString(req.query.client_id);
  const redirectUri = getFirstString(req.query.redirect_uri);
  const state = getFirstString(req.query.state);
  const codeChallenge = getFirstString(req.query.code_challenge);
  const codeChallengeMethod = getFirstString(req.query.code_challenge_method);

  if (responseType !== "code") {
    return { ok: false, message: "response_type must be 'code'" };
  }
  if (!clientId) {
    return { ok: false, message: "client_id is required" };
  }
  if (!redirectUri || !isValidRedirectUri(redirectUri)) {
    return { ok: false, message: "redirect_uri is invalid" };
  }
  if (!state) {
    return { ok: false, message: "state is required" };
  }
  if (!codeChallenge) {
    return { ok: false, message: "code_challenge is required" };
  }
  if (codeChallengeMethod !== "S256") {
    return { ok: false, message: "code_challenge_method must be S256" };
  }

  const requestedScopeRaw = getFirstString(req.query.scope) ?? "mcp:read";
  const scopes = parseScopes(requestedScopeRaw);
  if (!isValidScopeSet(scopes)) {
    return { ok: false, message: "scope is invalid; only mcp:read is supported" };
  }

  return {
    ok: true,
    clientId,
    redirectUri,
    state,
    scopes,
    codeChallenge,
  };
}

function hasRequiredScopes(scopes: OAuthScope[], required: OAuthScope[]): boolean {
  const set = new Set(scopes);
  return required.every((scope) => set.has(scope));
}

function parseScopes(scopeText: string): OAuthScope[] {
  return scopeText
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter((scope): scope is OAuthScope => scope.length > 0 && scope === "mcp:read");
}

function isValidScopeSet(scopes: OAuthScope[]): boolean {
  if (scopes.length === 0) {
    return false;
  }
  return scopes.every((scope) => ALLOWED_SCOPES.includes(scope));
}

function isSubset(candidate: OAuthScope[], parent: OAuthScope[]): boolean {
  const set = new Set(parent);
  return candidate.every((scope) => set.has(scope));
}

function getUserSession(req: Request, sessions: SessionStore, secret: string) {
  const cookieValue = getCookieValue(req, COOKIE_NAME);
  if (!cookieValue) {
    return null;
  }

  const sessionId = extractSignedSessionId(cookieValue, secret);
  if (!sessionId) {
    return null;
  }

  return sessions.get(sessionId);
}

function buildDiscoveryDocument(issuer: string, authorizationEndpoint: string, tokenEndpoint: string) {
  return {
    issuer,
    authorization_endpoint: authorizationEndpoint,
    token_endpoint: tokenEndpoint,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    scopes_supported: ["mcp:read"],
    authorization_response_iss_parameter_supported: true,
  };
}

function appendQuery(baseUrl: string, params: Record<string, string>): string {
  const url = new URL(baseUrl);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

function loginPage(requestId: string, clientId: string, errorMessage?: string): string {
  const safeError = errorMessage ? `<p style="color:#c53030">${escapeHtml(errorMessage)}</p>` : "";
  return page(
    "CodeSherpa Login",
    `<h1>Sign in</h1>
     <p>Client: <code>${escapeHtml(clientId)}</code></p>
     ${safeError}
     <form method="post" action="/login">
       <input type="hidden" name="request_id" value="${escapeHtml(requestId)}" />
       <label>Username<br><input name="username" autocomplete="username" required /></label><br><br>
       <label>Password<br><input type="password" name="password" autocomplete="current-password" required /></label><br><br>
       <button type="submit">Login</button>
     </form>`,
  );
}

function consentPage(requestId: string, clientId: string, redirectUri: string, scopes: OAuthScope[]): string {
  const scopeList = scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join("");
  return page(
    "OAuth Consent",
    `<h1>Authorize access</h1>
     <p><strong>Client ID:</strong> <code>${escapeHtml(clientId)}</code></p>
     <p><strong>Redirect URI:</strong> <code>${escapeHtml(redirectUri)}</code></p>
     <p><strong>Requested scopes:</strong></p>
     <ul>${scopeList}</ul>
     <form method="post" action="/oauth/consent" style="display:inline-block;margin-right:8px;">
       <input type="hidden" name="request_id" value="${escapeHtml(requestId)}" />
       <input type="hidden" name="action" value="allow" />
       <button type="submit">Allow</button>
     </form>
     <form method="post" action="/oauth/consent" style="display:inline-block;">
       <input type="hidden" name="request_id" value="${escapeHtml(requestId)}" />
       <input type="hidden" name="action" value="deny" />
       <button type="submit">Deny</button>
     </form>`,
  );
}

function errorPage(title: string, message: string): string {
  return page(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 680px; margin: 40px auto; padding: 0 16px; line-height: 1.5; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
    input { width: 100%; max-width: 360px; padding: 8px; }
    button { padding: 8px 14px; }
  </style>
</head>
<body>${body}</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function tokenError(res: Response, status: number, error: string, description: string): void {
  res.status(status).json({ error, error_description: description });
}

function setNoStoreHeaders(res: Response): void {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) {
    return null;
  }
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function asString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return "";
}

function getFirstString(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) && value.length > 0 && typeof value[0] === "string") {
    return value[0];
  }
  return null;
}

function isValidRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    return Boolean(parsed.protocol && parsed.host);
  } catch {
    return false;
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function buildAuthorizeUrl(request: {
  clientId: string;
  redirectUri: string;
  state: string;
  scopes: OAuthScope[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
}): string {
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", request.clientId);
  params.set("redirect_uri", request.redirectUri);
  params.set("scope", request.scopes.join(" "));
  params.set("state", request.state);
  params.set("code_challenge", request.codeChallenge);
  params.set("code_challenge_method", request.codeChallengeMethod);
  return `/authorize?${params.toString()}`;
}
