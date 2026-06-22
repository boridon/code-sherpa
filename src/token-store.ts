import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { generateRandomToken } from "./pkce.js";

export type OAuthScope = "mcp:read" | "mcp:write";

export type AuthorizationRequest = {
  id: string;
  clientId: string;
  redirectUri: string;
  state: string;
  scopes: OAuthScope[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: number;
};

export type AuthorizationCode = {
  code: string;
  clientId: string;
  redirectUri: string;
  scopes: OAuthScope[];
  userId: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: number;
};

export type AccessTokenRecord = {
  token: string;
  clientId: string;
  userId: string;
  scopes: OAuthScope[];
  expiresAt: number;
};

export type RefreshTokenRecord = {
  token: string;
  clientId: string;
  userId: string;
  scopes: OAuthScope[];
  expiresAt: number;
};

export class OAuthInMemoryStore {
  private readonly authRequests = new Map<string, AuthorizationRequest>();
  private readonly authCodes = new Map<string, AuthorizationCode>();
  private readonly accessTokens = new Map<string, AccessTokenRecord>();
  private readonly refreshTokens = new Map<string, RefreshTokenRecord>();
  private readonly persistPath: string | null;

  // Only access/refresh tokens are persisted across restarts; short-lived
  // authorization requests and codes are intentionally kept in memory only.
  constructor(persistPath?: string | null) {
    this.persistPath = persistPath ? persistPath : null;
    if (this.persistPath) {
      this.load();
    }
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.persistPath!, "utf8");
    } catch {
      return; // first run / no file yet
    }
    try {
      const data = JSON.parse(raw) as {
        accessTokens?: unknown[];
        refreshTokens?: unknown[];
      };
      const now = Date.now();
      for (const record of data.accessTokens ?? []) {
        if (isTokenRecord(record) && record.expiresAt > now) {
          this.accessTokens.set(record.token, record);
        }
      }
      for (const record of data.refreshTokens ?? []) {
        if (isTokenRecord(record) && record.expiresAt > now) {
          this.refreshTokens.set(record.token, record);
        }
      }
    } catch {
      // corrupt file → start empty rather than crash
    }
  }

  private persist(): void {
    if (!this.persistPath) {
      return;
    }
    try {
      const payload = JSON.stringify({
        accessTokens: [...this.accessTokens.values()],
        refreshTokens: [...this.refreshTokens.values()],
      });
      mkdirSync(dirname(this.persistPath), { recursive: true });
      const tmp = `${this.persistPath}.tmp`;
      writeFileSync(tmp, payload, { mode: 0o600 });
      renameSync(tmp, this.persistPath);
    } catch {
      // best-effort: never let a persistence failure break the auth flow
    }
  }

  createAuthorizationRequest(input: Omit<AuthorizationRequest, "id" | "expiresAt">, ttlMs: number): AuthorizationRequest {
    this.cleanupExpired();
    const request: AuthorizationRequest = {
      ...input,
      id: generateRandomToken(24),
      expiresAt: Date.now() + ttlMs,
    };
    this.authRequests.set(request.id, request);
    return request;
  }

  getAuthorizationRequest(requestId: string): AuthorizationRequest | null {
    this.cleanupExpired();
    return this.authRequests.get(requestId) ?? null;
  }

  removeAuthorizationRequest(requestId: string): void {
    this.authRequests.delete(requestId);
  }

  issueAuthorizationCode(request: AuthorizationRequest, userId: string, ttlMs: number): AuthorizationCode {
    this.cleanupExpired();
    const code: AuthorizationCode = {
      code: generateRandomToken(32),
      clientId: request.clientId,
      redirectUri: request.redirectUri,
      scopes: request.scopes,
      userId,
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: request.codeChallengeMethod,
      expiresAt: Date.now() + ttlMs,
    };
    this.authCodes.set(code.code, code);
    return code;
  }

  consumeAuthorizationCode(code: string): AuthorizationCode | null {
    this.cleanupExpired();
    const record = this.authCodes.get(code);
    if (!record) {
      return null;
    }
    this.authCodes.delete(code);
    return record;
  }

  issueAccessToken(input: Omit<AccessTokenRecord, "token" | "expiresAt">, ttlSec: number): AccessTokenRecord {
    this.cleanupExpired();
    const token: AccessTokenRecord = {
      ...input,
      token: generateRandomToken(32),
      expiresAt: Date.now() + ttlSec * 1000,
    };
    this.accessTokens.set(token.token, token);
    this.persist();
    return token;
  }

  getAccessToken(token: string): AccessTokenRecord | null {
    this.cleanupExpired();
    return this.accessTokens.get(token) ?? null;
  }

  issueRefreshToken(input: Omit<RefreshTokenRecord, "token" | "expiresAt">, ttlSec: number): RefreshTokenRecord {
    this.cleanupExpired();
    const token: RefreshTokenRecord = {
      ...input,
      token: generateRandomToken(32),
      expiresAt: Date.now() + ttlSec * 1000,
    };
    this.refreshTokens.set(token.token, token);
    this.persist();
    return token;
  }

  consumeRefreshToken(token: string): RefreshTokenRecord | null {
    this.cleanupExpired();
    const record = this.refreshTokens.get(token);
    if (!record) {
      return null;
    }
    this.refreshTokens.delete(token);
    this.persist();
    return record;
  }

  private cleanupExpired(): void {
    const now = Date.now();

    for (const [key, value] of this.authRequests.entries()) {
      if (value.expiresAt <= now) {
        this.authRequests.delete(key);
      }
    }

    for (const [key, value] of this.authCodes.entries()) {
      if (value.expiresAt <= now) {
        this.authCodes.delete(key);
      }
    }

    for (const [key, value] of this.accessTokens.entries()) {
      if (value.expiresAt <= now) {
        this.accessTokens.delete(key);
      }
    }

    for (const [key, value] of this.refreshTokens.entries()) {
      if (value.expiresAt <= now) {
        this.refreshTokens.delete(key);
      }
    }
  }
}

function isTokenRecord(value: unknown): value is AccessTokenRecord & RefreshTokenRecord {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.token === "string" &&
    typeof record.clientId === "string" &&
    typeof record.userId === "string" &&
    typeof record.expiresAt === "number" &&
    Array.isArray(record.scopes) &&
    record.scopes.every((scope) => scope === "mcp:read" || scope === "mcp:write")
  );
}
