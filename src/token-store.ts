import { generateRandomToken } from "./pkce.js";

export type OAuthScope = "mcp:read";

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
    return token;
  }

  consumeRefreshToken(token: string): RefreshTokenRecord | null {
    this.cleanupExpired();
    const record = this.refreshTokens.get(token);
    if (!record) {
      return null;
    }
    this.refreshTokens.delete(token);
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
