import { createHmac } from "node:crypto";
import type { Request } from "express";
import { generateRandomToken, secureEqual } from "./pkce.js";

export type UserSession = {
  id: string;
  userId: string;
  expiresAt: number;
};

export class SessionStore {
  private readonly sessions = new Map<string, UserSession>();

  create(userId: string, ttlMs: number): UserSession {
    this.cleanup();
    const session: UserSession = {
      id: generateRandomToken(24),
      userId,
      expiresAt: Date.now() + ttlMs,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  get(sessionId: string): UserSession | null {
    this.cleanup();
    return this.sessions.get(sessionId) ?? null;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.sessions.entries()) {
      if (value.expiresAt <= now) {
        this.sessions.delete(key);
      }
    }
  }
}

export function signedSessionValue(sessionId: string, secret: string): string {
  const signature = createHmac("sha256", secret).update(sessionId).digest("hex");
  return `${sessionId}.${signature}`;
}

export function extractSignedSessionId(value: string, secret: string): string | null {
  const parts = value.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [sessionId, signature] = parts;
  const expectedSignature = createHmac("sha256", secret).update(sessionId).digest("hex");
  if (!secureEqual(signature, expectedSignature)) {
    return null;
  }
  return sessionId;
}

export function getCookieValue(req: Request, cookieName: string): string | null {
  const header = req.headers.cookie;
  if (!header) {
    return null;
  }

  const pairs = header.split(";");
  for (const pair of pairs) {
    const trimmed = pair.trim();
    const index = trimmed.indexOf("=");
    if (index < 0) {
      continue;
    }
    const key = trimmed.slice(0, index).trim();
    if (key !== cookieName) {
      continue;
    }
    return decodeURIComponent(trimmed.slice(index + 1));
  }

  return null;
}
