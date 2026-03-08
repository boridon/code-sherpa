import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function generateRandomToken(bytes = 32): string {
  return toBase64Url(randomBytes(bytes));
}

export function pkceS256Challenge(verifier: string): string {
  return toBase64Url(createHash("sha256").update(verifier, "utf8").digest());
}

export function verifyPkceS256(verifier: string, expectedChallenge: string): boolean {
  const calculated = pkceS256Challenge(verifier);
  return secureEqual(calculated, expectedChallenge);
}

export function secureEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) {
    return false;
  }
  return timingSafeEqual(aBuf, bBuf);
}

function toBase64Url(buffer: Buffer): string {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
