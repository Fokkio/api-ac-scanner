import crypto from "node:crypto";

function stableDigest(value: string): Buffer {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

/** Compares credentials using fixed-length timing-safe digests. */
export function areCredentialsValid(
  suppliedUsername: unknown,
  suppliedPassword: unknown,
  expectedUsername: string,
  expectedPassword: string,
): boolean {
  if (typeof suppliedUsername !== "string" || typeof suppliedPassword !== "string") return false;
  const usernameMatches = crypto.timingSafeEqual(stableDigest(suppliedUsername), stableDigest(expectedUsername));
  const passwordMatches = crypto.timingSafeEqual(stableDigest(suppliedPassword), stableDigest(expectedPassword));
  return usernameMatches && passwordMatches;
}
