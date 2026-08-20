import crypto from "crypto";

/** Tiny uuid without extra deps. */
export function v4(): string {
  return crypto.randomBytes(16).toString("hex");
}
