import { ValidationError } from "../errors/AppError";
import { parseRelativePaths } from "./inputPolicy";
import type { AuthorizationPolicyRule, TestIdentity } from "../types/domain";

/** Parses a complete, bounded expected-access policy for the selected identities. */
export function parseAuthorizationPolicy(rawPolicy: unknown, identities: [TestIdentity, TestIdentity]): AuthorizationPolicyRule[] {
  if (typeof rawPolicy !== "string" || rawPolicy.length > 20_000) {
    throw new ValidationError("Authorization policy JSON is required and must be bounded");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawPolicy);
  } catch {
    throw new ValidationError("Authorization policy must be valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 30) {
    throw new ValidationError("Authorization policy must contain between 1 and 30 rules");
  }
  const allowedIdentities = new Set([identities[0].label, identities[1].label, "Anonymous"]);
  const rules = parsed.map((value): AuthorizationPolicyRule => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Each authorization policy rule must be an object");
    }
    const rule = value as Record<string, unknown>;
    if (rule.method !== "GET" && rule.method !== "POST" && rule.method !== "PUT" && rule.method !== "PATCH" && rule.method !== "DELETE") {
      throw new ValidationError("Policy method must be a supported HTTP method");
    }
    if (typeof rule.identity !== "string" || !allowedIdentities.has(rule.identity)) {
      throw new ValidationError("Policy method or identity does not match this scan");
    }
    if (rule.expected !== "allow" && rule.expected !== "deny") {
      throw new ValidationError("Policy expected value must be allow or deny");
    }
    const [path] = parseRelativePaths(rule.path, 1);
    if (!path) throw new ValidationError("Policy path is required");
    return { method: "GET", path, identity: rule.identity, expected: rule.expected };
  });
  const unique = new Set(rules.map((rule) => `${rule.method}\n${rule.path}\n${rule.identity}`));
  if (unique.size !== rules.length) throw new ValidationError("Authorization policy contains duplicate rules");
  return rules;
}
