import assert from "node:assert/strict";
import test from "node:test";
import type { SessionData } from "express-session";
import { BoundedMemoryStore } from "../security/BoundedMemoryStore";

function sessionData(isAuthenticated = false, expires = new Date(Date.now() + 60_000)): SessionData {
  return {
    cookie: { originalMaxAge: 60_000, expires, httpOnly: true, path: "/" },
    isAuthenticated,
  } as SessionData;
}

test("bounds session count and prefers evicting unauthenticated sessions", async () => {
  const store = new BoundedMemoryStore(2, 60_000);
  store.set("admin", sessionData(true));
  store.set("anonymous", sessionData(false));
  store.set("new", sessionData(false));

  assert.equal(store.getSize(), 2);
  assert.ok(await getSession(store, "admin"));
  assert.equal(await getSession(store, "anonymous"), null);
});

test("prunes expired sessions", () => {
  const store = new BoundedMemoryStore(2, 60_000);
  store.set("expired", sessionData(false, new Date(Date.now() - 1)));
  assert.equal(store.getSize(), 0);
});

function getSession(store: BoundedMemoryStore, sessionId: string): Promise<SessionData | null> {
  return new Promise((resolve, reject) => {
    store.get(sessionId, (error, value) => error ? reject(error) : resolve(value ?? null));
  });
}
