import assert from "node:assert/strict";
import test from "node:test";
import type { SessionData } from "express-session";
import { BoundedMemoryStore } from "../security/BoundedMemoryStore";

function sessionData(expires = new Date(Date.now() + 60_000)): SessionData {
  return {
    cookie: { originalMaxAge: 60_000, expires, httpOnly: true, path: "/" },
  } as SessionData;
}

test("bounds session count and evicts the least recently touched session", async () => {
  const store = new BoundedMemoryStore(2, 60_000);
  store.set("oldest", sessionData());
  store.set("newer", sessionData());
  store.set("newest", sessionData());

  assert.equal(store.getSize(), 2);
  assert.equal(await getSession(store, "oldest"), null);
  assert.ok(await getSession(store, "newer"));
});

test("prunes expired sessions", () => {
  const store = new BoundedMemoryStore(2, 60_000);
  store.set("expired", sessionData(new Date(Date.now() - 1)));
  assert.equal(store.getSize(), 0);
});

function getSession(store: BoundedMemoryStore, sessionId: string): Promise<SessionData | null> {
  return new Promise((resolve, reject) => {
    store.get(sessionId, (error, value) => error ? reject(error) : resolve(value ?? null));
  });
}
