import session, { type SessionData } from "express-session";

interface StoredSession {
  value: SessionData;
  expiresAt: number;
  lastTouchedAt: number;
}

type StoreCallback = (error?: unknown) => void;

/** Single-node session store with expiry and a hard capacity ceiling. */
export class BoundedMemoryStore extends session.Store {
  private readonly sessions = new Map<string, StoredSession>();

  public constructor(private readonly capacity: number, private readonly fallbackTtlMilliseconds: number) {
    super();
  }

  public get(sessionId: string, callback: (error: unknown, session?: SessionData | null) => void): void {
    this.pruneExpired();
    const stored = this.sessions.get(sessionId);
    callback(null, stored ? structuredClone(stored.value) : null);
  }

  public set(sessionId: string, value: SessionData, callback?: StoreCallback): void {
    this.pruneExpired();
    if (!this.sessions.has(sessionId) && this.sessions.size >= this.capacity) this.evictOneSession();
    const now = Date.now();
    this.sessions.set(sessionId, {
      value: structuredClone(value),
      expiresAt: resolveExpiry(value, now + this.fallbackTtlMilliseconds),
      lastTouchedAt: now,
    });
    callback?.();
  }

  public destroy(sessionId: string, callback?: StoreCallback): void {
    this.sessions.delete(sessionId);
    callback?.();
  }

  public touch(sessionId: string, value: SessionData, callback?: StoreCallback): void {
    const stored = this.sessions.get(sessionId);
    if (stored) {
      const now = Date.now();
      stored.value = structuredClone(value);
      stored.expiresAt = resolveExpiry(value, now + this.fallbackTtlMilliseconds);
      stored.lastTouchedAt = now;
    }
    callback?.();
  }

  /** Exposed for health-independent unit tests only. */
  public getSize(): number {
    this.pruneExpired();
    return this.sessions.size;
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [sessionId, stored] of this.sessions) {
      if (stored.expiresAt <= now) this.sessions.delete(sessionId);
    }
  }

  private evictOneSession(): void {
    const entries = [...this.sessions.entries()];
    entries.sort((left, right) => left[1].lastTouchedAt - right[1].lastTouchedAt);
    const oldest = entries[0];
    if (oldest) this.sessions.delete(oldest[0]);
  }
}

function resolveExpiry(value: SessionData, fallback: number): number {
  const expires = value.cookie.expires;
  if (!expires) return fallback;
  const timestamp = expires instanceof Date ? expires.getTime() : new Date(expires).getTime();
  return Number.isFinite(timestamp) ? timestamp : fallback;
}
