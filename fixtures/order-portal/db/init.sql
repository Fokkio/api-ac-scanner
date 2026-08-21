CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'viewer', 'admin')),
  tenant TEXT NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE auth_credentials (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  bearer_token TEXT UNIQUE NOT NULL,
  api_key TEXT UNIQUE NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  custom_secret TEXT NOT NULL
);

CREATE TABLE orders (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  description TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE workflow_resources (
  path TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  value JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO users (username, display_name, role, tenant, password_hash) VALUES
  ('alice', 'Alice Owner', 'owner', 'tenant-a', crypt('alice-password', gen_salt('bf', 4))),
  ('bob', 'Bob Viewer', 'viewer', 'tenant-a', crypt('bob-password', gen_salt('bf', 4))),
  ('admin', 'Ada Admin', 'admin', 'global', crypt('admin-password', gen_salt('bf', 4)));

INSERT INTO auth_credentials (user_id, bearer_token, api_key, session_token, custom_secret)
SELECT id,
  username || '-bearer-token-1234567890',
  username || '-api-key-1234567890',
  username || '-session-token-1234567890',
  username || '-custom-secret-1234567890'
FROM users;

INSERT INTO orders (owner_id, description, status)
SELECT id, 'Disposable scanner verification order', 'pending'
FROM users WHERE username = 'alice';

INSERT INTO orders (owner_id, description, status)
SELECT id, 'Viewer-owned reference order', 'approved'
FROM users WHERE username = 'bob';

INSERT INTO orders (owner_id, description, status)
SELECT id, 'Administrator audit order', 'review'
FROM users WHERE username = 'admin';
