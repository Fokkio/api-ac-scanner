"use strict";

const express = require("express");
const { Pool } = require("pg");

const port = Number.parseInt(process.env.PORT || "4100", 10);
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");

const pool = new Pool({ connectionString: databaseUrl, max: 5 });
const app = express();
app.disable("x-powered-by");
app.use((request, response, next) => {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("content-security-policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'");
  response.setHeader("cache-control", "no-store");
  if (request.method === "OPTIONS") {
    response.setHeader("allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS");
    response.status(204).end();
    return;
  }
  next();
});
app.use(express.json({ limit: "8kb", strict: true }));
app.use(express.urlencoded({ extended: false, limit: "8kb" }));
app.use(express.static("public", { fallthrough: true, index: false }));

app.get("/health", async (_request, response) => {
  const result = await pool.query("SELECT COUNT(*)::int AS users FROM users");
  response.json({ status: "ok", database: "connected", users: result.rows[0].users });
});

app.get("/", (_request, response) => {
  response.type("html").send(renderLanding());
});

app.post("/ui/login", async (request, response) => {
  const user = await verifyPassword(request.body.username, request.body.password);
  if (!user) {
    response.status(401).type("html").send(renderMessage("Login failed", "Invalid disposable test credential."));
    return;
  }
  const credential = await pool.query("SELECT session_token FROM auth_credentials WHERE user_id = $1", [user.id]);
  response.cookie("portal_session", credential.rows[0].session_token, {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 15 * 60 * 1000,
  });
  response.redirect(303, "/portal");
});

app.post("/ui/logout", (_request, response) => {
  response.clearCookie("portal_session");
  response.redirect(303, "/");
});

app.get("/portal", async (request, response) => {
  const user = await authenticate(request);
  if (!user) {
    response.redirect(303, "/");
    return;
  }
  const orders = await pool.query(
    user.role === "admin"
      ? "SELECT o.id, o.description, o.status, u.username AS owner FROM orders o JOIN users u ON u.id = o.owner_id ORDER BY o.id"
      : "SELECT o.id, o.description, o.status, u.username AS owner FROM orders o JOIN users u ON u.id = o.owner_id WHERE o.owner_id = $1 ORDER BY o.id",
    user.role === "admin" ? [] : [user.id],
  );
  response.type("html").send(renderPortal(user, orders.rows));
});

app.post("/__ac_test__/login", async (request, response) => {
  const user = await verifyPassword(request.body.username, request.body.password);
  if (!user) {
    response.status(401).json({ error: "invalid test credential" });
    return;
  }
  const credential = await pool.query("SELECT bearer_token FROM auth_credentials WHERE user_id = $1", [user.id]);
  response.json({ tokens: { access: credential.rows[0].bearer_token }, profile: { role: user.role, tenant: user.tenant } });
});

app.get("/api/orders/:id", async (request, response) => {
  const user = await authenticate(request);
  if (!user) return response.status(401).json({ error: "authentication required" });
  const order = await pool.query(
    "SELECT o.id, o.owner_id, o.description, o.status, u.username AS owner, u.tenant FROM orders o JOIN users u ON u.id = o.owner_id WHERE o.id = $1",
    [request.params.id],
  );
  if (order.rowCount === 0) return response.status(404).json({ error: "not found" });
  if (user.role !== "admin" && user.id !== order.rows[0].owner_id) {
    return response.status(403).json({ error: "order ownership required" });
  }
  const { owner_id: _ownerId, ...safeOrder } = order.rows[0];
  response.json(safeOrder);
});

app.get("/api/admin/reports", async (request, response) => {
  const user = await authenticate(request);
  if (!user) return response.status(401).json({ error: "authentication required" });
  if (user.role !== "admin") return response.status(403).json({ error: "admin role required" });
  const result = await pool.query("SELECT COUNT(*)::int AS order_count FROM orders");
  response.json({ report: "order-summary", orderCount: result.rows[0].order_count });
});

app.get("/api/owner/summary", async (request, response) => {
  const user = await authenticate(request);
  if (!user) return response.status(401).json({ error: "authentication required" });
  if (!new Set(["owner", "admin"]).has(user.role)) {
    return response.status(403).json({ error: "owner role required" });
  }
  const result = await pool.query("SELECT COUNT(*)::int AS visible_orders FROM orders WHERE owner_id = $1", [user.id]);
  response.json({ summary: "owner-orders", visibleOrders: result.rows[0].visible_orders });
});

app.get("/api/users/:username", async (request, response) => {
  const user = await authenticate(request);
  if (!user || user.role !== "admin") return response.status(401).json({ error: "not available" });
  const result = await pool.query("SELECT username, role, tenant FROM users WHERE username = $1", [request.params.username]);
  if (result.rowCount === 0) return response.status(404).json({ error: "not found" });
  response.json(result.rows[0]);
});

app.all(/^\/__ac_test__\/[a-z0-9][a-z0-9-]{0,63}$/, async (request, response) => {
  const user = await authenticate(request);
  if (!user) return response.status(401).json({ error: "authentication required" });
  if (!new Set(["owner", "admin"]).has(user.role)) {
    return response.status(403).json({ error: "owner or admin role required" });
  }
  const resourcePath = request.path;

  if (["POST", "PUT", "PATCH"].includes(request.method)
      && (!request.body || request.body.apiAcScannerTest !== true)) {
    return response.status(400).json({ error: "apiAcScannerTest=true marker required" });
  }

  if (request.method === "POST") {
    try {
      const created = await pool.query(
        "INSERT INTO workflow_resources (path, owner_id, value) VALUES ($1, $2, $3::jsonb) RETURNING path, value",
        [resourcePath, user.id, JSON.stringify(request.body)],
      );
      return response.status(201).json(created.rows[0]);
    } catch (error) {
      if (error && error.code === "23505") return response.status(409).json({ error: "resource already exists" });
      throw error;
    }
  }

  if (request.method === "PUT") {
    const updated = await pool.query(
      "UPDATE workflow_resources SET value = $1::jsonb, updated_at = NOW() WHERE path = $2 AND (owner_id = $3 OR $4 = 'admin') RETURNING path, value",
      [JSON.stringify(request.body), resourcePath, user.id, user.role],
    );
    return updated.rowCount === 0
      ? response.status(404).json({ error: "not found" })
      : response.json(updated.rows[0]);
  }

  if (request.method === "PATCH") {
    const updated = await pool.query(
      "UPDATE workflow_resources SET value = value || $1::jsonb, updated_at = NOW() WHERE path = $2 AND (owner_id = $3 OR $4 = 'admin') RETURNING path, value",
      [JSON.stringify(request.body), resourcePath, user.id, user.role],
    );
    return updated.rowCount === 0
      ? response.status(404).json({ error: "not found" })
      : response.json(updated.rows[0]);
  }

  if (request.method === "GET") {
    const found = await pool.query(
      "SELECT path, value FROM workflow_resources WHERE path = $1 AND (owner_id = $2 OR $3 = 'admin')",
      [resourcePath, user.id, user.role],
    );
    return found.rowCount === 0
      ? response.status(404).json({ error: "not found" })
      : response.json(found.rows[0]);
  }

  if (request.method === "DELETE") {
    const deleted = await pool.query(
      "DELETE FROM workflow_resources WHERE path = $1 AND (owner_id = $2 OR $3 = 'admin') RETURNING path",
      [resourcePath, user.id, user.role],
    );
    return deleted.rowCount === 0 ? response.status(404).end() : response.status(204).end();
  }

  response.status(405).json({ error: "method not allowed" });
});

app.use((error, _request, response, _next) => {
  console.error("Order portal request failed", { message: error instanceof Error ? error.message : String(error) });
  response.status(500).json({ error: "fixture request failed" });
});

async function authenticate(request) {
  const authorization = String(request.headers.authorization || "");
  if (/^Bearer /i.test(authorization)) {
    return findUserByCredential("bearer_token", authorization.replace(/^Bearer\s+/i, ""));
  }
  if (/^Basic /i.test(authorization)) {
    try {
      const decoded = Buffer.from(authorization.replace(/^Basic\s+/i, ""), "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator > 0) return verifyPassword(decoded.slice(0, separator), decoded.slice(separator + 1));
    } catch (_error) {
      return null;
    }
  }
  const apiKey = request.get("x-api-key");
  if (apiKey) return findUserByCredential("api_key", apiKey);
  const sessionToken = parseCookies(request.headers.cookie || "").portal_session;
  if (sessionToken) return findUserByCredential("session_token", sessionToken);
  const customUser = request.get("x-demo-user");
  const customSecret = request.get("x-demo-secret");
  if (customUser && customSecret) {
    const result = await pool.query(
      "SELECT u.id, u.username, u.display_name, u.role, u.tenant FROM users u JOIN auth_credentials a ON a.user_id = u.id WHERE u.username = $1 AND a.custom_secret = $2",
      [customUser, customSecret],
    );
    return result.rows[0] || null;
  }
  return null;
}

async function verifyPassword(username, password) {
  if (typeof username !== "string" || typeof password !== "string" || username.length > 64 || password.length > 128) return null;
  const result = await pool.query(
    "SELECT id, username, display_name, role, tenant FROM users WHERE username = $1 AND password_hash = crypt($2, password_hash)",
    [username, password],
  );
  return result.rows[0] || null;
}

async function findUserByCredential(column, value) {
  if (!new Set(["bearer_token", "api_key", "session_token"]).has(column) || typeof value !== "string" || value.length > 256) return null;
  const result = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.role, u.tenant FROM users u JOIN auth_credentials a ON a.user_id = u.id WHERE a.${column} = $1`,
    [value],
  );
  return result.rows[0] || null;
}

function parseCookies(raw) {
  return Object.fromEntries(raw.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const separator = part.indexOf("=");
    return separator < 0 ? [part, ""] : [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
  }));
}

function renderLanding() {
  return layout("Order Approval Portal", `
    <section class="hero">
      <div>
        <span class="role">Disposable local fixture</span>
        <h1>Order Approval Portal</h1>
        <p>A database-backed, multi-role application created to verify API AC Scanner V3.1 safely.</p>
        <div class="accounts">
          <div class="account"><strong>Alice</strong> — owner of order #1</div>
          <div class="account"><strong>Bob</strong> — viewer without access to Alice's order</div>
          <div class="account"><strong>Ada</strong> — administrator with report access</div>
        </div>
      </div>
      <form action="/ui/login" method="post">
        <h2>Sign in</h2>
        <label>Username<input name="username" autocomplete="username" required></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
        <button type="submit">Open portal</button>
      </form>
    </section>`);
}

function renderPortal(user, orders) {
  const rows = orders.length === 0
    ? '<tr><td colspan="4">No visible orders for this identity.</td></tr>'
    : orders.map((order) => `<tr><td>${order.id}</td><td>${escapeHtml(order.owner)}</td><td>${escapeHtml(order.description)}</td><td>${escapeHtml(order.status)}</td></tr>`).join("");
  return layout("Portal", `
    <section class="panel">
      <span class="role">${escapeHtml(user.role)}</span>
      <h1>Welcome, ${escapeHtml(user.display_name)}</h1>
      <p class="notice">Authenticated as <code>${escapeHtml(user.username)}</code> in <code>${escapeHtml(user.tenant)}</code>.</p>
      <h2>Visible orders</h2>
      <table><thead><tr><th>ID</th><th>Owner</th><th>Description</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
      <form action="/ui/logout" method="post"><button type="submit">Sign out</button></form>
    </section>`);
}

function renderMessage(title, message) {
  return layout(title, `<section class="panel"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a href="/">Return</a></section>`);
}

function layout(title, content) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/styles.css"></head><body><header><strong>Order Approval Portal</strong></header><main>${content}</main></body></html>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

async function start() {
  for (let attempt = 1; attempt <= 30; attempt += 1) {
    try {
      await pool.query("SELECT 1");
      app.listen(port, "0.0.0.0", () => console.info(`Order portal fixture listening on ${port}`));
      return;
    } catch (error) {
      if (attempt === 30) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

start().catch((error) => {
  console.error("Order portal failed to start", error);
  process.exit(1);
});
