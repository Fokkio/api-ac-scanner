"use strict";

const http = require("node:http");

const port = Number.parseInt(process.env.DEMO_PORT || "4100", 10);
const ownerToken = process.env.DEMO_OWNER_TOKEN;
const alternateToken = process.env.DEMO_ALTERNATE_TOKEN;
let temporaryMutationResourceExists = false;
let temporaryWorkflowResource = null;

if (!ownerToken || !alternateToken || ownerToken === alternateToken) {
  throw new Error("Two different demo-only tokens are required");
}

const server = http.createServer((request, response) => {
  const authorization = request.headers.authorization || "";
  const token = authorization.replace(/^Bearer\s+/i, "");
  response.setHeader("content-type", "application/json; charset=utf-8");

  if (request.url === "/__ac_test__/login" && request.method === "POST") {
    readJson(request, response, (body) => {
      if (body.username !== "fixture-owner" || body.password !== "fixture-password") {
        respond(response, 401, { error: "invalid test credential" });
        return;
      }
      respond(response, 200, { tokens: { access: ownerToken } });
    });
    return;
  }
  if (request.url === "/__ac_test__/workflow-resource") {
    if (token !== ownerToken) {
      request.resume();
      respond(response, 403, { error: "owner test identity required" });
      return;
    }
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      readJson(request, response, (body) => {
        if (body.apiAcScannerTest !== true) {
          respond(response, 400, { error: "test marker required" });
          return;
        }
        temporaryWorkflowResource = request.method === "PATCH"
          ? { ...(temporaryWorkflowResource || {}), ...body }
          : body;
        respond(response, request.method === "POST" ? 201 : 200, temporaryWorkflowResource);
      });
      return;
    }
    if (request.method === "GET") {
      respond(response, temporaryWorkflowResource ? 200 : 404, temporaryWorkflowResource || { error: "not found" });
      return;
    }
    if (request.method === "DELETE") {
      const existed = temporaryWorkflowResource !== null;
      temporaryWorkflowResource = null;
      respond(response, existed ? 204 : 404, null);
      return;
    }
  }

  if (request.url === "/__ac_test__/v3-safe-resource" && request.method === "POST") {
    if (token !== ownerToken) {
      respond(response, 403, { error: "owner test identity required" });
      return;
    }
    temporaryMutationResourceExists = true;
    request.resume();
    respond(response, 201, { created: true, apiAcScannerTest: true });
    return;
  }
  if (request.url === "/__ac_test__/v3-safe-resource" && request.method === "DELETE") {
    if (token !== ownerToken) {
      respond(response, 403, { error: "owner test identity required" });
      return;
    }
    const existed = temporaryMutationResourceExists;
    temporaryMutationResourceExists = false;
    respond(response, existed ? 204 : 404, null);
    return;
  }

  if (request.method === "OPTIONS") {
    response.setHeader("allow", "GET, OPTIONS");
    response.writeHead(204).end();
    return;
  }
  if (request.url === "/") {
    respond(response, 200, { name: "V3.1 intentionally vulnerable local fixture" });
    return;
  }
  if (request.url === "/api/orders/1") {
    if (token !== ownerToken && token !== alternateToken) {
      respond(response, 401, { error: "authentication required" });
      return;
    }
    respond(response, 200, {
      id: 1,
      ownerId: "owner-user",
      tenantId: "tenant-a",
      email: "fixture@example.invalid",
    });
    return;
  }
  if (request.url === "/api/admin") {
    if (token !== ownerToken && token !== alternateToken) {
      respond(response, 401, { error: "authentication required" });
      return;
    }
    respond(response, 200, { action: "admin-report", allowed: true });
    return;
  }
  if (request.url === "/api/users/alice") {
    respond(response, 200, { username: "alice", message: "existing local fixture account" });
    return;
  }
  if (request.url === "/api/users/definitely-missing") {
    respond(response, 404, { error: "not found" });
    return;
  }
  respond(response, 404, { error: "not found" });
});

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`Local authorization fixture listening on ${port}\n`);
});

function respond(response, status, body) {
  response.writeHead(status);
  response.end(JSON.stringify(body));
}

function readJson(request, response, callback) {
  let raw = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    raw += chunk;
    if (raw.length > 4096) request.destroy();
  });
  request.on("end", () => {
    try {
      callback(JSON.parse(raw || "{}"));
    } catch (_error) {
      respond(response, 400, { error: "invalid json" });
    }
  });
}
