import assert from "node:assert/strict";
import test from "node:test";
import type { NextFunction, Request, Response } from "express";
import { ForbiddenError } from "../errors/AppError";
import { getCsrfToken, requireCsrf } from "../middlewares/csrf";

function makeRequest(body: Record<string, unknown>, query: Record<string, unknown> = {}): Request {
  return {
    body,
    query,
    session: {},
    get: () => undefined,
  } as unknown as Request;
}

test("accepts the session token from the request body", () => {
  const request = makeRequest({});
  const token = getCsrfToken(request);
  request.body = { _csrf: token };
  let error: unknown;
  requireCsrf(request, {} as Response, ((received?: unknown) => { error = received; }) as NextFunction);
  assert.equal(error, undefined);
});

test("rejects CSRF tokens supplied only in the query string", () => {
  const request = makeRequest({});
  const token = getCsrfToken(request);
  request.query = { _csrf: token };
  let error: unknown;
  requireCsrf(request, {} as Response, ((received?: unknown) => { error = received; }) as NextFunction);
  assert.ok(error instanceof ForbiddenError);
});
