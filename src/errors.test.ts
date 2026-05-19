import assert from "node:assert/strict";
import test from "node:test";
import { errorMessage, normalizeError } from "./errors.js";

test("errorMessage extracts message from plain object", () => {
  assert.equal(errorMessage({ message: "boom" }), "boom");
});

test("errorMessage extracts nested message and decorates with metadata", () => {
  const result = errorMessage({
    message: "request failed",
    code: "ENOTFOUND",
    status: 404,
  });
  assert.equal(result, "request failed (code=ENOTFOUND, status=404)");
});

test("errorMessage handles primitives, null and undefined", () => {
  assert.equal(errorMessage("oops"), "oops");
  assert.equal(errorMessage(42), "42");
  assert.equal(errorMessage(true), "true");
  assert.equal(errorMessage(null), "Unknown error: null");
  assert.equal(errorMessage(undefined), "Unknown error");
});

test("normalizeError preserves Error instances unchanged", () => {
  const original = new Error("original");
  assert.strictEqual(normalizeError(original), original);
});

test("normalizeError does NOT attach the raw value as cause", () => {
  // Reason: the raw value may contain unsanitized secrets (1Password tokens,
  // Connect URLs with credentials) that would surface through Node's
  // Error.cause chain formatting in stderr / JSON serialization.
  const sensitive = { message: "auth failed", token: "ops_secret_abc123" };
  const wrapped = normalizeError(sensitive);
  assert.equal(wrapped.cause, undefined);
});

test("normalizeError of an object with a secret-bearing cause does not leak it", () => {
  // If a caller passes an object that itself has a `cause` containing secrets,
  // wrapping must not propagate that cause chain.
  const malicious = {
    message: "outer",
    cause: { message: "ops_eyJhbGciOi...trapped-token" },
  };
  const wrapped = normalizeError(malicious);
  assert.equal(wrapped.cause, undefined);
  assert.equal(wrapped.message, "outer");
  assert.ok(!wrapped.message.includes("ops_eyJhbGciOi"));
});

test("normalizeError of a primitive yields a clean Error with no cause", () => {
  const wrapped = normalizeError("ops_eyJhbGciOi.secret.payload");
  assert.equal(wrapped.cause, undefined);
  // String primitives are surfaced verbatim in the message — callers are
  // responsible for sanitizing before logging. This test documents the contract.
  assert.equal(wrapped.message, "ops_eyJhbGciOi.secret.payload");
});
