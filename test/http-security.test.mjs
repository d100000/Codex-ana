import test from "node:test";
import assert from "node:assert/strict";
import {
  assertEmptyRequest,
  assertJsonRequest,
  createRequestSecurity,
  RequestSecurityError,
  securityResponseHeaders,
} from "../src/http-security.mjs";

test("request guard rejects DNS-rebinding Host headers", () => {
  const guard = createRequestSecurity({
    bindHost: "127.0.0.1",
    port: 4317,
  });

  assert.throws(
    () =>
      guard(
        request({
          host: "attacker.example:4317",
        }),
        "/",
      ),
    (error) =>
      error instanceof RequestSecurityError &&
      error.code === "misdirected_request" &&
      error.httpStatus === 421,
  );
  assert.doesNotThrow(() =>
    guard(request(), "/"),
  );
});

test("state-changing APIs require same-origin intent", () => {
  const guard = createRequestSecurity({
    bindHost: "127.0.0.1",
    port: 4317,
  });

  assert.throws(
    () => guard(request({ method: "POST" }), "/api/models"),
    (error) => error.code === "api_intent_required",
  );
  assert.throws(
    () =>
      guard(
        request({
          method: "POST",
          headers: {
            "x-planscope-request": "1",
            "sec-fetch-site": "cross-site",
          },
        }),
        "/api/models",
      ),
    (error) => error.code === "cross_site_request_blocked",
  );
  assert.throws(
    () =>
      guard(
        request({
          method: "POST",
          headers: {
            "x-planscope-request": "1",
            origin: "https://attacker.example",
          },
        }),
        "/api/models",
      ),
    (error) => error.code === "origin_mismatch",
  );
  assert.doesNotThrow(() =>
    guard(
      request({
        method: "POST",
        headers: {
          "x-planscope-request": "1",
          "sec-fetch-site": "same-origin",
          origin: "http://127.0.0.1:4317",
        },
      }),
      "/api/models",
    ),
  );
});

test("public binding requires an explicit trusted host", () => {
  assert.throws(
    () =>
      createRequestSecurity({
        bindHost: "0.0.0.0",
        port: 4317,
      }),
    (error) => error.code === "unsafe_public_binding",
  );
  assert.throws(
    () =>
      createRequestSecurity({
        bindHost: "0.0.0.0",
        port: 4317,
        publicOrigin: "http://planscope.example",
      }),
    (error) => error.code === "unsafe_public_binding",
  );

  const guard = createRequestSecurity({
    bindHost: "0.0.0.0",
    port: 4317,
    publicOrigin: "https://planscope.example",
  });
  assert.throws(
    () =>
      guard(
        request({
          host: "planscope.example",
        }),
        "/",
      ),
    (error) =>
      error.code === "https_required" &&
      error.httpStatus === 426,
  );
  assert.doesNotThrow(() =>
    guard(
      request({
        host: "planscope.example",
        method: "POST",
        encrypted: true,
        headers: {
          "x-planscope-request": "1",
          origin: "https://planscope.example",
        },
      }),
      "/api/analyze",
    ),
  );
});

test("JSON endpoints reject simple cross-site content types", () => {
  assert.throws(
    () =>
      assertJsonRequest(
        request({
          headers: {
            "content-type": "text/plain",
          },
        }),
      ),
    (error) =>
      error.code === "unsupported_media_type" &&
      error.httpStatus === 415,
  );
  assert.doesNotThrow(() =>
    assertJsonRequest(
      request({
        headers: {
          "content-type": "application/json; charset=utf-8",
        },
      }),
    ),
  );
});

test("bodyless endpoints reject payloads and chunked uploads", () => {
  assert.doesNotThrow(() => assertEmptyRequest(request()));
  assert.throws(
    () =>
      assertEmptyRequest(
        request({
          headers: { "content-length": "1" },
        }),
      ),
    (error) => error.code === "unexpected_request_body",
  );
  assert.throws(
    () =>
      assertEmptyRequest(
        request({
          headers: { "transfer-encoding": "chunked" },
        }),
      ),
    (error) => error.httpStatus === 413,
  );
});

test("browser security headers isolate the application", () => {
  const headers = securityResponseHeaders({ secure: true });
  assert.match(headers["Content-Security-Policy"], /object-src 'none'/);
  assert.equal(headers["Cross-Origin-Opener-Policy"], "same-origin");
  assert.equal(headers["Cross-Origin-Resource-Policy"], "same-origin");
  assert.equal(
    headers["Strict-Transport-Security"],
    "max-age=31536000",
  );
  assert.equal(headers["X-Frame-Options"], "DENY");
});

function request(options = {}) {
  return {
    method: options.method ?? "GET",
    headers: {
      host: options.host ?? "127.0.0.1:4317",
      ...(options.headers ?? {}),
    },
    socket: {
      encrypted: options.encrypted === true,
      remoteAddress: "127.0.0.1",
    },
  };
}
