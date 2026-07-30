import test from "node:test";
import assert from "node:assert/strict";
import {
  AdminAuth,
  AdminAuthError,
} from "../src/admin-auth.mjs";

test("admin sessions are signed, expiring, and bound to one device", () => {
  const harness = createHarness();
  const session = harness.auth.createSession({
    password: "correct-admin-password",
    ...identity(),
  });

  assert.equal(
    harness.auth.verifySession(session.token, "device-a"),
    true,
  );
  assert.equal(
    harness.auth.verifySession(session.token, "device-b"),
    false,
  );
  assert.doesNotMatch(session.token, /correct-admin-password/);

  harness.advance(60_001);
  assert.equal(
    harness.auth.verifySession(session.token, "device-a"),
    false,
  );
});

test("admin login failures are limited by IP and device", () => {
  const harness = createHarness({
    maxLoginFailures: 2,
    loginWindowMs: 10_000,
  });

  assert.throws(
    () =>
      harness.auth.createSession({
        password: "wrong-password-one",
        ...identity(),
      }),
    (error) =>
      error instanceof AdminAuthError &&
      error.code === "invalid_admin_credentials" &&
      error.httpStatus === 401,
  );
  assert.throws(
    () =>
      harness.auth.createSession({
        password: "wrong-password-two",
        ...identity(),
      }),
    (error) =>
      error.code === "admin_login_rate_limited" &&
      error.httpStatus === 429,
  );
  assert.throws(
    () =>
      harness.auth.createSession({
        password: "correct-admin-password",
        ...identity({ deviceKey: "device-b" }),
      }),
    (error) => error.code === "admin_login_rate_limited",
  );
  assert.throws(
    () =>
      harness.auth.createSession({
        password: "correct-admin-password",
        ...identity({ ipKey: "ip-b" }),
      }),
    (error) => error.code === "admin_login_rate_limited",
  );

  harness.advance(10_001);
  assert.doesNotThrow(() =>
    harness.auth.createSession({
      password: "correct-admin-password",
      ...identity(),
    }),
  );
});

test("admin authentication can be explicitly disabled", () => {
  const auth = new AdminAuth({
    password: null,
    secret: "s".repeat(32),
  });
  assert.equal(auth.enabled, false);
  assert.equal(auth.verifySession("anything", "device-a"), false);
  assert.throws(
    () =>
      auth.createSession({
        password: "anything",
        ...identity(),
      }),
    (error) =>
      error.code === "admin_disabled" &&
      error.httpStatus === 503,
  );
});

function createHarness(config = {}) {
  let currentTime = 1_000;
  const auth = new AdminAuth({
    password: "correct-admin-password",
    secret: "s".repeat(32),
    now: () => currentTime,
    tokenFactory: () => "n".repeat(24),
    config: {
      sessionTtlMs: 60_000,
      ...config,
    },
  });
  return {
    auth,
    advance(ms) {
      currentTime += ms;
    },
  };
}

function identity(overrides = {}) {
  return {
    ipKey: "ip-a",
    deviceKey: "device-a",
    ...overrides,
  };
}
