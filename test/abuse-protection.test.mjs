import test from "node:test";
import assert from "node:assert/strict";
import {
  AbuseProtection,
  AbuseProtectionError,
} from "../src/abuse-protection.mjs";

test("a human-like slider trace produces one single-use proof", () => {
  const harness = createHarness();
  const challenge = harness.protection.issueChallenge(identity());
  harness.advance(900);
  const verified = harness.protection.verifyChallenge({
    challengeId: challenge.id,
    ...identity(),
    finalPosition: challenge.target,
    trace: validTrace(challenge.target),
  });

  const reservation = harness.protection.consumeProofAndReserve({
    proof: verified.proof,
    ...identity(),
  });
  assert.equal(reservation.cooldownSeconds, 300);
  assert.equal(reservation.nextAllowedAt, 300_900);

  assert.throws(
    () =>
      harness.protection.consumeProofAndReserve({
        proof: verified.proof,
        ...identity(),
      }),
    (error) =>
      error instanceof AbuseProtectionError &&
      error.code === "verification_required",
  );
});

test("cooldown is enforced independently for IP and device", () => {
  const harness = createHarness();
  reserveOneAnalysis(harness);

  assert.throws(
    () =>
      harness.protection.issueChallenge(
        identity({ deviceKey: "device-b" }),
      ),
    (error) =>
      error.code === "rate_limited" &&
      error.httpStatus === 429 &&
      error.retryAfterSeconds === 300,
  );
  assert.throws(
    () =>
      harness.protection.issueChallenge(
        identity({ ipKey: "ip-b" }),
      ),
    (error) => error.code === "rate_limited",
  );

  harness.advance(300_001);
  assert.doesNotThrow(() =>
    harness.protection.issueChallenge(identity()),
  );
});

test("challenge and proof are bound to the same IP and device", () => {
  const harness = createHarness();
  const challenge = harness.protection.issueChallenge(identity());

  assert.throws(
    () =>
      harness.protection.verifyChallenge({
        challengeId: challenge.id,
        ...identity({ deviceKey: "device-b" }),
        finalPosition: challenge.target,
        trace: validTrace(challenge.target),
      }),
    (error) => error.code === "verification_expired",
  );
});

test("too-fast or insufficient slider movement is rejected", () => {
  const harness = createHarness();
  const challenge = harness.protection.issueChallenge(identity());

  assert.throws(
    () =>
      harness.protection.verifyChallenge({
        challengeId: challenge.id,
        ...identity(),
        finalPosition: challenge.target,
        trace: [
          [0, 0],
          [100, 20],
          [200, 40],
          [300, 60],
          [400, 80],
          [500, 100],
          [600, 120],
          [challenge.target, 140],
        ],
      }),
    (error) => error.code === "verification_failed",
  );
});

test("expired challenges and excessive challenge creation are blocked", () => {
  const expiring = createHarness();
  const oldChallenge =
    expiring.protection.issueChallenge(identity());
  expiring.advance(120_001);
  assert.throws(
    () =>
      expiring.protection.verifyChallenge({
        challengeId: oldChallenge.id,
        ...identity(),
        finalPosition: oldChallenge.target,
        trace: validTrace(oldChallenge.target),
      }),
    (error) => error.code === "verification_expired",
  );

  const limited = createHarness({
    maxChallengesPerWindow: 2,
  });
  limited.protection.issueChallenge(identity());
  limited.advance(1);
  limited.protection.issueChallenge(identity());
  limited.advance(1);
  assert.throws(
    () => limited.protection.issueChallenge(identity()),
    (error) =>
      error.code === "challenge_rate_limited" &&
      error.httpStatus === 429,
  );
});

test("model lookup probing is limited by both IP and device", () => {
  const harness = createHarness({
    maxModelLookupsPerWindow: 2,
  });
  harness.protection.reserveModelLookup(identity());
  harness.advance(1);
  harness.protection.reserveModelLookup(identity());
  harness.advance(1);

  assert.throws(
    () =>
      harness.protection.reserveModelLookup(
        identity({ deviceKey: "device-b" }),
      ),
    (error) =>
      error.code === "model_lookup_rate_limited" &&
      error.httpStatus === 429,
  );
  assert.throws(
    () =>
      harness.protection.reserveModelLookup(
        identity({ ipKey: "ip-b" }),
      ),
    (error) => error.code === "model_lookup_rate_limited",
  );

  harness.advance(5 * 60 * 1_000);
  assert.doesNotThrow(() =>
    harness.protection.reserveModelLookup(identity()),
  );
});

function createHarness(config = {}) {
  let currentTime = 0;
  let tokenIndex = 0;
  const protection = new AbuseProtection({
    now: () => currentTime,
    randomInt: () => 700,
    tokenFactory: () => `token-${++tokenIndex}`,
    config,
  });
  return {
    protection,
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

function validTrace(target) {
  return Array.from({ length: 11 }, (_, index) => [
    Math.round((target * index) / 10),
    index * 90,
  ]);
}

function reserveOneAnalysis(harness) {
  const challenge = harness.protection.issueChallenge(identity());
  harness.advance(900);
  const verified = harness.protection.verifyChallenge({
    challengeId: challenge.id,
    ...identity(),
    finalPosition: challenge.target,
    trace: validTrace(challenge.target),
  });
  harness.protection.consumeProofAndReserve({
    proof: verified.proof,
    ...identity(),
  });
}
