import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeSubscriptionPool,
  calculateBreakdown,
  chooseModel,
  extractCodexEvidence,
  extractPlanFromResponse,
  normalizePlan,
  resolveApiEndpoints,
} from "../src/analyzer.mjs";

test("resolveApiEndpoints accepts a root, /v1, or /responses URL", () => {
  assert.deepEqual(resolveApiEndpoints("https://gateway.example/"), {
    normalizedBaseUrl: "https://gateway.example/v1",
    responsesUrl: "https://gateway.example/v1/responses",
    modelsUrl: "https://gateway.example/v1/models",
  });
  assert.equal(
    resolveApiEndpoints("https://gateway.example/openai/v1").responsesUrl,
    "https://gateway.example/openai/v1/responses",
  );
  assert.equal(
    resolveApiEndpoints("https://gateway.example/openai/v1/responses?x=1")
      .modelsUrl,
    "https://gateway.example/openai/v1/models",
  );
});

test("resolveApiEndpoints rejects unsafe or malformed URLs", () => {
  assert.throws(() => resolveApiEndpoints("gateway.example"), /http/);
  assert.throws(
    () => resolveApiEndpoints("ftp://gateway.example"),
    /HTTP/,
  );
  assert.throws(
    () => resolveApiEndpoints("https://user:pass@gateway.example"),
    /用户名或密码/,
  );
});

test("plan normalization preserves unknown tiers and labels known ones", () => {
  assert.deepEqual(normalizePlan(" PRO "), {
    key: "pro",
    label: "Pro",
    known: true,
  });
  assert.deepEqual(normalizePlan("partner-ultra"), {
    key: "partner_ultra",
    label: "Partner Ultra",
    known: false,
  });
});

test("x-codex-plan-type takes priority over body fields", () => {
  const headers = new Headers({ "x-codex-plan-type": "pro" });
  const result = extractPlanFromResponse(headers, { plan_type: "free" });
  assert.equal(result.normalized.key, "pro");
  assert.equal(result.source, "response_header:x-codex-plan-type");
});

test("body plan_type is used when the response header is absent", () => {
  const result = extractPlanFromResponse(new Headers(), {
    rate_limits: { plan_type: "plus" },
  });
  assert.equal(result.normalized.key, "plus");
  assert.equal(result.source, "response_body:rate_limits.plan_type");
});

test("Codex quota evidence is extracted without response content", () => {
  const headers = new Headers({
    "x-codex-active-limit": "premium",
    "x-codex-primary-used-percent": "65",
    "x-codex-primary-window-minutes": "10080",
    "x-codex-primary-reset-at": "1785992470",
    "x-codex-credits-has-credits": "true",
    "x-codex-credits-unlimited": "false",
    "x-request-id": "req_test_123",
  });
  const evidence = extractCodexEvidence(headers);
  assert.equal(evidence.activeLimit, "premium");
  assert.equal(evidence.primary.usedPercent, 65);
  assert.equal(evidence.primary.windowMinutes, 10080);
  assert.equal(evidence.credits.hasCredits, true);
  assert.equal(evidence.credits.unlimited, false);
  assert.equal(evidence.upstreamRequestId, "req_test_123");
});

test("breakdown percentages always use the logical sample total", () => {
  const samples = [
    classified(0, "pro", "Pro", 12),
    classified(1, "plus", "Plus", 18),
    { index: 2, status: "unknown", attempts: 1, latencyMs: 8 },
    { index: 3, status: "failed", attempts: 5, latencyMs: 22 },
    { index: 4, status: "queued", attempts: 0 },
  ];
  const breakdown = calculateBreakdown(samples, 100);
  assert.equal(breakdown.completed, 4);
  assert.equal(breakdown.pending, 96);
  assert.equal(breakdown.plans.find((plan) => plan.key === "pro").percent, 1);
  assert.equal(breakdown.unknownPercent, 1);
  assert.equal(breakdown.failedPercent, 1);
  assert.equal(breakdown.attempts, 8);
  assert.equal(breakdown.averageLatencyMs, 15);
});

test("model choice prefers a low-cost Codex-compatible model", () => {
  const choice = chooseModel([
    "gpt-image-1",
    "gpt-5.4",
    "gpt-5.3-codex",
    "gpt-5.4-mini",
  ]);
  assert.equal(choice.selected, "gpt-5.4-mini");
  assert.equal(choice.source, "models_endpoint");
});

test("analyzer observes concurrency and classifies every logical sample", async () => {
  let active = 0;
  let maxActive = 0;
  let postCount = 0;
  const fetchImpl = async (url, options = {}) => {
    if (String(url).endsWith("/models")) {
      return Response.json({ data: [{ id: "gpt-5.4-mini" }] });
    }

    postCount += 1;
    active += 1;
    maxActive = Math.max(maxActive, active);
    const body = JSON.parse(options.body);
    const index = sampleIndex(body.prompt_cache_key);
    await new Promise((resolve) => setTimeout(resolve, 3));
    active -= 1;

    const tier =
      index < 8 ? "pro" : index < 14 ? "plus" : index < 18 ? "free" : null;
    const headers = new Headers({
      "x-request-id": `req_${index}`,
      "x-codex-primary-used-percent": String(index),
    });
    if (tier) headers.set("x-codex-plan-type", tier);
    return Response.json({ output: [] }, { headers });
  };

  const state = await analyzeSubscriptionPool({
    baseUrl: "https://gateway.example",
    apiKey: "sk-test",
    fetchImpl,
    config: {
      totalRequests: 20,
      concurrency: 5,
      maxAttempts: 3,
      retryMinMs: 1,
      retryMaxMs: 2,
      requestTimeoutMs: 5_000,
    },
    jobSeed: "01234567-89ab-4def-8123-456789abcdef",
  });

  assert.equal(state.status, "completed");
  assert.equal(postCount, 20);
  assert.ok(maxActive <= 5, `max active was ${maxActive}`);
  assert.equal(state.breakdown.completed, 20);
  assert.equal(state.breakdown.classified, 18);
  assert.equal(state.breakdown.unknown, 2);
  assert.equal(state.breakdown.plans.find((plan) => plan.key === "pro").count, 8);
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "plus").count,
    6,
  );
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "free").count,
    4,
  );
});

test("retryable failures wait 1–3 seconds and reuse one logical sample", async () => {
  const attempts = new Map();
  const waits = [];
  const fetchImpl = async (url, options = {}) => {
    if (String(url).endsWith("/models")) {
      return Response.json({ data: [{ id: "gpt-5.4-mini" }] });
    }
    const body = JSON.parse(options.body);
    const index = sampleIndex(body.prompt_cache_key);
    const attempt = (attempts.get(index) || 0) + 1;
    attempts.set(index, attempt);
    if (attempt === 1) {
      return Response.json(
        { error: { message: "temporary overload" } },
        { status: 503 },
      );
    }
    return Response.json(
      { output: [] },
      { headers: { "x-codex-plan-type": index % 2 ? "plus" : "pro" } },
    );
  };

  const state = await analyzeSubscriptionPool({
    baseUrl: "https://gateway.example/v1",
    apiKey: "sk-test",
    fetchImpl,
    random: () => 0.5,
    sleep: async (ms) => waits.push(ms),
    config: {
      totalRequests: 4,
      concurrency: 2,
      maxAttempts: 5,
      retryMinMs: 1_000,
      retryMaxMs: 3_000,
      requestTimeoutMs: 5_000,
    },
    jobSeed: "01234567-89ab-4def-8123-456789abcdef",
  });

  assert.equal(state.breakdown.completed, 4);
  assert.equal(state.breakdown.attempts, 8);
  assert.deepEqual([...attempts.values()], [2, 2, 2, 2]);
  assert.equal(waits.length, 4);
  assert.ok(waits.every((wait) => wait >= 1_000 && wait <= 3_000));
});

function classified(index, key, label, latencyMs) {
  return {
    index,
    status: "classified",
    attempts: 1,
    plan: { key, label, known: true },
    latencyMs,
  };
}

function sampleIndex(cacheKey) {
  const match = String(cacheKey).match(/^plan-probe-(\d+)-/);
  assert.ok(match, `unexpected cache key: ${cacheKey}`);
  return Number(match[1]);
}
