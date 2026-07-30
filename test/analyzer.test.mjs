import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeSubscriptionPool,
  calculateBreakdown,
  chooseModel,
  extractCodexEvidence,
  extractPlanFromResponse,
  fastestReasoningEffort,
  listAvailableModels,
  normalizePlan,
  readResponsesPayload,
  resolveApiEndpoints,
  validateApiKey,
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
  assert.throws(
    () => resolveApiEndpoints(`https://gateway.example/${"a".repeat(2_100)}`),
    /长度/,
  );
  assert.throws(
    () =>
      resolveApiEndpoints("https://gateway.example/sk-secret/v1", {
        secret: "sk-secret",
      }),
    /不能包含 API Key/,
  );
});

test("API keys reject control characters and oversized input", () => {
  assert.equal(validateApiKey("  sk-test  "), "sk-test");
  assert.throws(
    () => validateApiKey("sk-test\nInjected: value"),
    /格式无效/,
  );
  assert.throws(() => validateApiKey("sk-测试"), /格式无效/);
  assert.throws(
    () => validateApiKey("x".repeat(4_097)),
    /长度/,
  );
});

test("plan normalization accepts known and previously unseen tier values", () => {
  assert.deepEqual(normalizePlan(" PRO "), {
    key: "pro",
    label: "Pro",
  });
  assert.deepEqual(normalizePlan("partner-ultra"), {
    key: "partner_ultra",
    label: "Partner Ultra",
  });
  assert.deepEqual(normalizePlan("k12"), {
    key: "k12",
    label: "K12",
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

test("Responses SSE is parsed across chunks until response.completed", async () => {
  const response = chunkedSseResponse([
    ": keep-alive\r\n\r\n",
    "event: response.created\r\n",
    'data: {"type":"response.created","response":{"status":"in_progress"}}\r\n\r\n',
    "event: response.output_text.delta\r\n",
    'data: {"type":"response.output_text.delta","delta":"OK"}\r\n\r\n',
    "event: response.completed\r\n",
    'data: {"type":"response.completed",\r\n',
    'data: "response":{"status":"completed","rate_limits":{"plan_type":"education_k12"}}}\r\n\r\n',
  ]);

  const result = await readResponsesPayload(response);
  assert.equal(result.transport, "sse");
  assert.equal(result.terminalEvent, "response.completed");
  assert.equal(result.eventCount, 3);
  assert.equal(result.payload.rate_limits.plan_type, "education_k12");

  const plan = extractPlanFromResponse(response.headers, result.payload);
  assert.equal(plan.normalized.key, "education_k12");
});

test("Responses SSE error events are redacted and retryable", async () => {
  const secret = "sk-sensitive-stream-value";
  const response = chunkedSseResponse([
    "event: error\n",
    `data: ${JSON.stringify({
      type: "error",
      code: "server_error",
      message: `temporary failure for ${secret}`,
    })}\n\n`,
  ]);

  await assert.rejects(
    readResponsesPayload(response, { secrets: [secret] }),
    (error) =>
      error?.code === "responses_stream_error" &&
      error.retryable === true &&
      error.message.includes("[REDACTED]") &&
      !error.message.includes(secret),
  );
});

test("truncated Responses SSE is rejected instead of counted as unknown", async () => {
  const response = chunkedSseResponse([
    "event: response.created\n",
    'data: {"type":"response.created","response":{"status":"in_progress"}}\n\n',
  ]);

  await assert.rejects(
    readResponsesPayload(response),
    (error) =>
      error?.code === "incomplete_responses_stream" &&
      error.retryable === true,
  );
});

test("untrusted tier values are sanitized and bounded", () => {
  const result = extractPlanFromResponse(
    new Headers(),
    {
      plan_type: `partner\n${"x".repeat(300)}`,
    },
  );
  assert.equal(result.raw.includes("\n"), false);
  assert.equal(result.raw.length, 128);
  assert.equal(
    extractPlanFromResponse(new Headers(), {
      plan_type: { nested: "pro" },
    }),
    null,
  );
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

test("model choice defaults to GPT-5.5 when it is available", () => {
  const choice = chooseModel([
    "gpt-image-1",
    "gpt-5.4",
    "gpt-5.5",
    "gpt-5.3-codex",
    "gpt-5.4-mini",
    "gpt-5.3-codex-spark",
  ]);
  assert.equal(choice.selected, "gpt-5.5");
  assert.equal(choice.source, "models_endpoint");
});

test("model choice falls back to GPT-5.4 before model variants", () => {
  const choice = chooseModel([
    "gpt-5.4-mini",
    "gpt-5.3-codex-spark",
    "gpt-5.4",
  ]);
  assert.equal(choice.selected, "gpt-5.4");
});

test("model discovery returns selectable IDs and its recommendation", async () => {
  const result = await listAvailableModels({
    baseUrl: "https://gateway.example",
    apiKey: "sk-test",
    fetchImpl: async (url, options) => {
      assert.equal(String(url), "https://gateway.example/v1/models");
      assert.equal(options.method, "GET");
      assert.equal(options.headers.Authorization, "Bearer sk-test");
      return Response.json({
        data: [
          { id: "gpt-5.4-mini" },
          { id: "gpt-5.4" },
          { id: "gpt-5.5" },
        ],
      });
    },
  });

  assert.equal(result.target, "https://gateway.example/v1");
  assert.equal(result.selected, "gpt-5.5");
  assert.deepEqual(result.models, [
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.4-mini",
  ]);
  assert.equal(result.source, "models_endpoint");
});

test("model discovery caps untrusted response size", async () => {
  await assert.rejects(
    listAvailableModels({
      baseUrl: "https://gateway.example",
      apiKey: "sk-test",
      fetchImpl: async () =>
        new Response("x".repeat(513 * 1_024), {
          headers: { "Content-Type": "application/json" },
        }),
    }),
    (error) => error?.code === "upstream_response_too_large",
  );
});

test("upstream errors cannot echo API keys into results", async () => {
  const apiKey = "sk-sensitive-test-value";
  await assert.rejects(
    listAvailableModels({
      baseUrl: "https://gateway.example",
      apiKey,
      fetchImpl: async () =>
        Response.json(
          {
            error: {
              message: `credential ${apiKey} was rejected`,
            },
          },
          { status: 401 },
        ),
    }),
    (error) =>
      error?.code === "invalid_credentials" &&
      !error.message.includes(apiKey) &&
      error.message.includes("[REDACTED]"),
  );
});

test("successful upstream metadata cannot echo API keys into snapshots", async () => {
  const apiKey = "sk-sensitive-success-value";
  const state = await analyzeSubscriptionPool({
    baseUrl: "https://gateway.example",
    apiKey,
    model: "gpt-5.5",
    fetchImpl: async (url) => {
      if (String(url).endsWith("/models")) {
        return Response.json({ data: [{ id: "gpt-5.5" }] });
      }
      return Response.json(
        { output: [] },
        {
          headers: {
            "x-codex-plan-type": apiKey,
            "x-request-id": `request-${apiKey}`,
          },
        },
      );
    },
    config: {
      totalRequests: 1,
      concurrency: 1,
      maxAttempts: 1,
      retryMinMs: 1,
      retryMaxMs: 1,
      requestTimeoutMs: 5_000,
    },
  });

  assert.equal(state.samples[0].status, "unknown");
  assert.equal(
    state.samples[0].evidence.upstreamRequestId,
    "request-[REDACTED]",
  );
  assert.equal(JSON.stringify(state).includes(apiKey), false);
});

test("reasoning effort uses the fastest compatible level", () => {
  assert.equal(fastestReasoningEffort("gpt-5.4-mini"), "none");
  assert.equal(fastestReasoningEffort("gpt-5.6-luna"), "none");
  assert.equal(fastestReasoningEffort("gpt-5"), "minimal");
  assert.equal(fastestReasoningEffort("gpt-5.3-codex-spark"), "low");
  assert.equal(fastestReasoningEffort("custom-codex"), "low");
});

test("analyzer observes concurrency and classifies arbitrary tier values", async () => {
  let active = 0;
  let maxActive = 0;
  let postCount = 0;
  const requestBodies = [];
  const fetchImpl = async (url, options = {}) => {
    if (String(url).endsWith("/models")) {
      return Response.json({ data: [{ id: "gpt-5.4-mini" }] });
    }

    postCount += 1;
    active += 1;
    maxActive = Math.max(maxActive, active);
    const body = JSON.parse(options.body);
    requestBodies.push(body);
    assert.equal(options.headers.Accept, "text/event-stream");
    assert.equal(options.streamResponse, true);
    const index = sampleIndex(body.prompt_cache_key);
    await new Promise((resolve) => setTimeout(resolve, 3));
    active -= 1;

    const tier =
      index < 6
        ? "pro"
        : index < 10
          ? "plus"
          : index < 14
            ? "team"
            : index < 18
              ? "k12"
              : index === 18
                ? "partner_alpha"
                : null;
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
    model: "gpt-5.4-mini",
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
  assert.equal(state.selectedModel, "gpt-5.4-mini");
  assert.equal(state.modelSource, "user_selected");
  assert.equal(postCount, 20);
  assert.ok(maxActive <= 5, `max active was ${maxActive}`);
  assert.equal(state.breakdown.completed, 20);
  assert.equal(state.breakdown.classified, 19);
  assert.equal(state.breakdown.unknown, 1);
  assert.equal(state.breakdown.plans.length, 5);
  assert.equal(state.breakdown.plans.find((plan) => plan.key === "pro").count, 6);
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "plus").count,
    4,
  );
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "team").count,
    4,
  );
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "k12").label,
    "K12",
  );
  assert.equal(
    state.breakdown.plans.find((plan) => plan.key === "partner_alpha").count,
    1,
  );

  const probe = requestBodies[0];
  assert.equal(probe.input[0].content[0].text, "Reply exactly OK.");
  assert.equal(probe.reasoning.effort, "none");
  assert.equal(probe.max_output_tokens, 16);
  assert.equal(probe.store, false);
  assert.equal(probe.stream, true);
  assert.equal(Object.hasOwn(probe, "instructions"), false);
  assert.equal(Object.hasOwn(probe, "tools"), false);
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
    model: "gpt-5.4-mini",
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

test("analyzer rejects a stale model selection before sampling", async () => {
  let posts = 0;
  await assert.rejects(
    analyzeSubscriptionPool({
      baseUrl: "https://gateway.example",
      apiKey: "sk-test",
      model: "gpt-5.5",
      fetchImpl: async (url) => {
        if (String(url).endsWith("/models")) {
          return Response.json({ data: [{ id: "gpt-5.4" }] });
        }
        posts += 1;
        return Response.json({ output: [] });
      },
      config: {
        totalRequests: 1,
        concurrency: 1,
        maxAttempts: 1,
        retryMinMs: 1,
        retryMaxMs: 1,
        requestTimeoutMs: 5_000,
      },
    }),
    (error) => error?.code === "model_not_available",
  );
  assert.equal(posts, 0);
});

test("analyzer rejects an API key copied into the model field", async () => {
  await assert.rejects(
    analyzeSubscriptionPool({
      baseUrl: "https://gateway.example",
      apiKey: "sk-secret-model-value",
      model: "prefix-sk-secret-model-value",
      fetchImpl: async () => {
        throw new Error("network should not run");
      },
    }),
    (error) => error?.code === "secret_in_model",
  );
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

function chunkedSseResponse(parts) {
  const encoder = new TextEncoder();
  const chunks = parts.flatMap((part) => {
    const bytes = encoder.encode(part);
    const middle = Math.max(1, Math.floor(bytes.byteLength / 2));
    return [
      bytes.slice(0, middle),
      bytes.slice(middle),
    ].filter((chunk) => chunk.byteLength > 0);
  });
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    }),
    {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
      },
    },
  );
}
