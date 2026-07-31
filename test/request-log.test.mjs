import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildRequestLogRecord,
  RequestLogStore,
} from "../src/request-log.mjs";

test("request log records exclude query strings and unlisted input", () => {
  const secret = "sk-request-log-secret-value";
  const record = buildRequestLogRecord({
    requestId: "request-id-0001",
    occurredAt: "2026-07-31T03:00:00.000Z",
    method: "POST",
    path: `/api/models?api_key=${secret}`,
    statusCode: 401,
    durationMs: 132,
    clientHash: "client_hash_001",
    deviceHash: "device_hash_001",
    errorCode: "unauthorized",
    headers: { authorization: `Bearer ${secret}` },
    body: JSON.stringify({ apiKey: secret }),
  });
  const serialized = JSON.stringify(record);

  assert.equal(record.path, "/api/models");
  assert.equal(record.statusCode, 401);
  assert.equal(record.clientHash, "client_hash_001");
  assert.equal(record.deviceHash, "device_hash_001");
  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /authorization|apiKey|headers|body/);
});

test("upstream logs keep every stream event but redact credentials", () => {
  const secret = "sk-upstream-log-secret-value";
  const record = buildRequestLogRecord({
    scope: "upstream",
    requestId: "request-id-0003",
    jobId: "01234567-89ab-4def-8123-456789abcdef",
    occurredAt: "2026-07-31T03:00:00.000Z",
    method: "POST",
    path: "/v1/responses",
    statusCode: 401,
    upstreamStatus: 401,
    durationMs: 132,
    errorCode: "http_401",
    errorMessage: `Invalid credential ${secret}`,
    domain: "gateway.example",
    model: "gpt-5.5",
    sampleIndex: 1,
    attempt: 1,
    requestSummary: {
      method: "POST",
      endpoint: "https://gateway.example/v1/responses?secret=ignored",
      protocol: "OpenAI Responses",
      headers: {
        accept: "text/event-stream",
        contentType: "application/json",
        authorization: `Bearer ${secret}`,
      },
      body: {
        model: "gpt-5.5",
        input: [
          {
            role: "user",
            content: [{ type: "input_text", text: "Reply exactly OK." }],
          },
        ],
        reasoning: { effort: "none" },
        max_output_tokens: 16,
        store: false,
        stream: true,
        prompt_cache_key: "plan-probe-0-test",
        apiKey: secret,
      },
    },
    responseDetail: {
      status: 401,
      contentType: "application/json",
      requestId: "upstream_req_001",
      body: JSON.stringify({
        error: {
          message: `Bearer ${secret}`,
          api_key: secret,
          access_token: "opaque-credential-value",
        },
      }),
    },
    streamTrace: {
      attempt: 1,
      occurredAt: "2026-07-31T03:00:00.000Z",
      latencyMs: 132,
      status: 401,
      contentType: "text/event-stream",
      requestId: "upstream_req_001",
      transport: "sse",
      terminalEvent: "response.failed",
      eventCount: 2,
      recordCount: 2,
      bodyBytes: 488,
      records: [
        {
          index: 1,
          event: "response.created",
          type: "response.created",
          data: {
            type: "response.created",
            response: { status: "in_progress" },
          },
        },
        {
          index: 2,
          event: "response.failed",
          type: "response.failed",
          data: {
            type: "response.failed",
            message: `Bearer ${secret}`,
            api_key: secret,
            metadata: {
              access_token: "opaque-credential-value",
              safe: "retained",
              [secret]: "dynamic secret field name",
            },
          },
        },
      ],
    },
  });
  const serialized = JSON.stringify(record);

  assert.equal(record.scope, "upstream");
  assert.equal(record.domain, "gateway.example");
  assert.equal(record.requestSummary.endpoint.includes("?"), false);
  assert.equal(record.requestSummary.body.apiKey, undefined);
  assert.equal(record.responseDetail.status, 401);
  assert.match(record.responseDetail.body, /\[REDACTED\]/);
  assert.equal(
    JSON.parse(record.responseDetail.body).error.access_token,
    "[REDACTED]",
  );
  assert.equal(record.streamTrace.records.length, 2);
  assert.equal(
    record.streamTrace.records[1].data.metadata.safe,
    "retained",
  );
  assert.equal(
    record.streamTrace.records[1].data.message,
    "Bearer [REDACTED]",
  );
  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /Bearer sk-/);
  assert.doesNotMatch(
    serialized,
    /"authorization"|"api_key"|"access_token"/i,
  );
});

test("request log lists omit event payloads and detail reads keep them", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "planscope-request-log-detail-"),
  );
  const filePath = join(directory, "request-log.ndjson");

  try {
    const store = await new RequestLogStore({
      filePath,
      maxRecords: 100,
    }).init();
    await store.record({
      scope: "upstream",
      requestId: "request-id-stream-0001",
      occurredAt: new Date().toISOString(),
      method: "POST",
      path: "/v1/responses",
      statusCode: 200,
      upstreamStatus: 200,
      durationMs: 42,
      domain: "gateway.example",
      model: "gpt-5.5",
      sampleIndex: 1,
      attempt: 1,
      outcome: "classified",
      plan: "Pro",
      streamTrace: {
        attempt: 1,
        occurredAt: new Date().toISOString(),
        latencyMs: 42,
        status: 200,
        transport: "sse",
        terminalEvent: "response.completed",
        eventCount: 2,
        recordCount: 2,
        bodyBytes: 256,
        records: [
          {
            index: 1,
            event: "response.created",
            type: "response.created",
            data: { type: "response.created" },
          },
          {
            index: 2,
            event: "response.completed",
            type: "response.completed",
            data: {
              type: "response.completed",
              response: { status: "completed" },
            },
          },
        ],
      },
    });

    const summary = store.list().records[0];
    assert.equal(summary.streamTrace.recordCount, 2);
    assert.deepEqual(summary.streamTrace.records, []);

    const detail = store.get("request-id-stream-0001");
    assert.equal(detail.streamTrace.records.length, 2);
    assert.equal(
      detail.streamTrace.records[1].type,
      "response.completed",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("request logs expire after 24 hours and persist with restricted permissions", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "planscope-request-log-"),
  );
  const filePath = join(directory, "request-log.ndjson");
  let now = Date.parse("2026-07-31T00:00:00.000Z");

  try {
    const store = await new RequestLogStore({
      filePath,
      maxRecords: 100,
      retentionMs: 24 * 60 * 60 * 1_000,
      now: () => now,
    }).init();
    await store.record({
      requestId: "request-id-0001",
      method: "GET",
      path: "/api/health",
      statusCode: 200,
      durationMs: 8,
      clientHash: "client_hash_001",
    });

    now += 23 * 60 * 60 * 1_000;
    await store.record({
      requestId: "request-id-0002",
      method: "POST",
      path: "/api/models",
      statusCode: 429,
      durationMs: 24,
      clientHash: "client_hash_002",
      errorCode: "rate_limited",
    });
    await store.record({
      scope: "upstream",
      requestId: "request-id-0003",
      jobId: "01234567-89ab-4def-8123-456789abcdef",
      method: "POST",
      path: "/v1/responses",
      statusCode: 503,
      upstreamStatus: 503,
      durationMs: 31,
      domain: "gateway.example",
      model: "gpt-5.5",
      sampleIndex: 1,
      attempt: 1,
      errorCode: "http_503",
      errorMessage: "temporary overload",
      responseDetail: {
        status: 503,
        contentType: "application/json",
        requestId: "upstream_req_503",
        body: '{"error":{"message":"temporary overload"}}',
      },
    });

    const beforeExpiry = store.list({
      statusGroup: "4xx",
      method: "POST",
    });
    assert.equal(beforeExpiry.totalStored, 3);
    assert.equal(beforeExpiry.total, 1);
    assert.equal(beforeExpiry.records[0].path, "/api/models");
    assert.equal(beforeExpiry.stats.success, 1);
    assert.equal(beforeExpiry.stats.clientError, 1);
    assert.equal(beforeExpiry.stats.serverError, 1);
    assert.equal(beforeExpiry.retentionSeconds, 86_400);

    now += 2 * 60 * 60 * 1_000;
    assert.equal(await store.purgeExpired(), true);
    const afterExpiry = store.list();
    assert.equal(afterExpiry.total, 2);
    assert.equal(afterExpiry.records[0].requestId, "request-id-0003");
    assert.equal(afterExpiry.records[0].responseDetail.status, 503);
    assert.equal((await stat(filePath)).mode & 0o777, 0o600);

    const stored = await readFile(filePath, "utf8");
    assert.doesNotMatch(stored, /request-id-0001/);
    assert.match(stored, /request-id-0002/);
    assert.match(stored, /upstream_req_503/);

    const reloaded = await new RequestLogStore({
      filePath,
      maxRecords: 100,
      retentionMs: 24 * 60 * 60 * 1_000,
      now: () => now,
    }).init();
    assert.equal(reloaded.list().total, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("request log byte capacity compacts the on-disk file immediately", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "planscope-request-log-capacity-"),
  );
  const filePath = join(directory, "request-log.ndjson");
  const largeData = "x".repeat(420_000);

  try {
    const store = await new RequestLogStore({
      filePath,
      maxRecords: 100,
      maxBytes: 1 * 1_024 * 1_024,
    }).init();
    for (let index = 1; index <= 3; index += 1) {
      await store.record({
        scope: "upstream",
        requestId: `capacity-request-000${index}`,
        occurredAt: new Date(Date.now() + index).toISOString(),
        method: "POST",
        path: "/v1/responses",
        statusCode: 200,
        durationMs: 10,
        domain: "gateway.example",
        model: "gpt-5.5",
        sampleIndex: index,
        attempt: 1,
        streamTrace: {
          eventCount: 1,
          recordCount: 1,
          records: [
            {
              index: 1,
              event: "response.completed",
              type: "response.completed",
              data: {
                type: "response.completed",
                payload: largeData,
              },
            },
          ],
        },
      });
    }

    const inMemory = store.list({ limit: 100 });
    assert.equal(inMemory.totalStored, 2);
    assert.equal(
      inMemory.records.some(
        (record) => record.requestId === "capacity-request-0001",
      ),
      false,
    );

    const stored = await readFile(filePath, "utf8");
    assert.doesNotMatch(stored, /capacity-request-0001/);
    assert.match(stored, /capacity-request-0002/);
    assert.match(stored, /capacity-request-0003/);
    assert.ok(Buffer.byteLength(stored) <= 1 * 1_024 * 1_024);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
