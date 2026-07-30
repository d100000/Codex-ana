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

    const beforeExpiry = store.list({
      statusGroup: "4xx",
      method: "POST",
    });
    assert.equal(beforeExpiry.totalStored, 2);
    assert.equal(beforeExpiry.total, 1);
    assert.equal(beforeExpiry.records[0].path, "/api/models");
    assert.equal(beforeExpiry.stats.success, 1);
    assert.equal(beforeExpiry.stats.clientError, 1);
    assert.equal(beforeExpiry.retentionSeconds, 86_400);

    now += 2 * 60 * 60 * 1_000;
    assert.equal(await store.purgeExpired(), true);
    const afterExpiry = store.list();
    assert.equal(afterExpiry.total, 1);
    assert.equal(afterExpiry.records[0].requestId, "request-id-0002");
    assert.equal((await stat(filePath)).mode & 0o777, 0o600);

    const stored = await readFile(filePath, "utf8");
    assert.doesNotMatch(stored, /request-id-0001/);
    assert.match(stored, /request-id-0002/);

    const reloaded = await new RequestLogStore({
      filePath,
      maxRecords: 100,
      retentionMs: 24 * 60 * 60 * 1_000,
      now: () => now,
    }).init();
    assert.equal(reloaded.list().total, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
