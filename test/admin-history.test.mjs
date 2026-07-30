import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AdminHistoryStore,
  buildHistoryRecord,
} from "../src/admin-history.mjs";

test("history records retain only domain-level aggregate data", () => {
  const secret = "sk-history-secret-value";
  const record = buildHistoryRecord(
    createJob({
      safeTarget:
        `https://api.example.com/private/v1?api_key=${secret}`,
      injectedSecret: secret,
    }),
  );
  const serialized = JSON.stringify(record);

  assert.equal(record.origin, "https://api.example.com");
  assert.equal(record.domain, "api.example.com");
  assert.equal(record.model, "gpt-5.5");
  assert.deepEqual(record.plans, [
    {
      key: "team",
      label: "Team",
      count: 61,
      percent: 61,
    },
    {
      key: "k12",
      label: "K12",
      count: 27,
      percent: 27,
    },
  ]);
  assert.equal(record.unknownPercent, 8);
  assert.equal(record.failedPercent, 4);
  assert.doesNotMatch(serialized, /private\/v1/);
  assert.doesNotMatch(serialized, /api_key/);
  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /evidence|samples|apiKey/);
});

test("history store persists, filters, and protects its data file", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "planscope-history-"),
  );
  const filePath = join(directory, "history.json");

  try {
    const store = await new AdminHistoryStore({
      filePath,
      maxRecords: 100,
    }).init();
    await store.record(createJob());
    await store.record(
      createJob({
        status: "failed",
        safeTarget: "https://other.example.net/v1",
        model: "gpt-5.4",
      }),
    );

    const result = store.list({
      query: "example.com",
      status: "completed",
      limit: 20,
    });
    assert.equal(result.total, 1);
    assert.equal(result.records[0].domain, "api.example.com");
    assert.equal(result.stats.total, 2);
    assert.equal(result.stats.domains, 2);
    assert.equal(result.stats.completed, 1);
    assert.equal(result.stats.failed, 1);

    const reloaded = await new AdminHistoryStore({
      filePath,
      maxRecords: 100,
    }).init();
    assert.equal(reloaded.list({ limit: 10 }).records.length, 2);
    assert.equal((await stat(filePath)).mode & 0o777, 0o600);

    const stored = await readFile(filePath, "utf8");
    assert.doesNotMatch(stored, /sk-history-secret-value/);
    assert.doesNotMatch(stored, /apiKey/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function createJob(overrides = {}) {
  const status = overrides.status ?? "completed";
  const completedAt = "2026-07-31T02:01:12.000Z";
  return {
    id: "job-id-that-is-not-persisted",
    status,
    safeTarget:
      overrides.safeTarget ??
      "https://api.example.com/tenant-a/v1",
    createdAt: "2026-07-31T02:00:00.000Z",
    updatedAt: completedAt,
    apiKey: overrides.injectedSecret,
    state: {
      status,
      selectedModel: overrides.model ?? "gpt-5.5",
      startedAt: "2026-07-31T02:00:02.000Z",
      completedAt,
      apiKey: overrides.injectedSecret,
      samples: [
        {
          evidence: {
            echoed: overrides.injectedSecret,
          },
        },
      ],
      error:
        status === "failed"
          ? {
              code: "preflight_sample_failed",
              message: overrides.injectedSecret,
            }
          : null,
      config: { totalRequests: 100 },
      breakdown: {
        total: 100,
        completed: 100,
        classified: 88,
        unknown: 8,
        failed: 4,
        attempts: 104,
        successRate: 96,
        averageLatencyMs: 842,
        unknownPercent: 8,
        failedPercent: 4,
        plans: [
          {
            key: "team",
            label: "Team",
            count: 61,
            percent: 61,
          },
          {
            key: "k12",
            label: "K12",
            count: 27,
            percent: 27,
          },
        ],
      },
    },
  };
}
