import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";

const HISTORY_SCHEMA_VERSION = 1;
const TERMINAL_STATUSES = new Set([
  "completed",
  "failed",
  "cancelled",
]);

export class AdminHistoryError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "AdminHistoryError";
    this.code = options.code ?? "admin_history_error";
    this.cause = options.cause;
  }
}

export class AdminHistoryStore {
  constructor(options = {}) {
    if (!options.filePath) {
      throw new TypeError("历史记录文件路径不能为空。");
    }
    this.filePath = options.filePath;
    this.maxRecords = clampInteger(
      options.maxRecords,
      100,
      20_000,
      5_000,
    );
    this.records = [];
    this.writeQueue = Promise.resolve();
    this.initialized = false;
  }

  async init() {
    await mkdir(dirname(this.filePath), {
      recursive: true,
      mode: 0o700,
    });

    try {
      const source = await readFile(this.filePath, "utf8");
      const payload = JSON.parse(source);
      if (
        payload?.version !== HISTORY_SCHEMA_VERSION ||
        !Array.isArray(payload?.records)
      ) {
        throw new Error("history schema mismatch");
      }
      this.records = payload.records
        .map(sanitizeStoredRecord)
        .filter(Boolean)
        .slice(0, this.maxRecords);
      await chmod(this.filePath, 0o600);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw new AdminHistoryError(
          "分析历史文件无法读取，请检查或备份后修复该文件。",
          {
            code: "history_file_invalid",
            cause: error,
          },
        );
      }
      this.records = [];
      await this.persist();
    }

    this.initialized = true;
    return this;
  }

  async record(job) {
    this.assertInitialized();
    const entry = buildHistoryRecord(job);
    this.records.unshift(entry);
    if (this.records.length > this.maxRecords) {
      this.records.length = this.maxRecords;
    }

    this.writeQueue = this.writeQueue
      .catch(() => undefined)
      .then(() => this.persist());
    await this.writeQueue;
    return structuredClone(entry);
  }

  list(options = {}) {
    this.assertInitialized();
    const offset = clampInteger(
      options.offset,
      0,
      this.maxRecords,
      0,
    );
    const limit = clampInteger(options.limit, 1, 100, 50);
    const query = cleanText(options.query, 120).toLowerCase();
    const status = TERMINAL_STATUSES.has(options.status)
      ? options.status
      : "";
    const filtered = this.records.filter((record) => {
      if (status && record.status !== status) return false;
      if (
        query &&
        !record.domain.toLowerCase().includes(query) &&
        !record.model.toLowerCase().includes(query)
      ) {
        return false;
      }
      return true;
    });
    const records = filtered.slice(offset, offset + limit);

    return {
      records: structuredClone(records),
      total: filtered.length,
      totalStored: this.records.length,
      nextOffset:
        offset + records.length < filtered.length
          ? offset + records.length
          : null,
      stats: calculateHistoryStats(this.records),
    };
  }

  assertInitialized() {
    if (this.initialized) return;
    throw new AdminHistoryError("分析历史存储尚未初始化。", {
      code: "history_not_initialized",
    });
  }

  async persist() {
    const payload = JSON.stringify({
      version: HISTORY_SCHEMA_VERSION,
      records: this.records,
    });
    const temporaryPath = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, `${payload}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      await rename(temporaryPath, this.filePath);
      await chmod(this.filePath, 0o600);
    } catch (error) {
      throw new AdminHistoryError("分析历史写入失败。", {
        code: "history_write_failed",
        cause: error,
      });
    } finally {
      await rm(temporaryPath, { force: true }).catch(
        () => undefined,
      );
    }
  }
}

export function buildHistoryRecord(job) {
  const status = TERMINAL_STATUSES.has(job?.status)
    ? job.status
    : "failed";
  const target = safeTarget(job?.safeTarget);
  const state = job?.state ?? {};
  const breakdown = state.breakdown ?? {};
  const total = safeInteger(
    breakdown.total ?? state.config?.totalRequests,
    0,
    10_000,
  );
  const startedAt = safeIsoDate(
    state.startedAt ?? job?.createdAt,
  );
  const completedAt = safeIsoDate(
    state.completedAt ?? job?.updatedAt,
  );

  return {
    id: randomUUID(),
    recordedAt: new Date().toISOString(),
    createdAt: safeIsoDate(job?.createdAt),
    startedAt,
    completedAt,
    status,
    origin: target.origin,
    domain: target.domain,
    model: cleanText(state.selectedModel, 200) || "—",
    durationMs: calculateDuration(startedAt, completedAt),
    total,
    completed: safeInteger(breakdown.completed, 0, total),
    classified: safeInteger(breakdown.classified, 0, total),
    unknown: safeInteger(breakdown.unknown, 0, total),
    failed: safeInteger(breakdown.failed, 0, total),
    attempts: safeInteger(breakdown.attempts, 0, 100_000),
    successRate: safePercent(breakdown.successRate),
    averageLatencyMs: nullableInteger(
      breakdown.averageLatencyMs,
      0,
      24 * 60 * 60 * 1_000,
    ),
    unknownPercent: safePercent(breakdown.unknownPercent),
    failedPercent: safePercent(breakdown.failedPercent),
    plans: sanitizePlans(breakdown.plans, total),
    errorCode:
      status === "failed"
        ? cleanText(state.error?.code, 100) || "analysis_failed"
        : null,
  };
}

function sanitizeStoredRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    !TERMINAL_STATUSES.has(value.status)
  ) {
    return null;
  }
  const target = safeTarget(value.origin);
  const total = safeInteger(value.total, 0, 10_000);
  return {
    id: /^[a-f0-9-]{16,64}$/i.test(String(value.id ?? ""))
      ? String(value.id)
      : randomUUID(),
    recordedAt: safeIsoDate(value.recordedAt),
    createdAt: safeIsoDate(value.createdAt),
    startedAt: safeIsoDate(value.startedAt),
    completedAt: safeIsoDate(value.completedAt),
    status: value.status,
    origin: target.origin,
    domain: target.domain,
    model: cleanText(value.model, 200) || "—",
    durationMs: nullableInteger(
      value.durationMs,
      0,
      24 * 60 * 60 * 1_000,
    ),
    total,
    completed: safeInteger(value.completed, 0, total),
    classified: safeInteger(value.classified, 0, total),
    unknown: safeInteger(value.unknown, 0, total),
    failed: safeInteger(value.failed, 0, total),
    attempts: safeInteger(value.attempts, 0, 100_000),
    successRate: safePercent(value.successRate),
    averageLatencyMs: nullableInteger(
      value.averageLatencyMs,
      0,
      24 * 60 * 60 * 1_000,
    ),
    unknownPercent: safePercent(value.unknownPercent),
    failedPercent: safePercent(value.failedPercent),
    plans: sanitizePlans(value.plans, total),
    errorCode:
      value.status === "failed"
        ? cleanText(value.errorCode, 100) || "analysis_failed"
        : null,
  };
}

function calculateHistoryStats(records) {
  const domains = new Set();
  let completed = 0;
  let failed = 0;
  let cancelled = 0;
  let recent = 0;
  const recentThreshold = Date.now() - 24 * 60 * 60 * 1_000;

  for (const record of records) {
    domains.add(record.domain);
    if (record.status === "completed") completed += 1;
    if (record.status === "failed") failed += 1;
    if (record.status === "cancelled") cancelled += 1;
    if (Date.parse(record.recordedAt) >= recentThreshold) recent += 1;
  }

  return {
    total: records.length,
    domains: domains.size,
    completed,
    failed,
    cancelled,
    recent24h: recent,
  };
}

function safeTarget(value) {
  try {
    const url = new URL(String(value ?? ""));
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    ) {
      throw new Error("unsafe target");
    }
    return {
      origin: url.origin.slice(0, 512),
      domain: url.host.toLowerCase().slice(0, 255),
    };
  } catch {
    return {
      origin: "unknown://unknown",
      domain: "unknown",
    };
  }
}

function sanitizePlans(plans, total) {
  if (!Array.isArray(plans)) return [];
  return plans.slice(0, 100).map((plan, index) => ({
    key:
      cleanText(plan?.key, 128) ||
      `tier_${String(index + 1).padStart(2, "0")}`,
    label:
      cleanText(plan?.label, 128) ||
      `Tier ${index + 1}`,
    count: safeInteger(plan?.count, 0, total),
    percent: safePercent(plan?.percent),
  }));
}

function cleanText(value, maxLength) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, maxLength);
}

function safePercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.round(Math.min(100, Math.max(0, number)) * 10) / 10;
}

function safeInteger(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

function nullableInteger(value, min, max) {
  if (value === null || value === undefined) return null;
  return safeInteger(value, min, max);
}

function safeIsoDate(value) {
  const timestamp = Date.parse(String(value ?? ""));
  return Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString()
    : null;
}

function calculateDuration(startedAt, completedAt) {
  if (!startedAt || !completedAt) return null;
  return nullableInteger(
    Date.parse(completedAt) - Date.parse(startedAt),
    0,
    24 * 60 * 60 * 1_000,
  );
}

function clampInteger(value, min, max, fallback) {
  const number = Number(value);
  return Number.isInteger(number) && number >= min && number <= max
    ? number
    : fallback;
}
