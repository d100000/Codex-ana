import {
  appendFile,
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import {
  createDiagnosticExcerpt,
  sanitizeDiagnosticText,
} from "./redaction.mjs";

const REQUEST_LOG_SCHEMA_VERSION = 1;
export const REQUEST_LOG_RETENTION_MS = 24 * 60 * 60 * 1_000;
export const REQUEST_LOG_CLEANUP_INTERVAL_MS = 5 * 60 * 1_000;
const STATUS_GROUPS = new Set(["2xx", "3xx", "4xx", "5xx"]);
const METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

export class RequestLogError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "RequestLogError";
    this.code = options.code ?? "request_log_error";
    this.cause = options.cause;
  }
}

export class RequestLogStore {
  constructor(options = {}) {
    if (!options.filePath) {
      throw new TypeError("请求日志文件路径不能为空。");
    }
    this.filePath = options.filePath;
    this.maxRecords = clampInteger(
      options.maxRecords,
      100,
      100_000,
      20_000,
    );
    this.retentionMs = clampInteger(
      options.retentionMs,
      1_000,
      7 * 24 * 60 * 60 * 1_000,
      REQUEST_LOG_RETENTION_MS,
    );
    this.now = typeof options.now === "function"
      ? options.now
      : () => Date.now();
    this.records = [];
    this.writeQueue = Promise.resolve();
    this.needsCompaction = false;
    this.initialized = false;
  }

  async init() {
    await mkdir(dirname(this.filePath), {
      recursive: true,
      mode: 0o700,
    });

    try {
      const source = await readFile(this.filePath, "utf8");
      const cutoff = this.now() - this.retentionMs;
      this.records = source
        .split("\n")
        .filter(Boolean)
        .map(parseStoredRecord)
        .filter(
          (record) =>
            record && Date.parse(record.occurredAt) >= cutoff,
        )
        .slice(-this.maxRecords)
        .reverse();
      await this.persistSnapshot(this.records);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw new RequestLogError(
          "请求日志文件无法读取，请检查或备份后修复该文件。",
          {
            code: "request_log_file_invalid",
            cause: error,
          },
        );
      }
      this.records = [];
      await this.persistSnapshot(this.records);
    }

    this.initialized = true;
    return this;
  }

  async record(value) {
    this.assertInitialized();
    const entry = buildRequestLogRecord(value, {
      now: this.now,
    });
    if (this.pruneInMemory(this.now())) {
      this.needsCompaction = true;
    }
    this.records.unshift(entry);
    if (this.records.length > this.maxRecords) {
      this.records.length = this.maxRecords;
      this.needsCompaction = true;
    }

    const line = `${serializeStoredRecord(entry)}\n`;
    this.writeQueue = this.writeQueue
      .catch(() => undefined)
      .then(async () => {
        await appendFile(this.filePath, line, {
          encoding: "utf8",
          mode: 0o600,
        });
        await chmod(this.filePath, 0o600);
      });
    await this.writeQueue;
    return structuredClone(entry);
  }

  list(options = {}) {
    this.assertInitialized();
    if (this.pruneInMemory(this.now())) {
      this.needsCompaction = true;
      void this.compact().catch(() => undefined);
    }

    const offset = clampInteger(
      options.offset,
      0,
      this.maxRecords,
      0,
    );
    const limit = clampInteger(options.limit, 1, 100, 50);
    const query = cleanText(options.query, 160).toLowerCase();
    const statusGroup = STATUS_GROUPS.has(options.statusGroup)
      ? options.statusGroup
      : "";
    const method = METHODS.has(
      String(options.method ?? "").toUpperCase(),
    )
      ? String(options.method).toUpperCase()
      : "";
    const filtered = this.records.filter((record) => {
      if (
        statusGroup &&
        Math.trunc(record.statusCode / 100) !==
          Number(statusGroup[0])
      ) {
        return false;
      }
      if (method && record.method !== method) return false;
      if (
        query &&
        ![
          record.path,
          record.method,
          record.errorCode,
          record.requestId,
          record.clientHash,
          record.deviceHash,
          record.scope,
          record.jobId,
          record.domain,
          record.model,
          record.errorMessage,
          record.responseDetail?.requestId,
        ].some((value) =>
          String(value ?? "").toLowerCase().includes(query),
        )
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
      retentionSeconds: Math.trunc(this.retentionMs / 1_000),
      stats: calculateRequestStats(this.records),
    };
  }

  async purgeExpired() {
    this.assertInitialized();
    const removed = this.pruneInMemory(this.now());
    if (removed) this.needsCompaction = true;
    if (this.needsCompaction) await this.compact();
    return removed;
  }

  async compact() {
    this.assertInitialized();
    const snapshot = structuredClone(this.records);
    this.needsCompaction = false;
    this.writeQueue = this.writeQueue
      .catch(() => undefined)
      .then(() => this.persistSnapshot(snapshot));
    try {
      await this.writeQueue;
    } catch (error) {
      this.needsCompaction = true;
      throw error;
    }
  }

  async flush() {
    if (!this.initialized) return;
    await this.compact();
  }

  pruneInMemory(now) {
    const cutoff = now - this.retentionMs;
    const before = this.records.length;
    this.records = this.records
      .filter(
        (record) => Date.parse(record.occurredAt) >= cutoff,
      )
      .slice(0, this.maxRecords);
    return this.records.length !== before;
  }

  assertInitialized() {
    if (this.initialized) return;
    throw new RequestLogError("请求日志存储尚未初始化。", {
      code: "request_log_not_initialized",
    });
  }

  async persistSnapshot(records) {
    const payload = records
      .slice()
      .reverse()
      .map(serializeStoredRecord)
      .join("\n");
    const temporaryPath =
      `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(
        temporaryPath,
        payload ? `${payload}\n` : "",
        {
          encoding: "utf8",
          mode: 0o600,
          flag: "wx",
        },
      );
      await rename(temporaryPath, this.filePath);
      await chmod(this.filePath, 0o600);
    } catch (error) {
      throw new RequestLogError("请求日志写入失败。", {
        code: "request_log_write_failed",
        cause: error,
      });
    } finally {
      await rm(temporaryPath, { force: true }).catch(
        () => undefined,
      );
    }
  }
}

export function buildRequestLogRecord(value, options = {}) {
  const now = typeof options.now === "function"
    ? options.now()
    : Date.now();
  const statusCode = clampInteger(
    value?.statusCode,
    100,
    599,
    500,
  );
  const record = {
    requestId: safeIdentifier(value?.requestId) || randomUUID(),
    occurredAt: safeIsoDate(value?.occurredAt, now),
    method: safeMethod(value?.method),
    path: safeRoute(value?.path),
    statusCode,
    durationMs: clampInteger(
      value?.durationMs,
      0,
      7 * 24 * 60 * 60 * 1_000,
      0,
    ),
    clientHash: safeHash(value?.clientHash),
    deviceHash: safeHash(value?.deviceHash),
    errorCode: safeErrorCode(value?.errorCode),
  };
  if (value?.scope !== "upstream") return record;

  return {
    ...record,
    scope: "upstream",
    jobId: safeIdentifier(value?.jobId) || null,
    domain: safeDomain(value?.domain),
    model: cleanText(value?.model, 200) || null,
    sampleIndex: clampInteger(
      value?.sampleIndex,
      1,
      1_000,
      null,
    ),
    attempt: clampInteger(value?.attempt, 1, 10, null),
    upstreamStatus: clampInteger(
      value?.upstreamStatus,
      100,
      599,
      null,
    ),
    requestSummary: sanitizeUpstreamRequestSummary(
      value?.requestSummary,
    ),
    responseDetail: sanitizeUpstreamResponseDetail(
      value?.responseDetail,
    ),
    errorMessage:
      sanitizeDiagnosticText(value?.errorMessage, {
        maxLength: 600,
      }) || null,
  };
}

function parseStoredRecord(line) {
  try {
    const payload = JSON.parse(line);
    if (payload?.v !== REQUEST_LOG_SCHEMA_VERSION) return null;
    return sanitizeStoredRecord(payload.record);
  } catch {
    return null;
  }
}

function sanitizeStoredRecord(value) {
  if (!value || typeof value !== "object") return null;
  const occurredAt = safeIsoDate(value.occurredAt, NaN);
  if (!occurredAt) return null;
  const statusCode = clampInteger(
    value.statusCode,
    100,
    599,
    0,
  );
  if (!statusCode) return null;
  const record = {
    requestId: safeIdentifier(value.requestId) || randomUUID(),
    occurredAt,
    method: safeMethod(value.method),
    path: safeRoute(value.path),
    statusCode,
    durationMs: clampInteger(
      value.durationMs,
      0,
      7 * 24 * 60 * 60 * 1_000,
      0,
    ),
    clientHash: safeHash(value.clientHash),
    deviceHash: safeHash(value.deviceHash),
    errorCode: safeErrorCode(value.errorCode),
  };
  if (value.scope !== "upstream") return record;

  return {
    ...record,
    scope: "upstream",
    jobId: safeIdentifier(value.jobId) || null,
    domain: safeDomain(value.domain),
    model: cleanText(value.model, 200) || null,
    sampleIndex: clampInteger(value.sampleIndex, 1, 1_000, null),
    attempt: clampInteger(value.attempt, 1, 10, null),
    upstreamStatus: clampInteger(
      value.upstreamStatus,
      100,
      599,
      null,
    ),
    requestSummary: sanitizeUpstreamRequestSummary(
      value.requestSummary,
    ),
    responseDetail: sanitizeUpstreamResponseDetail(
      value.responseDetail,
    ),
    errorMessage:
      sanitizeDiagnosticText(value.errorMessage, {
        maxLength: 600,
      }) || null,
  };
}

function serializeStoredRecord(record) {
  return JSON.stringify({
    v: REQUEST_LOG_SCHEMA_VERSION,
    record,
  });
}

function calculateRequestStats(records) {
  let success = 0;
  let redirect = 0;
  let clientError = 0;
  let serverError = 0;
  let totalDurationMs = 0;
  for (const record of records) {
    const group = Math.trunc(record.statusCode / 100);
    if (group === 2) success += 1;
    if (group === 3) redirect += 1;
    if (group === 4) clientError += 1;
    if (group === 5) serverError += 1;
    totalDurationMs += record.durationMs;
  }
  return {
    total: records.length,
    success,
    redirect,
    clientError,
    serverError,
    averageDurationMs:
      records.length > 0
        ? Math.round(totalDurationMs / records.length)
        : null,
  };
}

function safeRoute(value) {
  const route = String(value ?? "")
    .split(/[?#]/, 1)[0]
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  if (
    !route.startsWith("/") ||
    route.startsWith("//") ||
    route.length > 200
  ) {
    return "/[unmatched]";
  }
  return route;
}

function safeMethod(value) {
  const method = String(value ?? "").trim().toUpperCase();
  return METHODS.has(method) ? method : "OTHER";
}

function safeIdentifier(value) {
  const identifier = String(value ?? "").trim();
  return /^[A-Za-z0-9_-]{8,64}$/.test(identifier)
    ? identifier
    : "";
}

function safeHash(value) {
  const hash = String(value ?? "").trim();
  return /^[A-Za-z0-9_-]{8,24}$/.test(hash) ? hash : null;
}

function safeErrorCode(value) {
  const code = cleanText(value, 100);
  return /^[A-Za-z][A-Za-z0-9_]{0,99}$/.test(code)
    ? code
    : null;
}

function safeDomain(value) {
  const domain = String(value ?? "")
    .trim()
    .toLowerCase();
  return (
    domain.length <= 253 &&
    /^(?:\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::\d{1,5})?$/i.test(
      domain,
    )
  )
    ? domain
    : null;
}

export function sanitizeUpstreamRequestSummary(value) {
  if (!value || typeof value !== "object") return null;
  const endpoint = safeEndpoint(value.endpoint);
  const body = value.body && typeof value.body === "object"
    ? {
        model:
          sanitizeDiagnosticText(value.body.model, {
            maxLength: 200,
          }) || null,
        input: sanitizeProbeInput(value.body.input),
        reasoning: {
          effort:
            sanitizeDiagnosticText(
              value.body.reasoning?.effort,
              {
                maxLength: 32,
              },
            ) || null,
        },
        max_output_tokens: clampInteger(
          value.body.max_output_tokens,
          1,
          10_000,
          null,
        ),
        store: value.body.store === true,
        stream: value.body.stream === true,
        prompt_cache_key:
          sanitizeDiagnosticText(value.body.prompt_cache_key, {
            maxLength: 240,
          }) || null,
      }
    : null;

  return {
    method: "POST",
    endpoint,
    protocol:
      sanitizeDiagnosticText(value.protocol, {
        maxLength: 80,
      }) || "OpenAI Responses",
    headers: {
      accept:
        sanitizeDiagnosticText(value.headers?.accept, {
          maxLength: 80,
        }) ||
        "text/event-stream",
      contentType:
        sanitizeDiagnosticText(value.headers?.contentType, {
          maxLength: 80,
        }) ||
        "application/json",
    },
    body,
  };
}

function sanitizeProbeInput(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 4).map((message) => ({
    role:
      sanitizeDiagnosticText(message?.role, {
        maxLength: 32,
      }) || null,
    content: Array.isArray(message?.content)
      ? message.content.slice(0, 4).map((part) => ({
          type:
            sanitizeDiagnosticText(part?.type, {
              maxLength: 40,
            }) || null,
          text:
            sanitizeDiagnosticText(part?.text, {
              maxLength: 600,
            }) || null,
        }))
      : [],
  }));
}

export function sanitizeUpstreamResponseDetail(value) {
  if (!value || typeof value !== "object") return null;
  const body = createDiagnosticExcerpt(value.body, {
    maxLength: 4_096,
  });
  return {
    status: clampInteger(value.status, 100, 599, null),
    statusText:
      sanitizeDiagnosticText(value.statusText, {
        maxLength: 120,
      }) || null,
    contentType:
      sanitizeDiagnosticText(value.contentType, {
        maxLength: 160,
      }) || null,
    requestId:
      sanitizeDiagnosticText(value.requestId, {
        maxLength: 512,
      }) || null,
    cfRay:
      sanitizeDiagnosticText(value.cfRay, {
        maxLength: 160,
      }) || null,
    retryAfter:
      sanitizeDiagnosticText(value.retryAfter, {
        maxLength: 120,
      }) || null,
    body: body.text || null,
    bodyTruncated: Boolean(value.bodyTruncated || body.truncated),
  };
}

function safeEndpoint(value) {
  try {
    const url = new URL(String(value ?? ""));
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    ) {
      return null;
    }
    url.search = "";
    url.hash = "";
    const endpoint = sanitizeDiagnosticText(url.toString(), {
      maxLength: 2_048,
    });
    return endpoint.length <= 2_048 ? endpoint : null;
  } catch {
    return null;
  }
}

function cleanText(value, maxLength) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, maxLength);
}

function safeIsoDate(value, fallbackTimestamp) {
  const timestamp = Date.parse(String(value ?? ""));
  const selected = Number.isFinite(timestamp)
    ? timestamp
    : fallbackTimestamp;
  return Number.isFinite(selected)
    ? new Date(selected).toISOString()
    : null;
}

function clampInteger(value, min, max, fallback) {
  const number = Number(value);
  return Number.isInteger(number) && number >= min && number <= max
    ? number
    : fallback;
}
