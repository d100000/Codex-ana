import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createHmac,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { isIP } from "node:net";
import {
  AbuseProtection,
  DEFAULT_PROTECTION_CONFIG,
} from "./src/abuse-protection.mjs";
import {
  AnalysisError,
  DEFAULT_ANALYSIS_CONFIG,
  analyzeSubscriptionPool,
  calculateBreakdown,
  listAvailableModels,
  resolveApiEndpoints,
  validateApiKey,
  validateRequestedModel,
} from "./src/analyzer.mjs";
import {
  assertEmptyRequest,
  assertJsonRequest,
  createRequestSecurity,
  requestIsSecure,
  securityResponseHeaders,
} from "./src/http-security.mjs";
import { createSafeFetch } from "./src/safe-fetch.mjs";

const ROOT_DIR = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = join(ROOT_DIR, "public");
const HOST = process.env.HOST || "127.0.0.1";
const PORT = readIntegerEnv("PORT", 4317, 1, 65_535);
const TRUST_PROXY = /^(1|true)$/i.test(process.env.TRUST_PROXY ?? "");
const FORWARDED_IP_HEADER = readForwardedIpHeader();
const TRUSTED_PROXY_IPS = new Set([
  "127.0.0.1",
  "::1",
  ...String(process.env.TRUSTED_PROXY_IPS ?? "")
    .split(",")
    .map(normalizeIp)
    .filter(Boolean),
]);
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN ?? "";
const DEVICE_COOKIE = /^https:\/\//i.test(PUBLIC_ORIGIN.trim())
  ? "__Host-planscope_device"
  : "planscope_device";
const DEVICE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;
const MAX_ACTIVE_JOBS = readIntegerEnv("MAX_ACTIVE_JOBS", 2, 1, 20);
const MAX_STORED_JOBS = readIntegerEnv(
  "MAX_STORED_JOBS",
  500,
  10,
  5_000,
);
const MAX_JOB_LISTENERS = readIntegerEnv(
  "MAX_JOB_LISTENERS",
  3,
  1,
  20,
);
const MAX_CONCURRENT_MODEL_LOOKUPS = readIntegerEnv(
  "MAX_CONCURRENT_MODEL_LOOKUPS",
  4,
  1,
  20,
);
const identitySecret = readIdentitySecret();
const abuseProtection = new AbuseProtection();
const requestSecurity = createRequestSecurity({
  bindHost: HOST,
  port: PORT,
  trustProxy: TRUST_PROXY,
  isTrustedProxy: trustedProxyRequest,
  publicOrigin: PUBLIC_ORIGIN,
  allowedHosts: process.env.ALLOWED_HOSTS,
  allowInsecurePublicOrigin: readBooleanEnv(
    "ALLOW_INSECURE_PUBLIC_ORIGIN",
  ),
});
const upstreamFetch = createSafeFetch({
  allowHttp: readBooleanEnv("ALLOW_HTTP_UPSTREAMS"),
  allowPrivateNetworks: readBooleanEnv(
    "ALLOW_PRIVATE_UPSTREAMS",
  ),
  allowedHosts: process.env.ALLOWED_UPSTREAM_HOSTS,
  allowedPorts: process.env.ALLOWED_UPSTREAM_PORTS,
});
const jobs = new Map();
const TERMINAL_JOB_TTL_MS = 60 * 60 * 1_000;
let pendingJobStarts = 0;
let activeModelLookups = 0;

const staticRoutes = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"],
  ["/styles.css", "styles.css"],
  ["/app.js", "app.js"],
]);

class ServiceError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "ServiceError";
    this.code = options.code ?? "service_error";
    this.httpStatus = options.httpStatus ?? 500;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}

const server = createServer(async (request, response) => {
  applySecurityHeaders(request, response);

  try {
    const url = parseRequestUrl(request.url);
    const { pathname } = url;
    requestSecurity(request, pathname);

    if (request.method === "GET" && staticRoutes.has(pathname)) {
      await serveStatic(response, staticRoutes.get(pathname));
      return;
    }

    if (request.method === "GET" && pathname === "/api/health") {
      sendJson(response, 200, {
        ok: true,
        service: "codex-plan-scope",
        config: publicConfig(DEFAULT_ANALYSIS_CONFIG),
        protection: {
          sliderVerification: true,
          cooldownSeconds:
            DEFAULT_PROTECTION_CONFIG.cooldownMs / 1_000,
          dimensions: ["ip", "device"],
          modelLookupLimit:
            DEFAULT_PROTECTION_CONFIG.maxModelLookupsPerWindow,
          ssrfProtection: true,
          httpsUpstreamsOnly: !upstreamFetch.policy.allowHttp,
          privateUpstreamsAllowed:
            upstreamFetch.policy.allowPrivateNetworks,
          maxActiveJobs: MAX_ACTIVE_JOBS,
        },
      });
      return;
    }

    if (
      request.method === "POST" &&
      pathname === "/api/verification/challenge"
    ) {
      assertEmptyRequest(request);
      const identity = identifyClient(request, response);
      const challenge = abuseProtection.issueChallenge(identity);
      sendJson(response, 201, challenge);
      return;
    }

    if (
      request.method === "POST" &&
      pathname === "/api/verification/verify"
    ) {
      assertJsonRequest(request);
      const body = await readJsonBody(request);
      const identity = identifyClient(request, response);
      const result = abuseProtection.verifyChallenge({
        challengeId: body?.challengeId,
        finalPosition: body?.finalPosition,
        trace: body?.trace,
        ...identity,
      });
      sendJson(response, 200, result);
      return;
    }

    if (request.method === "POST" && pathname === "/api/models") {
      assertJsonRequest(request);
      assertModelLookupCapacity();
      const body = await readJsonBody(request);
      const identity = identifyClient(request, response);
      abuseProtection.reserveModelLookup(identity);
      activeModelLookups += 1;
      let result;
      try {
        result = await listAvailableModels({
          baseUrl: body?.baseUrl,
          apiKey: body?.apiKey,
          fetchImpl: upstreamFetch,
        });
      } finally {
        activeModelLookups -= 1;
      }

      sendJson(response, 200, result);
      return;
    }

    if (request.method === "POST" && pathname === "/api/analyze") {
      assertJsonRequest(request);
      const body = await readJsonBody(request);
      const baseUrl = String(body?.baseUrl ?? "").trim();
      const apiKey = validateApiKey(body?.apiKey);
      const model = validateRequestedModel(body?.model);
      const verificationProof = String(
        body?.verificationProof ?? "",
      ).trim();
      const endpoints = resolveApiEndpoints(baseUrl, {
        secret: apiKey,
      });

      if (!model) {
        throw new AnalysisError("请先读取模型列表并选择本次分析模型。", {
          code: "missing_model",
        });
      }
      if (model.includes(apiKey)) {
        throw new AnalysisError("模型名称中不能包含 API Key。", {
          code: "secret_in_model",
        });
      }

      assertJobCapacity();
      const identity = identifyClient(request, response);
      pendingJobStarts += 1;
      let reservation;
      let job;
      try {
        reservation = abuseProtection.consumeProofAndReserve({
          proof: verificationProof,
          ...identity,
        });
        await upstreamFetch.validateUrl(endpoints.modelsUrl);
        pruneJobs();
        if (jobs.size >= MAX_STORED_JOBS) {
          throw new ServiceError(
            "任务存储已达到安全上限，请稍后再试。",
            {
              code: "job_capacity_reached",
              httpStatus: 503,
              retryAfterSeconds: 30,
            },
          );
        }

        const id = randomUUID();
        const abortController = new AbortController();
        job = {
          id,
          ownerDeviceKey: identity.deviceKey,
          status: "queued",
          safeTarget: endpoints.normalizedBaseUrl,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          state: {
            status: "queued",
            stage: "任务已创建",
            config: DEFAULT_ANALYSIS_CONFIG,
            selectedModel: model,
            modelSource: "user_selected",
            startedAt: null,
            completedAt: null,
            samples: Array.from(
              {
                length:
                  DEFAULT_ANALYSIS_CONFIG.totalRequests,
              },
              (_, index) => ({
                index,
                status: "queued",
                attempts: 0,
              }),
            ),
          },
          abortController,
          listeners: new Set(),
          broadcastTimer: null,
        };
        job.state.breakdown = calculateBreakdown(
          job.state.samples,
          DEFAULT_ANALYSIS_CONFIG.totalRequests,
        );
        jobs.set(id, job);
        runJob(job, { baseUrl, apiKey, model });
      } finally {
        pendingJobStarts -= 1;
      }

      sendJson(response, 202, {
        jobId: job.id,
        location: `/api/jobs/${job.id}`,
        events: `/api/jobs/${job.id}/events`,
        nextAllowedAt: new Date(
          reservation.nextAllowedAt,
        ).toISOString(),
      });
      return;
    }

    const jobMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]+)$/i);
    if (request.method === "GET" && jobMatch) {
      const identity = identifyClient(request, response);
      const job = getOwnedJob(jobMatch[1], identity);
      sendJson(response, 200, snapshotJob(job));
      return;
    }

    const eventsMatch = pathname.match(
      /^\/api\/jobs\/([a-f0-9-]+)\/events$/i,
    );
    if (request.method === "GET" && eventsMatch) {
      const identity = identifyClient(request, response);
      const job = getOwnedJob(eventsMatch[1], identity);
      openEventStream(request, response, job);
      return;
    }

    const cancelMatch = pathname.match(
      /^\/api\/jobs\/([a-f0-9-]+)\/cancel$/i,
    );
    if (request.method === "POST" && cancelMatch) {
      assertEmptyRequest(request);
      const identity = identifyClient(request, response);
      const job = getOwnedJob(cancelMatch[1], identity);
      if (!isTerminal(job.status)) {
        job.abortController.abort();
        job.status = "cancelled";
        job.state.status = "cancelled";
        job.state.stage = "分析已取消";
        job.state.completedAt = new Date().toISOString();
        job.updatedAt = job.state.completedAt;
        broadcast(job, true);
      }
      sendJson(response, 200, snapshotJob(job));
      return;
    }

    sendJson(response, 404, {
      error: {
        code: "not_found",
        message: "请求的地址不存在。",
      },
    });
  } catch (error) {
    const status =
      Number.isInteger(error?.httpStatus)
        ? error.httpStatus
        : error instanceof AnalysisError
          ? 400
          : 500;
    if (status === 500) {
      console.error("Unhandled request error:", {
        name: error?.name,
        code: error?.code,
        message: error?.message,
      });
    }
    const retryAfterSeconds =
      Number(error?.retryAfterSeconds) || null;
    if (retryAfterSeconds) {
      response.setHeader("Retry-After", String(retryAfterSeconds));
    }
    sendJson(response, status, {
      error: {
        code: error?.code ?? "internal_error",
        message:
          status === 500
            ? "本地服务处理请求时发生错误。"
            : error.message,
        retryAfterSeconds,
      },
    });
  }
});

async function runJob(job, credentials) {
  job.status = "running";
  job.updatedAt = new Date().toISOString();

  try {
    const state = await analyzeSubscriptionPool({
      ...credentials,
      fetchImpl: upstreamFetch,
      signal: job.abortController.signal,
      onUpdate(nextState) {
        job.state = nextState;
        job.status = nextState.status;
        job.updatedAt = new Date().toISOString();
        broadcast(job);
      },
      jobSeed: job.id,
    });
    job.state = state;
    job.status = "completed";
  } catch (error) {
    if (job.abortController.signal.aborted || error?.code === "cancelled") {
      job.status = "cancelled";
      job.state.status = "cancelled";
      job.state.stage = "分析已取消";
    } else {
      job.status = "failed";
      job.state.status = "failed";
      job.state.stage = "分析未完成";
      job.state.error = {
        code: error?.code ?? "analysis_failed",
        message: error?.message ?? "分析失败",
        status: error?.status ?? null,
      };
    }
    job.state.completedAt = new Date().toISOString();
  } finally {
    job.updatedAt = new Date().toISOString();
    // Ensure credentials cannot remain reachable after the task finishes.
    credentials.apiKey = "";
    broadcast(job, true);
    setTimeout(() => {
      const current = jobs.get(job.id);
      if (current && isTerminal(current.status)) {
        jobs.delete(job.id);
      }
    }, TERMINAL_JOB_TTL_MS).unref();
  }
}

function snapshotJob(job) {
  const state = job.state;
  return {
    id: job.id,
    status: job.status,
    target: job.safeTarget,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    stage: state.stage,
    config: publicConfig(state.config),
    selectedModel: state.selectedModel,
    modelSource: state.modelSource,
    startedAt: state.startedAt,
    completedAt: state.completedAt,
    error: state.error ?? null,
    breakdown:
      state.breakdown ??
      calculateBreakdown(
        state.samples ?? [],
        state.config?.totalRequests ?? DEFAULT_ANALYSIS_CONFIG.totalRequests,
      ),
    samples: (state.samples ?? []).map(sanitizeSample),
  };
}

function sanitizeSample(sample) {
  return {
    index: sample.index,
    status: sample.status,
    attempts: sample.attempts,
    nextRetryMs: sample.nextRetryMs ?? null,
    plan: sample.plan ?? null,
    rawPlan: sample.rawPlan ?? null,
    source: sample.source ?? null,
    httpStatus: sample.httpStatus ?? null,
    latencyMs: sample.latencyMs ?? null,
    evidence: sample.evidence ?? null,
    error: sample.error ?? null,
    startedAt: sample.startedAt ?? null,
    completedAt: sample.completedAt ?? null,
  };
}

function publicConfig(config) {
  return {
    totalRequests: config.totalRequests,
    concurrency: config.concurrency,
    maxAttempts: config.maxAttempts,
    retryMinMs: config.retryMinMs,
    retryMaxMs: config.retryMaxMs,
    requestTimeoutMs: config.requestTimeoutMs,
  };
}

function broadcast(job, immediate = false) {
  if (immediate) {
    if (job.broadcastTimer) clearTimeout(job.broadcastTimer);
    job.broadcastTimer = null;
    emitSnapshot(job);
    return;
  }
  if (job.broadcastTimer) return;
  job.broadcastTimer = setTimeout(() => {
    job.broadcastTimer = null;
    emitSnapshot(job);
  }, 120);
}

function emitSnapshot(job) {
  const data = `event: snapshot\ndata: ${JSON.stringify(snapshotJob(job))}\n\n`;
  for (const listener of job.listeners) {
    if (listener.destroyed || listener.writableEnded) {
      job.listeners.delete(listener);
      continue;
    }
    try {
      listener.write(data);
    } catch {
      job.listeners.delete(listener);
      listener.destroy();
    }
  }
}

function openEventStream(request, response, job) {
  if (job.listeners.size >= MAX_JOB_LISTENERS) {
    throw new ServiceError(
      "当前任务的实时连接过多，请关闭重复页面后重试。",
      {
        code: "too_many_event_streams",
        httpStatus: 429,
        retryAfterSeconds: 5,
      },
    );
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  response.write(
    `event: snapshot\ndata: ${JSON.stringify(snapshotJob(job))}\n\n`,
  );
  job.listeners.add(response);

  const keepAlive = setInterval(() => {
    if (!response.destroyed && !response.writableEnded) {
      response.write(": keep-alive\n\n");
    }
  }, 15_000);
  keepAlive.unref();

  const cleanup = () => {
    clearInterval(keepAlive);
    job.listeners.delete(response);
  };
  request.once("close", cleanup);
  response.once("close", cleanup);
  response.once("error", cleanup);
}

function getOwnedJob(id, identity) {
  const job = jobs.get(id);
  if (!job || job.ownerDeviceKey !== identity.deviceKey) {
    throw new ServiceError("分析任务不存在或已过期。", {
      code: "job_not_found",
      httpStatus: 404,
    });
  }
  return job;
}

function parseRequestUrl(value) {
  const source = String(value ?? "");
  if (!source || source.length > 4_096) {
    throw new ServiceError("请求地址长度超过限制。", {
      code: "request_target_too_long",
      httpStatus: 414,
    });
  }
  if (!source.startsWith("/") || source.startsWith("//")) {
    throw new ServiceError("请求地址格式无效。", {
      code: "invalid_request_target",
      httpStatus: 400,
    });
  }
  try {
    return new URL(source, "http://localhost");
  } catch {
    throw new ServiceError("请求地址格式无效。", {
      code: "invalid_request_target",
      httpStatus: 400,
    });
  }
}

function assertModelLookupCapacity() {
  if (activeModelLookups < MAX_CONCURRENT_MODEL_LOOKUPS) return;
  throw new ServiceError("模型读取服务当前繁忙，请稍后再试。", {
    code: "model_lookup_capacity_reached",
    httpStatus: 503,
    retryAfterSeconds: 10,
  });
}

function assertJobCapacity() {
  pruneJobs();
  const activeJobs = [...jobs.values()].filter(
    (job) => !isTerminal(job.status),
  ).length;
  if (
    activeJobs + pendingJobStarts < MAX_ACTIVE_JOBS &&
    jobs.size < MAX_STORED_JOBS
  ) {
    return;
  }
  throw new ServiceError("分析服务当前繁忙，请稍后再试。", {
    code: "analysis_capacity_reached",
    httpStatus: 503,
    retryAfterSeconds: 30,
  });
}

function pruneJobs(now = Date.now()) {
  for (const [id, job] of jobs) {
    if (
      isTerminal(job.status) &&
      now - Date.parse(job.updatedAt) >= TERMINAL_JOB_TTL_MS
    ) {
      jobs.delete(id);
    }
  }
}

async function serveStatic(response, fileName) {
  const filePath = join(PUBLIC_DIR, fileName);
  const data = await readFile(filePath);
  response.writeHead(200, {
    "Content-Type": mimeType(filePath),
    "Cache-Control": "no-store",
  });
  response.end(data);
}

function mimeType(filePath) {
  return (
    {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".svg": "image/svg+xml",
    }[extname(filePath)] ?? "application/octet-stream"
  );
}

async function readJsonBody(request) {
  assertJsonRequest(request);
  const declaredLength = Number(request.headers["content-length"]);
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > 64 * 1_024
  ) {
    throw new ServiceError("请求内容过大。", {
      code: "request_too_large",
      httpStatus: 413,
    });
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1_024) {
      throw new ServiceError("请求内容过大。", {
        code: "request_too_large",
        httpStatus: 413,
      });
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new AnalysisError("请求内容不是有效 JSON。", {
      code: "invalid_json",
    });
  }
}

function sendJson(response, status, payload, headers = {}) {
  if (response.headersSent) return;
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function identifyClient(request, response) {
  const cookies = parseCookies(request.headers.cookie);
  let deviceId = cookies.get(DEVICE_COOKIE);
  if (!/^[A-Za-z0-9_-]{32}$/.test(deviceId ?? "")) {
    deviceId = randomBytes(24).toString("base64url");
    response.setHeader(
      "Set-Cookie",
      serializeDeviceCookie(deviceId, request),
    );
  }

  return {
    ipKey: hashIdentity("ip", clientIp(request)),
    deviceKey: hashIdentity("device", deviceId),
  };
}

function clientIp(request) {
  const forwarded = trustedProxyRequest(request)
    ? firstHeaderValue(request.headers[FORWARDED_IP_HEADER])
    : null;
  const remote = String(
    request.socket?.remoteAddress ?? "unknown",
  ).trim();
  return normalizeIp(forwarded) || normalizeIp(remote) || "unknown";
}

function trustedProxyRequest(request) {
  if (!TRUST_PROXY) return false;
  const remote = normalizeIp(request.socket?.remoteAddress);
  return Boolean(remote && TRUSTED_PROXY_IPS.has(remote));
}

function normalizeIp(value) {
  const candidate = String(value ?? "").split(",")[0].trim();
  const family = isIP(candidate);
  if (family === 4) {
    return candidate
      .split(".")
      .map((part) => String(Number(part)))
      .join(".");
  }
  if (family !== 6) return null;

  let canonical;
  try {
    canonical = new URL(`http://[${candidate}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const mapped = canonical.match(
    /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i,
  );
  if (mapped) {
    const high = Number.parseInt(mapped[1], 16);
    const low = Number.parseInt(mapped[2], 16);
    return [
      high >> 8,
      high & 0xff,
      low >> 8,
      low & 0xff,
    ].join(".");
  }
  return canonical;
}

function firstHeaderValue(value) {
  return Array.isArray(value) ? value[0] : value;
}

function parseCookies(header) {
  const cookies = new Map();
  for (const entry of String(header ?? "").split(";")) {
    const separator = entry.indexOf("=");
    if (separator <= 0) continue;
    const name = entry.slice(0, separator).trim();
    const value = entry.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

function serializeDeviceCookie(deviceId, request) {
  const attributes = [
    `${DEVICE_COOKIE}=${deviceId}`,
    "Path=/",
    `Max-Age=${DEVICE_COOKIE_MAX_AGE}`,
    "HttpOnly",
    "SameSite=Strict",
    "Priority=High",
  ];
  if (applicationRequestIsSecure(request)) {
    attributes.push("Secure");
  }
  return attributes.join("; ");
}

function hashIdentity(kind, value) {
  return createHmac("sha256", identitySecret)
    .update(`${kind}:${value}`)
    .digest("base64url");
}

function applySecurityHeaders(request, response) {
  const headers = securityResponseHeaders({
    secure: applicationRequestIsSecure(request),
  });
  for (const [name, value] of Object.entries(headers)) {
    response.setHeader(name, value);
  }
}

function applicationRequestIsSecure(request) {
  return (
    requestSecurity.publicOrigin?.startsWith("https://") ||
    requestIsSecure(request, trustedProxyRequest(request))
  );
}

function readBooleanEnv(name) {
  return /^(1|true)$/i.test(process.env[name] ?? "");
}

function readIntegerEnv(name, fallback, min, max) {
  const value = Number(process.env[name]);
  return Number.isInteger(value) && value >= min && value <= max
    ? value
    : fallback;
}

function readIdentitySecret() {
  const configured = process.env.ABUSE_SECRET;
  if (!configured) return randomBytes(32);
  if (Buffer.byteLength(configured) < 32) {
    throw new Error("ABUSE_SECRET 必须至少包含 32 字节。");
  }
  return configured;
}

function readForwardedIpHeader() {
  const header = String(
    process.env.FORWARDED_IP_HEADER ?? "x-real-ip",
  )
    .trim()
    .toLowerCase();
  if (
    !["x-real-ip", "x-forwarded-for", "cf-connecting-ip"].includes(
      header,
    )
  ) {
    throw new Error("FORWARDED_IP_HEADER 配置无效。");
  }
  return header;
}

function isTerminal(status) {
  return ["completed", "failed", "cancelled"].includes(status);
}

server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.maxRequestsPerSocket = 100;
server.maxConnections = 256;

server.listen(PORT, HOST, () => {
  console.log(`Codex PlanScope 已启动：http://${HOST}:${PORT}`);
  console.log(
    `固定策略：${DEFAULT_ANALYSIS_CONFIG.totalRequests} 次请求 / ${DEFAULT_ANALYSIS_CONFIG.concurrency} 并发 / 最多 ${DEFAULT_ANALYSIS_CONFIG.maxAttempts} 次尝试`,
  );
  console.log("防滥用：滑块验证 / IP 与设备独立冷却 5 分钟");
  console.log(
    `网络保护：SSRF 防护已启用 / ${upstreamFetch.policy.allowHttp ? "允许显式 HTTP" : "仅 HTTPS"} / 最大并行任务 ${MAX_ACTIVE_JOBS}`,
  );
});

function shutdown() {
  for (const job of jobs.values()) {
    job.abortController.abort();
  }
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
