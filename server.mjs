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
  AbuseProtectionError,
  DEFAULT_PROTECTION_CONFIG,
} from "./src/abuse-protection.mjs";
import {
  AnalysisError,
  DEFAULT_ANALYSIS_CONFIG,
  analyzeSubscriptionPool,
  calculateBreakdown,
  listAvailableModels,
  resolveApiEndpoints,
} from "./src/analyzer.mjs";

const ROOT_DIR = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = join(ROOT_DIR, "public");
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4317);
const TRUST_PROXY = /^(1|true)$/i.test(process.env.TRUST_PROXY ?? "");
const DEVICE_COOKIE = "planscope_device";
const DEVICE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;
const identitySecret =
  process.env.ABUSE_SECRET || randomBytes(32);
const abuseProtection = new AbuseProtection();
const jobs = new Map();
const TERMINAL_JOB_TTL_MS = 60 * 60 * 1_000;

const staticRoutes = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"],
  ["/styles.css", "styles.css"],
  ["/app.js", "app.js"],
]);

const server = createServer(async (request, response) => {
  applySecurityHeaders(response);

  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const { pathname } = url;

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
        },
      });
      return;
    }

    if (
      request.method === "POST" &&
      pathname === "/api/verification/challenge"
    ) {
      const identity = identifyClient(request, response);
      const challenge = abuseProtection.issueChallenge(identity);
      sendJson(response, 201, challenge);
      return;
    }

    if (
      request.method === "POST" &&
      pathname === "/api/verification/verify"
    ) {
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
      const body = await readJsonBody(request);
      const result = await listAvailableModels({
        baseUrl: body?.baseUrl,
        apiKey: body?.apiKey,
      });

      sendJson(response, 200, result);
      return;
    }

    if (request.method === "POST" && pathname === "/api/analyze") {
      const body = await readJsonBody(request);
      const baseUrl = String(body?.baseUrl ?? "").trim();
      const apiKey = String(body?.apiKey ?? "").trim();
      const model = String(body?.model ?? "").trim();
      const verificationProof = String(
        body?.verificationProof ?? "",
      ).trim();
      const endpoints = resolveApiEndpoints(baseUrl);

      if (!apiKey) {
        throw new AnalysisError("请填写 API Key。", {
          code: "missing_api_key",
        });
      }
      if (!model) {
        throw new AnalysisError("请先读取模型列表并选择本次分析模型。", {
          code: "missing_model",
        });
      }

      const identity = identifyClient(request, response);
      const reservation = abuseProtection.consumeProofAndReserve({
        proof: verificationProof,
        ...identity,
      });
      const id = randomUUID();
      const abortController = new AbortController();
      const job = {
        id,
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
            { length: DEFAULT_ANALYSIS_CONFIG.totalRequests },
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

      sendJson(response, 202, {
        jobId: id,
        location: `/api/jobs/${id}`,
        events: `/api/jobs/${id}/events`,
        nextAllowedAt: new Date(
          reservation.nextAllowedAt,
        ).toISOString(),
      });
      return;
    }

    const jobMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]+)$/i);
    if (request.method === "GET" && jobMatch) {
      const job = getJob(jobMatch[1]);
      sendJson(response, 200, snapshotJob(job));
      return;
    }

    const eventsMatch = pathname.match(
      /^\/api\/jobs\/([a-f0-9-]+)\/events$/i,
    );
    if (request.method === "GET" && eventsMatch) {
      const job = getJob(eventsMatch[1]);
      openEventStream(request, response, job);
      return;
    }

    const cancelMatch = pathname.match(
      /^\/api\/jobs\/([a-f0-9-]+)\/cancel$/i,
    );
    if (request.method === "POST" && cancelMatch) {
      const job = getJob(cancelMatch[1]);
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
      error instanceof AbuseProtectionError
        ? error.httpStatus
        : error instanceof AnalysisError
          ? 400
          : 500;
    if (status === 500) {
      console.error("Unhandled request error:", error);
    }
    const retryAfterSeconds =
      error instanceof AbuseProtectionError
        ? error.retryAfterSeconds
        : null;
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
    listener.write(data);
  }
}

function openEventStream(request, response, job) {
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
    response.write(": keep-alive\n\n");
  }, 15_000);
  keepAlive.unref();

  request.on("close", () => {
    clearInterval(keepAlive);
    job.listeners.delete(response);
  });
}

function getJob(id) {
  const job = jobs.get(id);
  if (!job) {
    throw new AnalysisError("分析任务不存在或已过期。", {
      code: "job_not_found",
    });
  }
  return job;
}

async function serveStatic(response, fileName) {
  const filePath = join(PUBLIC_DIR, fileName);
  const data = await readFile(filePath);
  response.writeHead(200, {
    "Content-Type": mimeType(filePath),
    "Cache-Control": "no-cache",
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
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1_024) {
      throw new AnalysisError("请求内容过大。", {
        code: "request_too_large",
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
  const forwarded = TRUST_PROXY
    ? firstHeaderValue(
        request.headers["cf-connecting-ip"] ??
          request.headers["x-forwarded-for"] ??
          request.headers["x-real-ip"],
      )
    : null;
  const remote = String(
    request.socket?.remoteAddress ?? "unknown",
  ).trim();
  return normalizeIp(forwarded) || normalizeIp(remote) || "unknown";
}

function normalizeIp(value) {
  let candidate = String(value ?? "").split(",")[0].trim();
  if (candidate.startsWith("::ffff:")) {
    candidate = candidate.slice(7);
  }
  return isIP(candidate) ? candidate : null;
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
  ];
  if (requestIsSecure(request)) attributes.push("Secure");
  return attributes.join("; ");
}

function requestIsSecure(request) {
  if (request.socket?.encrypted) return true;
  if (!TRUST_PROXY) return false;
  return (
    String(request.headers["x-forwarded-proto"] ?? "")
      .split(",")[0]
      .trim()
      .toLowerCase() === "https"
  );
}

function hashIdentity(kind, value) {
  return createHmac("sha256", identitySecret)
    .update(`${kind}:${value}`)
    .digest("base64url");
}

function applySecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
}

function isTerminal(status) {
  return ["completed", "failed", "cancelled"].includes(status);
}

server.listen(PORT, HOST, () => {
  console.log(`Codex PlanScope 已启动：http://${HOST}:${PORT}`);
  console.log(
    `固定策略：${DEFAULT_ANALYSIS_CONFIG.totalRequests} 次请求 / ${DEFAULT_ANALYSIS_CONFIG.concurrency} 并发 / 最多 ${DEFAULT_ANALYSIS_CONFIG.maxAttempts} 次尝试`,
  );
  console.log("防滥用：滑块验证 / IP 与设备独立冷却 5 分钟");
});

function shutdown() {
  for (const job of jobs.values()) {
    job.abortController.abort();
  }
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
