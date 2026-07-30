import { randomUUID } from "node:crypto";

export const DEFAULT_ANALYSIS_CONFIG = Object.freeze({
  totalRequests: 100,
  concurrency: 50,
  maxAttempts: 5,
  retryMinMs: 1_000,
  retryMaxMs: 3_000,
  requestTimeoutMs: 45_000,
});

const PLAN_LABELS = Object.freeze({
  guest: "Guest",
  free: "Free",
  free_workspace: "Free Workspace",
  go: "Go",
  plus: "Plus",
  pro: "Pro",
  prolite: "Pro Lite",
  self_serve_business_prolite: "Business Pro Lite",
  team: "Team",
  self_serve_business_usage_based: "Business Usage",
  business: "Business",
  ent26: "Enterprise",
  enterprise_cbp_usage_based: "Enterprise Usage",
  enterprise: "Enterprise",
  education: "Education",
  edu: "Education",
  quorum: "Quorum",
  k12: "K-12",
});

const COMMON_MODEL_FALLBACKS = Object.freeze([
  "gpt-5.4-mini",
  "gpt-5.3-codex",
  "gpt-5-codex",
  "codex-mini-latest",
  "gpt-5.4",
]);

export class AnalysisError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "AnalysisError";
    this.code = options.code ?? "analysis_error";
    this.status = options.status ?? null;
    this.retryable = options.retryable ?? false;
  }
}

export function resolveApiEndpoints(rawUrl) {
  const input = String(rawUrl ?? "").trim();
  if (!input) {
    throw new AnalysisError("请填写 API 地址。", { code: "missing_url" });
  }

  let url;
  try {
    url = new URL(input);
  } catch {
    throw new AnalysisError("API 地址格式不正确，请包含 http:// 或 https://。", {
      code: "invalid_url",
    });
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new AnalysisError("API 地址仅支持 HTTP 或 HTTPS。", {
      code: "invalid_protocol",
    });
  }
  if (url.username || url.password) {
    throw new AnalysisError("API 地址中不能包含用户名或密码。", {
      code: "url_credentials_not_allowed",
    });
  }

  url.search = "";
  url.hash = "";
  const cleanPath = url.pathname.replace(/\/+$/, "");
  const isResponsesEndpoint = /\/responses$/i.test(cleanPath);
  const apiRootPath = isResponsesEndpoint
    ? cleanPath.replace(/\/responses$/i, "")
    : /\/v1$/i.test(cleanPath)
      ? cleanPath
      : `${cleanPath}/v1`.replace(/\/{2,}/g, "/");

  const origin = url.origin;
  const responsesPath = isResponsesEndpoint
    ? cleanPath
    : `${apiRootPath}/responses`;

  return {
    normalizedBaseUrl: `${origin}${apiRootPath}`,
    responsesUrl: `${origin}${responsesPath}`,
    modelsUrl: `${origin}${apiRootPath}/models`,
  };
}

export function normalizePlan(rawPlan) {
  const raw = String(rawPlan ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "_")
    .replace(/\s+/g, "_");

  if (!raw) {
    return null;
  }

  return {
    key: raw,
    label: PLAN_LABELS[raw] ?? titleCasePlan(raw),
    known: Object.hasOwn(PLAN_LABELS, raw),
  };
}

function titleCasePlan(value) {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function chooseModel(modelIds) {
  const uniqueIds = [
    ...new Set(
      (Array.isArray(modelIds) ? modelIds : [])
        .map((model) =>
          typeof model === "string" ? model : String(model?.id ?? ""),
        )
        .map((id) => id.trim())
        .filter(Boolean),
    ),
  ];

  if (uniqueIds.length === 0) {
    return {
      selected: COMMON_MODEL_FALLBACKS[0],
      candidates: [...COMMON_MODEL_FALLBACKS],
      source: "fallback",
    };
  }

  const disallowed = /(audio|image|embedding|realtime|transcri|moderation)/i;
  const scored = uniqueIds
    .filter((id) => !disallowed.test(id))
    .map((id, index) => ({ id, index, score: scoreModel(id) }))
    .sort((a, b) => b.score - a.score || a.index - b.index);

  const candidates = scored.map(({ id }) => id);
  if (candidates.length === 0) {
    candidates.push(...uniqueIds);
  }

  return {
    selected: candidates[0],
    candidates,
    source: "models_endpoint",
  };
}

function scoreModel(modelId) {
  const id = modelId.toLowerCase();
  let score = 0;

  if (id === "gpt-5.4-mini") score += 1_000;
  if (id.includes("mini") || id.includes("compact") || id.includes("luna")) {
    score += 350;
  }
  if (id.includes("codex")) score += 240;
  if (id.startsWith("gpt-5")) score += 200;
  if (id.startsWith("gpt-")) score += 100;
  if (id.includes("auto-review")) score -= 500;
  if (id.includes("pro")) score -= 80;

  return score;
}

export function extractPlanFromResponse(headers, payload = null) {
  const headerPlan = headers?.get?.("x-codex-plan-type");
  if (headerPlan) {
    return {
      raw: headerPlan,
      normalized: normalizePlan(headerPlan),
      source: "response_header:x-codex-plan-type",
    };
  }

  const candidates = [
    ["response_body:plan_type", payload?.plan_type],
    ["response_body:planType", payload?.planType],
    ["response_body:error.plan_type", payload?.error?.plan_type],
    ["response_body:error.planType", payload?.error?.planType],
    ["response_body:rate_limits.plan_type", payload?.rate_limits?.plan_type],
    ["response_body:rateLimits.planType", payload?.rateLimits?.planType],
  ];

  for (const [source, raw] of candidates) {
    if (raw !== undefined && raw !== null && String(raw).trim()) {
      return {
        raw: String(raw),
        normalized: normalizePlan(raw),
        source,
      };
    }
  }

  return null;
}

export function extractCodexEvidence(headers) {
  const get = (name) => cleanHeaderValue(headers?.get?.(name));
  const boolean = (name) => parseHeaderBoolean(get(name));

  const additionalLimits = [];
  if (headers?.entries) {
    const prefixes = new Set();
    for (const [name] of headers.entries()) {
      const match = name
        .toLowerCase()
        .match(/^x-codex-(.+)-primary-used-percent$/);
      if (match && match[1] !== "primary") {
        prefixes.add(match[1]);
      }
    }

    for (const prefix of prefixes) {
      additionalLimits.push({
        id: prefix.replaceAll("-", "_"),
        name: get(`x-codex-${prefix}-limit-name`),
        primary: readWindow(headers, `x-codex-${prefix}-primary`),
        secondary: readWindow(headers, `x-codex-${prefix}-secondary`),
      });
    }
  }

  return {
    activeLimit: get("x-codex-active-limit"),
    primary: readWindow(headers, "x-codex-primary"),
    secondary: readWindow(headers, "x-codex-secondary"),
    credits: {
      hasCredits: boolean("x-codex-credits-has-credits"),
      unlimited: boolean("x-codex-credits-unlimited"),
      balance: get("x-codex-credits-balance"),
    },
    additionalLimits,
    upstreamRequestId:
      get("x-request-id") ??
      get("openai-request-id") ??
      get("x-oneapi-request-id"),
    serverModel: get("openai-model"),
  };

  function readWindow(sourceHeaders, prefix) {
    const sourceGet = (suffix) =>
      cleanHeaderValue(sourceHeaders?.get?.(`${prefix}-${suffix}`));
    return {
      usedPercent: parseFiniteNumber(sourceGet("used-percent")),
      windowMinutes: parseFiniteNumber(sourceGet("window-minutes")),
      resetsAt: parseFiniteNumber(sourceGet("reset-at")),
      resetAfterSeconds: parseFiniteNumber(sourceGet("reset-after-seconds")),
    };
  }
}

function cleanHeaderValue(value) {
  if (value === undefined || value === null) return null;
  const clean = String(value).trim();
  return clean === "" ? null : clean;
}

function parseFiniteNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseHeaderBoolean(value) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim().toLowerCase();
  if (["true", "1"].includes(normalized)) return true;
  if (["false", "0"].includes(normalized)) return false;
  return null;
}

export function isRetryableStatus(status) {
  return [408, 409, 425, 429, 500, 502, 503, 504].includes(Number(status));
}

export function calculateBreakdown(samples, totalRequests) {
  const total = Number(totalRequests) || samples.length || 1;
  const counts = new Map();
  let completed = 0;
  let classified = 0;
  let unknown = 0;
  let failed = 0;
  let latencyTotal = 0;
  let latencyCount = 0;
  let attempts = 0;

  for (const sample of samples) {
    if (!sample || ["queued", "running", "waiting_retry"].includes(sample.status)) {
      attempts += sample?.attempts ?? 0;
      continue;
    }

    completed += 1;
    attempts += sample.attempts ?? 0;

    if (Number.isFinite(sample.latencyMs)) {
      latencyTotal += sample.latencyMs;
      latencyCount += 1;
    }

    if (sample.status === "classified" && sample.plan?.key) {
      classified += 1;
      const current = counts.get(sample.plan.key) ?? {
        key: sample.plan.key,
        label: sample.plan.label,
        count: 0,
      };
      current.count += 1;
      counts.set(sample.plan.key, current);
    } else if (sample.status === "failed") {
      failed += 1;
    } else {
      unknown += 1;
    }
  }

  const preferredOrder = [
    "pro",
    "plus",
    "free",
    "go",
    "prolite",
    "team",
    "business",
    "enterprise",
  ];

  const plans = [...counts.values()]
    .sort((a, b) => {
      const ai = preferredOrder.indexOf(a.key);
      const bi = preferredOrder.indexOf(b.key);
      if (ai !== -1 || bi !== -1) {
        return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      }
      return b.count - a.count || a.label.localeCompare(b.label);
    })
    .map((entry) => ({
      ...entry,
      percent: roundPercent(entry.count, total),
      classifiedPercent: roundPercent(entry.count, classified || 1),
    }));

  return {
    total,
    completed,
    pending: Math.max(0, total - completed),
    classified,
    unknown,
    failed,
    attempts,
    successRate: roundPercent(classified + unknown, total),
    averageLatencyMs:
      latencyCount > 0 ? Math.round(latencyTotal / latencyCount) : null,
    plans,
    unknownPercent: roundPercent(unknown, total),
    failedPercent: roundPercent(failed, total),
  };
}

function roundPercent(count, total) {
  return Math.round((count / total) * 1_000) / 10;
}

export async function analyzeSubscriptionPool(options) {
  const {
    baseUrl,
    apiKey,
    config: configOverride = {},
    fetchImpl = globalThis.fetch,
    random = Math.random,
    sleep = defaultSleep,
    signal,
    onUpdate = () => {},
    jobSeed = randomUUID(),
  } = options;

  if (typeof fetchImpl !== "function") {
    throw new AnalysisError("当前 Node.js 环境不支持 fetch。", {
      code: "fetch_unavailable",
    });
  }

  const key = String(apiKey ?? "").trim();
  if (!key) {
    throw new AnalysisError("请填写 API Key。", { code: "missing_api_key" });
  }

  const config = validateConfig({
    ...DEFAULT_ANALYSIS_CONFIG,
    ...configOverride,
  });
  const endpoints = resolveApiEndpoints(baseUrl);
  const state = {
    status: "preparing",
    stage: "正在验证地址和模型",
    config,
    endpoints: {
      normalizedBaseUrl: endpoints.normalizedBaseUrl,
      responsesUrl: endpoints.responsesUrl,
    },
    selectedModel: null,
    modelSource: null,
    startedAt: new Date().toISOString(),
    completedAt: null,
    error: null,
    samples: Array.from({ length: config.totalRequests }, (_, index) => ({
      index,
      status: "queued",
      attempts: 0,
    })),
    breakdown: null,
  };

  const notify = () => {
    state.breakdown = calculateBreakdown(
      state.samples,
      config.totalRequests,
    );
    onUpdate(state);
  };

  notify();
  throwIfCancelled(signal);

  const modelIds = await fetchModelIds({
    url: endpoints.modelsUrl,
    apiKey: key,
    fetchImpl,
    signal,
    timeoutMs: Math.min(config.requestTimeoutMs, 20_000),
  });
  const modelChoice = chooseModel(modelIds);
  state.selectedModel = modelChoice.selected;
  state.modelSource = modelChoice.source;
  state.status = "running";
  state.stage = "正在执行首个有效性样本";
  notify();

  await runSingleSample({
    state,
    sampleIndex: 0,
    responsesUrl: endpoints.responsesUrl,
    apiKey: key,
    model: modelChoice.selected,
    config,
    fetchImpl,
    random,
    sleep,
    signal,
    jobSeed,
    notify,
  });

  const firstSample = state.samples[0];
  if (firstSample.status === "failed") {
    throw new AnalysisError(
      `首个样本失败，已停止后续并发请求：${firstSample.error?.message ?? "未知错误"}`,
      {
        code: "preflight_sample_failed",
        status: firstSample.httpStatus,
      },
    );
  }

  state.stage = `正在以 ${config.concurrency} 并发采集剩余样本`;
  notify();

  let nextIndex = 1;
  const workerCount = Math.min(
    config.concurrency,
    Math.max(0, config.totalRequests - 1),
  );
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      throwIfCancelled(signal);
      const index = nextIndex;
      nextIndex += 1;
      if (index >= config.totalRequests) return;

      await runSingleSample({
        state,
        sampleIndex: index,
        responsesUrl: endpoints.responsesUrl,
        apiKey: key,
        model: modelChoice.selected,
        config,
        fetchImpl,
        random,
        sleep,
        signal,
        jobSeed,
        notify,
      });
    }
  });

  await Promise.all(workers);
  throwIfCancelled(signal);

  state.status = "completed";
  state.stage = "分析完成";
  state.completedAt = new Date().toISOString();
  notify();
  return state;
}

async function fetchModelIds({
  url,
  apiKey,
  fetchImpl,
  signal,
  timeoutMs,
}) {
  const requestSignal = combinedSignal(signal, timeoutMs);
  let response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json",
      },
      redirect: "manual",
      signal: requestSignal,
    });
  } catch (error) {
    throw mapFetchError(error, "模型列表请求失败");
  }

  if (isRedirect(response.status)) {
    throw new AnalysisError("模型接口发生重定向，为避免泄露 API Key 已停止。", {
      code: "unsafe_redirect",
      status: response.status,
    });
  }

  const text = await response.text();
  if (!response.ok) {
    const message = extractErrorMessage(text);
    if ([401, 403].includes(response.status)) {
      throw new AnalysisError(`API Key 验证失败：${message}`, {
        code: "invalid_credentials",
        status: response.status,
      });
    }
    if ([404, 405].includes(response.status)) {
      return [];
    }
    throw new AnalysisError(`模型列表请求失败：${message}`, {
      code: "models_request_failed",
      status: response.status,
      retryable: isRetryableStatus(response.status),
    });
  }

  const payload = safeJsonParse(text);
  const models = Array.isArray(payload?.data)
    ? payload.data
    : Array.isArray(payload?.models)
      ? payload.models
      : [];
  return models
    .map((model) => (typeof model === "string" ? model : model?.id))
    .filter(Boolean);
}

async function runSingleSample({
  state,
  sampleIndex,
  responsesUrl,
  apiKey,
  model,
  config,
  fetchImpl,
  random,
  sleep,
  signal,
  jobSeed,
  notify,
}) {
  const sample = state.samples[sampleIndex];
  const sampleId = `plan-probe-${sampleIndex}-${jobSeed}`;
  const sessionId = stableUuid(jobSeed, sampleIndex);

  for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
    throwIfCancelled(signal);
    sample.status = "running";
    sample.attempts = attempt;
    sample.nextRetryMs = null;
    sample.startedAt ??= new Date().toISOString();
    notify();

    const started = performance.now();
    let response;
    try {
      response = await fetchImpl(responsesUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          "OpenAI-Beta": "responses=experimental",
          originator: "codex_cli_rs",
          "User-Agent": "codex-plan-scope/1.0",
          "session-id": sessionId,
          "thread-id": sessionId,
          "x-client-request-id": sessionId,
          "x-codex-window-id": sessionId,
        },
        body: JSON.stringify({
          model,
          instructions: "",
          input: [
            {
              role: "user",
              content: [
                {
                  type: "input_text",
                  text: "Reply only: OK",
                },
              ],
            },
          ],
          tools: [],
          tool_choice: "auto",
          parallel_tool_calls: false,
          reasoning: {
            effort: "low",
            summary: "auto",
          },
          max_output_tokens: 16,
          store: false,
          stream: false,
          prompt_cache_key: sampleId,
        }),
        redirect: "manual",
        signal: combinedSignal(signal, config.requestTimeoutMs),
      });
    } catch (error) {
      const mapped = mapFetchError(error, "请求失败");
      const canRetry =
        mapped.retryable && attempt < config.maxAttempts && !signal?.aborted;
      if (canRetry) {
        const waitMs = randomDelay(
          config.retryMinMs,
          config.retryMaxMs,
          random,
        );
        sample.status = "waiting_retry";
        sample.nextRetryMs = waitMs;
        sample.error = serializeError(mapped);
        notify();
        await sleep(waitMs, signal);
        continue;
      }

      completeFailedSample(sample, mapped, performance.now() - started);
      notify();
      return;
    }

    const latencyMs = Math.round(performance.now() - started);
    if (isRedirect(response.status)) {
      const error = new AnalysisError(
        "接口发生重定向，为避免将 API Key 转发到其他地址已停止该样本。",
        {
          code: "unsafe_redirect",
          status: response.status,
        },
      );
      completeFailedSample(sample, error, latencyMs);
      notify();
      return;
    }

    const text = await response.text();
    if (!response.ok) {
      const error = new AnalysisError(extractErrorMessage(text), {
        code: `http_${response.status}`,
        status: response.status,
        retryable: isRetryableStatus(response.status),
      });
      const canRetry =
        error.retryable && attempt < config.maxAttempts && !signal?.aborted;
      if (canRetry) {
        const waitMs = randomDelay(
          config.retryMinMs,
          config.retryMaxMs,
          random,
        );
        sample.status = "waiting_retry";
        sample.httpStatus = response.status;
        sample.nextRetryMs = waitMs;
        sample.error = serializeError(error);
        notify();
        await sleep(waitMs, signal);
        continue;
      }

      completeFailedSample(sample, error, latencyMs, response.status);
      notify();
      return;
    }

    const payload = safeJsonParse(text);
    const planResult = extractPlanFromResponse(response.headers, payload);
    const evidence = extractCodexEvidence(response.headers);

    Object.assign(sample, {
      status: planResult?.normalized ? "classified" : "unknown",
      plan: planResult?.normalized ?? null,
      rawPlan: planResult?.raw ?? null,
      source: planResult?.source ?? null,
      httpStatus: response.status,
      latencyMs,
      evidence,
      error: null,
      nextRetryMs: null,
      completedAt: new Date().toISOString(),
    });
    notify();
    return;
  }
}

function completeFailedSample(sample, error, latencyMs, status = null) {
  Object.assign(sample, {
    status: "failed",
    httpStatus: status ?? error.status ?? null,
    latencyMs: Math.max(0, Math.round(latencyMs)),
    plan: null,
    rawPlan: null,
    source: null,
    evidence: null,
    error: serializeError(error),
    nextRetryMs: null,
    completedAt: new Date().toISOString(),
  });
}

function validateConfig(config) {
  const integer = (name, min, max) => {
    const value = Number(config[name]);
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new AnalysisError(`分析参数 ${name} 无效。`, {
        code: "invalid_config",
      });
    }
    return value;
  };

  const totalRequests = integer("totalRequests", 1, 1_000);
  const concurrency = Math.min(
    integer("concurrency", 1, 100),
    totalRequests,
  );
  const maxAttempts = integer("maxAttempts", 1, 10);
  const retryMinMs = integer("retryMinMs", 0, 60_000);
  const retryMaxMs = integer("retryMaxMs", retryMinMs, 120_000);
  const requestTimeoutMs = integer("requestTimeoutMs", 1_000, 180_000);

  return {
    totalRequests,
    concurrency,
    maxAttempts,
    retryMinMs,
    retryMaxMs,
    requestTimeoutMs,
  };
}

function randomDelay(min, max, random) {
  if (max <= min) return min;
  return Math.floor(min + random() * (max - min + 1));
}

function combinedSignal(parentSignal, timeoutMs) {
  const signals = [AbortSignal.timeout(timeoutMs)];
  if (parentSignal) signals.push(parentSignal);
  return AbortSignal.any(signals);
}

function throwIfCancelled(signal) {
  if (signal?.aborted) {
    throw new AnalysisError("分析已取消。", {
      code: "cancelled",
    });
  }
}

function mapFetchError(error, prefix) {
  if (error instanceof AnalysisError) return error;
  if (error?.name === "AbortError") {
    return new AnalysisError(`${prefix}：请求已取消。`, {
      code: "request_aborted",
      retryable: false,
      cause: error,
    });
  }
  if (error?.name === "TimeoutError") {
    return new AnalysisError(`${prefix}：请求超时。`, {
      code: "request_timeout",
      retryable: true,
      cause: error,
    });
  }
  return new AnalysisError(`${prefix}：${error?.message ?? "网络错误"}`, {
    code: "network_error",
    retryable: true,
    cause: error,
  });
}

function extractErrorMessage(text) {
  const payload = safeJsonParse(text);
  const message =
    payload?.error?.message ??
    payload?.message ??
    payload?.error ??
    String(text ?? "").trim();
  return String(message || "接口返回未知错误").slice(0, 600);
}

function safeJsonParse(text) {
  if (!text || typeof text !== "string") return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isRedirect(status) {
  return status >= 300 && status < 400;
}

function serializeError(error) {
  return {
    code: error?.code ?? "unknown_error",
    message: error?.message ?? "未知错误",
    status: error?.status ?? null,
    retryable: error?.retryable ?? false,
  };
}

function stableUuid(seed, index) {
  const clean = String(seed).replaceAll("-", "").padEnd(32, "0").slice(0, 32);
  const mixed = `${clean.slice(0, 24)}${index.toString(16).padStart(8, "0")}`;
  return [
    mixed.slice(0, 8),
    mixed.slice(8, 12),
    `4${mixed.slice(13, 16)}`,
    `8${mixed.slice(17, 20)}`,
    mixed.slice(20, 32),
  ].join("-");
}

function defaultSleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(
        new AnalysisError("分析已取消。", {
          code: "cancelled",
        }),
      );
      return;
    }

    const onAbort = () => {
      clearTimeout(timeout);
      reject(
        new AnalysisError("分析已取消。", {
          code: "cancelled",
        }),
      );
    };
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
