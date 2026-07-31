import { randomUUID } from "node:crypto";
import {
  createDiagnosticExcerpt,
  redactSensitiveText,
  sanitizeDiagnosticText,
} from "./redaction.mjs";

export const DEFAULT_ANALYSIS_CONFIG = Object.freeze({
  totalRequests: 100,
  concurrency: 50,
  maxAttempts: 5,
  retryMinMs: 1_000,
  retryMaxMs: 3_000,
  requestTimeoutMs: 45_000,
});

const MAX_UPSTREAM_BODY_BYTES = 512 * 1_024;
const MAX_RESPONSES_STREAM_EVENTS = 10_000;
const MAX_MODEL_COUNT = 500;
const MAX_MODEL_ID_LENGTH = 200;
const MAX_API_KEY_LENGTH = 4_096;
const MAX_FAILURE_RESPONSE_CHARS = 4_096;
const MAX_FAILURE_DETAILS = 10;
const SENSITIVE_STRUCTURED_FIELD =
  /(?:^|[-_])(?:api[-_]?key|authorization|proxy[-_]?authorization|access[-_]?token|refresh[-_]?token|auth[-_]?token|id[-_]?token|token|secret|password|passwd|cookie|set[-_]?cookie|credential|credentials|private[-_]?key)(?:$|[-_])/i;

const COMMON_MODEL_FALLBACKS = Object.freeze([
  "gpt-5.5",
  "gpt-5.4",
  "gpt-5.4-mini",
  "gpt-5.3-codex-spark",
  "gpt-5.3-codex",
  "gpt-5-codex",
  "codex-mini-latest",
]);

export class AnalysisError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "AnalysisError";
    this.code = options.code ?? "analysis_error";
    this.status = options.status ?? null;
    this.retryable = options.retryable ?? false;
    this.diagnosticBody =
      typeof options.diagnosticBody === "string"
        ? options.diagnosticBody
        : null;
    this.streamTrace =
      options.streamTrace && typeof options.streamTrace === "object"
        ? options.streamTrace
        : null;
  }
}

export function resolveApiEndpoints(rawUrl, options = {}) {
  const input = String(rawUrl ?? "").trim();
  if (!input) {
    throw new AnalysisError("请填写 API 地址。", { code: "missing_url" });
  }
  if (input.length > 2_048) {
    throw new AnalysisError("API 地址长度超过安全限制。", {
      code: "url_too_long",
    });
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

  const endpoints = {
    normalizedBaseUrl: `${origin}${apiRootPath}`,
    responsesUrl: `${origin}${responsesPath}`,
    modelsUrl: `${origin}${apiRootPath}/models`,
  };
  const secret = String(options?.secret ?? "");
  const encodedSecret = secret ? encodeURIComponent(secret) : "";
  if (
    secret.length >= 4 &&
    Object.values(endpoints).some(
      (value) =>
        value.includes(secret) ||
        (encodedSecret && value.includes(encodedSecret)),
    )
  ) {
    throw new AnalysisError("API 地址中不能包含 API Key。", {
      code: "secret_in_url",
    });
  }
  return endpoints;
}

export function normalizePlan(rawPlan) {
  const source = cleanPlanValue(rawPlan);
  const raw = source
    .trim()
    .toLowerCase()
    .replaceAll("-", "_")
    .replace(/\s+/g, "_");

  if (!raw) {
    return null;
  }

  return {
    key: raw,
    label: formatPlanLabel(source),
  };
}

function formatPlanLabel(value) {
  return value
    .replace(/[-_\s]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((part) =>
      /\d/.test(part)
        ? part.toUpperCase()
        : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase(),
    )
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
        .filter(isSafeModelId)
        .slice(0, MAX_MODEL_COUNT),
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

  if (id === "gpt-5.5") return 10_000;
  if (id === "gpt-5.4") return 9_000;
  if (/^gpt-5\.5(?:[-.].+)$/.test(id)) score += 8_000;
  if (/^gpt-5\.4(?:[-.].+)$/.test(id)) score += 7_000;
  if (id.includes("codex-spark")) score += 1_500;
  if (id.includes("luna")) score += 1_050;
  if (id.includes("mini") || id.includes("compact")) {
    score += 350;
  }
  if (id.includes("codex")) score += 240;
  if (id.startsWith("gpt-5")) score += 200;
  if (id.startsWith("gpt-")) score += 100;
  if (id.includes("auto-review")) score -= 500;
  if (id.includes("pro")) score -= 80;

  return score;
}

export function fastestReasoningEffort(modelId) {
  const id = String(modelId ?? "").trim().toLowerCase();

  if (/^gpt-5\.(?:1|2|4|5|6)(?:$|[-.])/.test(id)) {
    return "none";
  }
  if (/^gpt-5(?:$|-2025)/.test(id)) {
    return "minimal";
  }
  return "low";
}

export function extractPlanFromResponse(headers, payload = null) {
  const headerPlan = cleanPlanValue(
    headers?.get?.("x-codex-plan-type"),
  );
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
    const clean = cleanPlanValue(raw);
    if (clean) {
      return {
        raw: clean,
        normalized: normalizePlan(clean),
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
        if (prefixes.size >= 20) break;
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
  const clean = String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, 512);
  return clean === "" ? null : clean;
}

function cleanPlanValue(value) {
  if (value === undefined || value === null) return "";
  if (!["string", "number"].includes(typeof value)) return "";
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, 128);
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

  const plans = [...counts.values()]
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
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
    model: requestedModel,
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

  const key = validateApiKey(apiKey);
  const selectedModel = validateRequestedModel(requestedModel);
  if (selectedModel && containsSecret(selectedModel, [key])) {
    throw new AnalysisError("模型名称中不能包含 API Key。", {
      code: "secret_in_model",
    });
  }

  const config = validateConfig({
    ...DEFAULT_ANALYSIS_CONFIG,
    ...configOverride,
  });
  const endpoints = resolveApiEndpoints(baseUrl, { secret: key });
  const state = {
    status: "preparing",
    stage: "正在验证地址、密钥和所选模型",
    config,
    endpoints: {
      normalizedBaseUrl: endpoints.normalizedBaseUrl,
      responsesUrl: endpoints.responsesUrl,
    },
    selectedModel,
    modelSource: selectedModel ? "user_selected" : null,
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

  const modelInfo = await listAvailableModels({
    baseUrl,
    apiKey: key,
    fetchImpl,
    signal,
    timeoutMs: Math.min(config.requestTimeoutMs, 20_000),
  });
  if (
    selectedModel &&
    modelInfo.source === "models_endpoint" &&
    !modelInfo.models.includes(selectedModel)
  ) {
    throw new AnalysisError(
      "所选模型不在当前接口返回的模型列表中，请重新读取模型后再试。",
      {
        code: "model_not_available",
      },
    );
  }

  state.selectedModel = selectedModel || modelInfo.selected;
  state.modelSource = selectedModel ? "user_selected" : modelInfo.source;
  state.status = "running";
  state.stage = "正在执行首个有效性样本";
  notify();

  await runSingleSample({
    state,
    sampleIndex: 0,
    responsesUrl: endpoints.responsesUrl,
    apiKey: key,
    model: state.selectedModel,
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
  if (firstSample.status === "unknown") {
    const skippedRequests = Math.max(0, config.totalRequests - 1);
    throw new AnalysisError(
      `无法获取订阅数据：首个样本请求成功，但响应未返回 x-codex-plan-type 或 plan_type。已停止后续 ${skippedRequests} 次请求，请上游开放订阅字段透传。`,
      {
        code: "subscription_data_unavailable",
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
        model: state.selectedModel,
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

export async function listAvailableModels(options) {
  const {
    baseUrl,
    apiKey,
    fetchImpl = globalThis.fetch,
    signal,
    timeoutMs = 20_000,
  } = options;

  if (typeof fetchImpl !== "function") {
    throw new AnalysisError("当前 Node.js 环境不支持 fetch。", {
      code: "fetch_unavailable",
    });
  }

  const key = validateApiKey(apiKey);

  const endpoints = resolveApiEndpoints(baseUrl, { secret: key });
  const modelIds = await fetchModelIds({
    url: endpoints.modelsUrl,
    apiKey: key,
    fetchImpl,
    signal,
    timeoutMs,
  });
  const modelChoice = chooseModel(modelIds);

  return {
    target: endpoints.normalizedBaseUrl,
    models: modelChoice.candidates,
    selected: modelChoice.selected,
    source: modelChoice.source,
  };
}

export function validateRequestedModel(value) {
  const model = String(value ?? "").trim();
  if (!model) return null;
  if (model.length > 200 || /[\u0000-\u001f\u007f]/.test(model)) {
    throw new AnalysisError("所选模型名称无效。", {
      code: "invalid_model",
    });
  }
  return model;
}

export function validateApiKey(value) {
  const key = String(value ?? "").trim();
  if (!key) {
    throw new AnalysisError("请填写 API Key。", {
      code: "missing_api_key",
    });
  }
  if (
    key.length > MAX_API_KEY_LENGTH ||
    /[^\u0021-\u007e]/.test(key)
  ) {
    throw new AnalysisError("API Key 格式无效或长度超过限制。", {
      code: "invalid_api_key_format",
    });
  }
  return key;
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

  const text = await readLimitedResponseText(response);
  if (!response.ok) {
    const message = extractErrorMessage(text, [apiKey]);
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
    .map((model) => String(model ?? "").trim())
    .filter(isSafeModelId)
    .filter((model) => !containsSecret(model, [apiKey]))
    .slice(0, MAX_MODEL_COUNT);
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
  const reasoningEffort = fastestReasoningEffort(model);
  const requestBody = {
    model,
    input: [
      {
        role: "user",
        content: [
          {
            type: "input_text",
            text: "Reply exactly OK.",
          },
        ],
      },
    ],
    reasoning: {
      effort: reasoningEffort,
    },
    max_output_tokens: 16,
    store: false,
    stream: true,
    prompt_cache_key: sampleId,
  };
  sample.requestSummary = {
    method: "POST",
    endpoint: responsesUrl,
    protocol: "OpenAI Responses",
    headers: {
      accept: "text/event-stream",
      contentType: "application/json",
    },
    body: requestBody,
  };
  sample.failureDetails ??= [];

  for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
    throwIfCancelled(signal);
    sample.status = "running";
    sample.attempts = attempt;
    sample.nextRetryMs = null;
    sample.startedAt ??= new Date().toISOString();
    notify();

    const started = performance.now();
    const attemptStartedAt = new Date().toISOString();
    let response;
    try {
      response = await fetchImpl(responsesUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          Accept: "text/event-stream",
          "OpenAI-Beta": "responses=experimental",
          originator: "codex_cli_rs",
          "User-Agent": "codex-plan-scope/1.0",
          "session-id": sessionId,
          "thread-id": sessionId,
          "x-client-request-id": sessionId,
          "x-codex-window-id": sessionId,
        },
        body: JSON.stringify(requestBody),
        redirect: "manual",
        streamResponse: true,
        signal: combinedSignal(signal, config.requestTimeoutMs),
      });
    } catch (error) {
      const mapped = mapFetchError(error, "请求失败");
      appendFailureDetail(sample, {
        attempt,
        attemptStartedAt,
        latencyMs: performance.now() - started,
        error: mapped,
        secrets: [apiKey],
      });
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

    if (isRedirect(response.status)) {
      await response.body?.cancel?.().catch(() => {});
      const error = new AnalysisError(
        "接口发生重定向，为避免将 API Key 转发到其他地址已停止该样本。",
        {
          code: "unsafe_redirect",
          status: response.status,
        },
      );
      appendFailureDetail(sample, {
        attempt,
        attemptStartedAt,
        latencyMs: performance.now() - started,
        response,
        error,
        secrets: [apiKey],
      });
      completeFailedSample(
        sample,
        error,
        performance.now() - started,
      );
      notify();
      return;
    }

    if (!response.ok) {
      let text;
      try {
        text = await readLimitedResponseText(response);
      } catch (error) {
        const mapped = mapFetchError(error, "读取响应失败");
        appendFailureDetail(sample, {
          attempt,
          attemptStartedAt,
          latencyMs: performance.now() - started,
          response,
          error: mapped,
          secrets: [apiKey],
        });
        completeFailedSample(
          sample,
          mapped,
          performance.now() - started,
          response.status,
        );
        notify();
        return;
      }
      const error = new AnalysisError(
        extractErrorMessage(text, [apiKey]),
        {
          code: `http_${response.status}`,
          status: response.status,
          retryable: isRetryableStatus(response.status),
        },
      );
      appendFailureDetail(sample, {
        attempt,
        attemptStartedAt,
        latencyMs: performance.now() - started,
        response,
        responseBody: text,
        error,
        secrets: [apiKey],
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

      completeFailedSample(
        sample,
        error,
        performance.now() - started,
        response.status,
      );
      notify();
      return;
    }

    let readResult;
    try {
      readResult = await readResponsesPayload(response, {
        secrets: [apiKey],
      });
    } catch (error) {
      const mapped = mapFetchError(error, "读取 Responses 流失败");
      const responseTrace = mapped.streamTrace
        ? createResponseTrace(response, mapped.streamTrace, {
            attempt,
            occurredAt: attemptStartedAt,
            latencyMs: performance.now() - started,
            secrets: [apiKey],
          })
        : null;
      appendFailureDetail(sample, {
        attempt,
        attemptStartedAt,
        latencyMs: performance.now() - started,
        response,
        responseBody: mapped.diagnosticBody,
        responseTrace,
        error: mapped,
        secrets: [apiKey],
      });
      const canRetry =
        mapped.retryable && attempt < config.maxAttempts && !signal?.aborted;
      if (canRetry) {
        const waitMs = randomDelay(
          config.retryMinMs,
          config.retryMaxMs,
          random,
        );
        sample.status = "waiting_retry";
        sample.httpStatus = response.status;
        sample.nextRetryMs = waitMs;
        sample.error = serializeError(mapped);
        notify();
        await sleep(waitMs, signal);
        continue;
      }

      completeFailedSample(
        sample,
        mapped,
        performance.now() - started,
        response.status,
      );
      notify();
      return;
    }
    const latencyMs = Math.round(performance.now() - started);
    const { payload, streamTrace } = readResult;
    let planResult = extractPlanFromResponse(response.headers, payload);
    if (planResult && containsSecret(planResult.raw, [apiKey])) {
      planResult = null;
    }
    const evidence = redactStructuredSecrets(
      extractCodexEvidence(response.headers),
      [apiKey],
    );

    Object.assign(sample, {
      status: planResult?.normalized ? "classified" : "unknown",
      plan: planResult?.normalized ?? null,
      rawPlan: planResult?.raw ?? null,
      source: planResult?.source ?? null,
      httpStatus: response.status,
      latencyMs,
      evidence,
      responseTrace: createResponseTrace(response, streamTrace, {
        attempt,
        occurredAt: attemptStartedAt,
        latencyMs,
        secrets: [apiKey],
      }),
      error: null,
      nextRetryMs: null,
      completedAt: new Date().toISOString(),
    });
    notify();
    return;
  }
}

function appendFailureDetail(
  sample,
  {
    attempt,
    attemptStartedAt,
    latencyMs,
    response = null,
    responseBody = null,
    responseTrace = null,
    error,
    secrets = [],
  },
) {
  const body = createDiagnosticExcerpt(responseBody, {
    secrets,
    maxLength: MAX_FAILURE_RESPONSE_CHARS,
  });
  const headers = response?.headers;
  const responseDetail = response
    ? {
        status: Number(response.status) || null,
        statusText:
          sanitizeDiagnosticText(response.statusText, {
            secrets,
            maxLength: 120,
          }) || null,
        contentType:
          safeResponseHeader(headers, ["content-type"], secrets) || null,
        requestId:
          safeResponseHeader(
            headers,
            [
              "x-request-id",
              "openai-request-id",
              "x-oneapi-request-id",
              "request-id",
            ],
            secrets,
          ) || null,
        cfRay:
          safeResponseHeader(headers, ["cf-ray"], secrets) || null,
        retryAfter:
          safeResponseHeader(headers, ["retry-after"], secrets) || null,
        body: body.text || null,
        bodyTruncated: body.truncated,
      }
    : null;

  const failure = {
    attempt: Math.max(1, Math.trunc(Number(attempt) || 1)),
    occurredAt: attemptStartedAt,
    latencyMs: Math.max(0, Math.round(Number(latencyMs) || 0)),
    error: {
      ...serializeError(error),
      message: sanitizeDiagnosticText(error?.message, {
        secrets,
        maxLength: 600,
      }) || "未知错误",
    },
    response: responseDetail,
    responseTrace:
      responseTrace && typeof responseTrace === "object"
        ? redactStructuredSecrets(responseTrace, secrets)
        : null,
  };
  sample.failureDetails = [
    ...(Array.isArray(sample.failureDetails)
      ? sample.failureDetails
      : []),
    failure,
  ].slice(-MAX_FAILURE_DETAILS);
}

function safeResponseHeader(headers, names, secrets) {
  for (const name of names) {
    const value = headers?.get?.(name);
    const clean = sanitizeDiagnosticText(value, {
      secrets,
      maxLength: 512,
    });
    if (clean) return clean;
  }
  return "";
}

function createResponseTrace(
  response,
  streamTrace,
  {
    attempt,
    occurredAt,
    latencyMs,
    secrets = [],
  },
) {
  const headers = response?.headers;
  return redactStructuredSecrets(
    {
      attempt: Math.max(1, Math.trunc(Number(attempt) || 1)),
      occurredAt,
      latencyMs: Math.max(0, Math.round(Number(latencyMs) || 0)),
      status: Number(response?.status) || null,
      statusText:
        sanitizeDiagnosticText(response?.statusText, {
          secrets,
          maxLength: 120,
        }) || null,
      contentType:
        safeResponseHeader(headers, ["content-type"], secrets) || null,
      requestId:
        safeResponseHeader(
          headers,
          [
            "x-request-id",
            "openai-request-id",
            "x-oneapi-request-id",
            "request-id",
          ],
          secrets,
        ) || null,
      transport: streamTrace?.transport ?? null,
      terminalEvent: streamTrace?.terminalEvent ?? null,
      eventCount: streamTrace?.eventCount ?? 0,
      recordCount: streamTrace?.recordCount ?? 0,
      bodyBytes: streamTrace?.bodyBytes ?? null,
      doneMarker: streamTrace?.doneMarker === true,
      records: Array.isArray(streamTrace?.records)
        ? streamTrace.records
        : [],
    },
    secrets,
  );
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
    responseTrace: null,
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
  const inheritedDiagnostics = {
    diagnosticBody:
      typeof error?.diagnosticBody === "string"
        ? error.diagnosticBody
        : null,
    streamTrace:
      error?.streamTrace && typeof error.streamTrace === "object"
        ? error.streamTrace
        : null,
  };
  if (error?.code && error?.retryable === false) {
    return new AnalysisError(error.message || `${prefix}：请求被安全策略阻止。`, {
      code: error.code,
      retryable: false,
      cause: error,
      ...inheritedDiagnostics,
    });
  }
  if (error?.name === "AbortError") {
    return new AnalysisError(`${prefix}：请求已取消。`, {
      code: "request_aborted",
      retryable: false,
      cause: error,
      ...inheritedDiagnostics,
    });
  }
  if (error?.name === "TimeoutError") {
    return new AnalysisError(`${prefix}：请求超时。`, {
      code: "request_timeout",
      retryable: true,
      cause: error,
      ...inheritedDiagnostics,
    });
  }
  return new AnalysisError(`${prefix}：${error?.message ?? "网络错误"}`, {
    code: error?.code ?? "network_error",
    retryable: error?.retryable !== false,
    cause: error,
    ...inheritedDiagnostics,
  });
}

export async function readResponsesPayload(response, options = {}) {
  const maxBytes = Number.isFinite(options.maxBytes)
    ? Math.max(1, Math.floor(options.maxBytes))
    : MAX_UPSTREAM_BODY_BYTES;
  const secrets = Array.isArray(options.secrets) ? options.secrets : [];
  const contentType = String(
    response?.headers?.get?.("content-type") ?? "",
  ).toLowerCase();

  if (!contentType.includes("text/event-stream")) {
    const text = await readLimitedResponseText(response, maxBytes);
    if (looksLikeResponsesEventStream(text)) {
      const parser = createResponsesEventStreamParser(secrets);
      try {
        parser.push(text, true);
        return parser.finish({
          transport: "sse_compat",
          bodyBytes: Buffer.byteLength(text),
        });
      } catch (error) {
        attachStreamTrace(error, parser.trace({
          transport: "sse_compat",
          bodyBytes: Buffer.byteLength(text),
        }));
        throw error;
      }
    }
    const payload = safeJsonParse(text);
    return {
      payload,
      transport: "json_compat",
      terminalEvent: null,
      eventCount: 0,
      streamTrace: {
        transport: "json_compat",
        terminalEvent: null,
        eventCount: 0,
        recordCount: 1,
        bodyBytes: Buffer.byteLength(text),
        doneMarker: false,
        records: [
          {
            index: 1,
            event: "response.json",
            type: "response.json",
            data:
              payload === null
                ? sanitizeStreamText(text, secrets)
                : redactStructuredSecrets(payload, secrets),
          },
        ],
      },
    };
  }

  const declaredLength = Number(response?.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new AnalysisError("上游响应内容超过安全限制。", {
      code: "upstream_response_too_large",
    });
  }

  const reader = response?.body?.getReader?.();
  if (!reader) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maxBytes) {
      throw new AnalysisError("上游响应内容超过安全限制。", {
        code: "upstream_response_too_large",
      });
    }
    const parser = createResponsesEventStreamParser(secrets);
    try {
      parser.push(text, true);
      return parser.finish({
        transport: "sse",
        bodyBytes: Buffer.byteLength(text),
      });
    } catch (error) {
      attachStreamTrace(error, parser.trace({
        transport: "sse",
        bodyBytes: Buffer.byteLength(text),
      }));
      throw error;
    }
  }

  const decoder = new TextDecoder();
  const parser = createResponsesEventStreamParser(secrets);
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new AnalysisError("上游响应内容超过安全限制。", {
          code: "upstream_response_too_large",
        });
      }
      parser.push(decoder.decode(value, { stream: true }));
    }
    parser.push(decoder.decode(), true);
    return parser.finish({
      transport: "sse",
      bodyBytes: size,
    });
  } catch (error) {
    attachStreamTrace(error, parser.trace({
      transport: "sse",
      bodyBytes: size,
    }));
    await reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    reader.releaseLock?.();
  }
}

function createResponsesEventStreamParser(secrets) {
  let buffer = "";
  let eventName = "";
  let dataLines = [];
  let eventCount = 0;
  let terminalEvent = null;
  let terminalPayload = null;
  let sawDoneMarker = false;
  let sawText = false;
  let finished = false;
  const records = [];

  const dispatch = () => {
    if (dataLines.length === 0) {
      eventName = "";
      return;
    }

    const data = dataLines.join("\n").trim();
    const declaredEventName = eventName;
    dataLines = [];
    eventName = "";
    if (!data) return;
    if (data === "[DONE]") {
      sawDoneMarker = true;
      records.push({
        index: records.length + 1,
        event: declaredEventName || "done",
        type: "done",
        data: "[DONE]",
      });
      return;
    }

    let event;
    try {
      event = JSON.parse(data);
    } catch {
      const diagnostic = createDiagnosticExcerpt(data, {
        secrets,
        maxLength: MAX_FAILURE_RESPONSE_CHARS,
      });
      records.push({
        index: records.length + 1,
        event: declaredEventName || "message",
        type: "invalid_json",
        data: diagnostic.text,
      });
      throw new AnalysisError(
        "Responses 流包含无法解析的 SSE JSON 事件。",
        {
          code: "invalid_responses_stream_event",
          retryable: true,
          diagnosticBody: diagnostic.text,
        },
      );
    }

    eventCount += 1;
    if (eventCount > MAX_RESPONSES_STREAM_EVENTS) {
      throw new AnalysisError("Responses 流事件数量超过安全限制。", {
        code: "responses_stream_event_limit",
      });
    }

    const type = cleanStreamEventType(event?.type || declaredEventName);
    records.push({
      index: records.length + 1,
      event: cleanStreamEventType(declaredEventName) || type || "message",
      type: type || "message",
      data: redactStructuredSecrets(event, secrets),
    });
    if (type === "error" || type === "response.failed") {
      throw createResponsesStreamError(event, type, secrets);
    }
    if (
      type === "response.completed" ||
      type === "response.incomplete"
    ) {
      terminalEvent = type;
      terminalPayload = event?.response ?? event;
    }
  };

  const processLine = (line) => {
    if (line === "") {
      dispatch();
      return;
    }
    if (line.startsWith(":")) return;

    const separator = line.indexOf(":");
    const field =
      separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) value = value.slice(1);

    if (field === "event") {
      eventName = value;
    } else if (field === "data") {
      dataLines.push(value);
    }
  };

  const push = (text, flush = false) => {
    if (finished) {
      throw new AnalysisError("Responses 流已结束，不能继续写入事件。", {
        code: "invalid_responses_stream_state",
      });
    }

    let chunk = String(text ?? "");
    if (!sawText) {
      chunk = chunk.replace(/^\uFEFF/, "");
      sawText = true;
    }
    buffer += chunk;

    while (buffer.length > 0) {
      const lineFeed = buffer.indexOf("\n");
      const carriageReturn = buffer.indexOf("\r");
      let delimiter = -1;
      if (lineFeed === -1) {
        delimiter = carriageReturn;
      } else if (carriageReturn === -1) {
        delimiter = lineFeed;
      } else {
        delimiter = Math.min(lineFeed, carriageReturn);
      }
      if (delimiter === -1) break;
      if (
        buffer[delimiter] === "\r" &&
        delimiter === buffer.length - 1 &&
        !flush
      ) {
        break;
      }

      const line = buffer.slice(0, delimiter);
      const delimiterLength =
        buffer[delimiter] === "\r" &&
        buffer[delimiter + 1] === "\n"
          ? 2
          : 1;
      buffer = buffer.slice(delimiter + delimiterLength);
      processLine(line);
    }

    if (flush) {
      if (buffer) {
        processLine(buffer);
        buffer = "";
      }
      dispatch();
    }
  };

  const trace = ({
    transport = "sse",
    bodyBytes = null,
  } = {}) => ({
    transport,
    terminalEvent,
    eventCount,
    recordCount: records.length,
    bodyBytes:
      Number.isInteger(bodyBytes) && bodyBytes >= 0
        ? bodyBytes
        : null,
    doneMarker: sawDoneMarker,
    records,
  });

  const finish = (meta = {}) => {
    if (finished) {
      throw new AnalysisError("Responses 流被重复结束。", {
        code: "invalid_responses_stream_state",
      });
    }
    finished = true;
    if (!terminalEvent) {
      throw new AnalysisError(
        sawDoneMarker
          ? "Responses 流在终止标记前未返回完成事件。"
          : "Responses 流意外结束，未返回完成事件。",
        {
          code: "incomplete_responses_stream",
          retryable: true,
        },
      );
    }
    const streamTrace = trace(meta);
    return {
      payload: terminalPayload,
      transport: streamTrace.transport,
      terminalEvent,
      eventCount,
      streamTrace,
    };
  };

  return { push, finish, trace };
}

function attachStreamTrace(error, streamTrace) {
  if (
    error &&
    typeof error === "object" &&
    streamTrace &&
    typeof streamTrace === "object"
  ) {
    error.streamTrace = streamTrace;
  }
}

function sanitizeStreamText(value, secrets) {
  return redactSecrets(value, secrets)
    .replace(/\r\n?/g, "\n")
    .replace(
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,
      " ",
    );
}

function looksLikeResponsesEventStream(text) {
  return /^(?:\uFEFF)?\s*(?::|event:|data:)/.test(String(text ?? ""));
}

function cleanStreamEventType(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .toLowerCase()
    .slice(0, 128);
}

function createResponsesStreamError(event, type, secrets) {
  const response = event?.response;
  const error = event?.error ?? response?.error;
  const upstreamCode = String(
    event?.code ?? error?.code ?? response?.status ?? "",
  )
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, 128);
  const rawMessage = String(
    event?.message ??
      error?.message ??
      response?.incomplete_details?.reason ??
      "上游返回流式错误",
  )
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, 600);
  const retryText = `${upstreamCode} ${rawMessage}`.toLowerCase();
  const explicitlyPermanent =
    /(invalid|auth|permission|forbidden|billing|quota|unsupported)/.test(
      retryText,
    );

  return new AnalysisError(
    redactSecrets(
      `${type === "response.failed" ? "Responses 生成失败" : "Responses 流返回错误"}${upstreamCode ? `（${upstreamCode}）` : ""}：${rawMessage}`,
      secrets,
    ),
    {
      code: "responses_stream_error",
      retryable: !explicitlyPermanent,
      diagnosticBody: createDiagnosticExcerpt(
        JSON.stringify(event),
        {
          secrets,
          maxLength: MAX_FAILURE_RESPONSE_CHARS,
        },
      ).text,
    },
  );
}

async function readLimitedResponseText(
  response,
  maxBytes = MAX_UPSTREAM_BODY_BYTES,
) {
  const declaredLength = Number(response?.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new AnalysisError("上游响应内容超过安全限制。", {
      code: "upstream_response_too_large",
    });
  }

  const reader = response?.body?.getReader?.();
  if (!reader) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maxBytes) {
      throw new AnalysisError("上游响应内容超过安全限制。", {
        code: "upstream_response_too_large",
      });
    }
    return text;
  }

  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new AnalysisError("上游响应内容超过安全限制。", {
          code: "upstream_response_too_large",
        });
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock?.();
  }
}

function isSafeModelId(value) {
  return (
    Boolean(value) &&
    value.length <= MAX_MODEL_ID_LENGTH &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function extractErrorMessage(text, secrets = []) {
  const payload = safeJsonParse(text);
  const message =
    payload?.error?.message ??
    payload?.message ??
    payload?.error ??
    String(text ?? "").trim();
  return redactSecrets(
    String(message || "接口返回未知错误").slice(0, 2_000),
    secrets,
  ).slice(0, 600);
}

function redactStructuredSecrets(value, secrets) {
  if (typeof value === "string") {
    return redactSecrets(value, secrets);
  }
  if (Array.isArray(value)) {
    return value.map((entry) =>
      redactStructuredSecrets(entry, secrets),
    );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !SENSITIVE_STRUCTURED_FIELD.test(key))
        .map(([key, entry]) => [
          sanitizeDiagnosticText(key, {
            secrets,
            maxLength: 200,
          }),
          redactStructuredSecrets(entry, secrets),
        ]),
    );
  }
  return value;
}

function redactSecrets(value, secrets) {
  return redactSensitiveText(value, secrets);
}

function containsSecret(value, secrets) {
  const text = String(value ?? "");
  return secrets.some((secret) => {
    const candidate = String(secret ?? "");
    return (
      candidate.length >= 4 &&
      (text.includes(candidate) ||
        text.includes(encodeURIComponent(candidate)))
    );
  });
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
