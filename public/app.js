const FIXED_TOTAL = 100;
const API_INTENT_HEADERS = Object.freeze({
  "X-PlanScope-Request": "1",
});

const PLAN_COLOR_PALETTE = Object.freeze([
  "#315be8",
  "#0b9b88",
  "#d99117",
  "#7656d6",
  "#287fa6",
  "#b44d78",
  "#527a38",
  "#b05d2f",
  "#4d63a8",
  "#776c24",
  "#3c7e72",
  "#9b4aa0",
]);
const planColorRegistry = new Map();

const STATUS_LABELS = Object.freeze({
  queued: "等待",
  running: "请求中",
  waiting_retry: "等待重试",
  classified: "已识别",
  unknown: "未识别",
  failed: "失败",
});

const JOB_LABELS = Object.freeze({
  queued: "已排队",
  preparing: "正在准备",
  running: "分析中",
  completed: "分析完成",
  failed: "分析失败",
  cancelled: "已取消",
});

const elements = {
  form: document.querySelector("#analysis-form"),
  baseUrl: document.querySelector("#base-url"),
  apiKey: document.querySelector("#api-key"),
  keyToggle: document.querySelector("#key-toggle"),
  modelSelect: document.querySelector("#model-select"),
  loadModels: document.querySelector("#load-models"),
  modelStatus: document.querySelector("#model-status"),
  startButton: document.querySelector("#start-button"),
  cancelButton: document.querySelector("#cancel-button"),
  protectionCopy: document.querySelector("#protection-copy"),
  verificationOverlay: document.querySelector("#verification-overlay"),
  verificationClose: document.querySelector("#verification-close"),
  verificationCancel: document.querySelector("#verification-cancel"),
  verificationSlider: document.querySelector("#verification-slider"),
  verificationTrack: document.querySelector("#verification-track"),
  verificationFill: document.querySelector("#verification-fill"),
  verificationTarget: document.querySelector("#verification-target"),
  verificationStatus: document.querySelector("#verification-status"),
  statusBadge: document.querySelector("#status-badge"),
  jobId: document.querySelector("#job-id"),
  stageTitle: document.querySelector("#stage-title"),
  stageDescription: document.querySelector("#stage-description"),
  targetMeta: document.querySelector("#target-meta"),
  modelMeta: document.querySelector("#model-meta"),
  elapsedMeta: document.querySelector("#elapsed-meta"),
  progressTrack: document.querySelector("#progress-track"),
  progressFill: document.querySelector("#progress-fill"),
  progressCopy: document.querySelector("#progress-copy"),
  attemptCopy: document.querySelector("#attempt-copy"),
  errorBanner: document.querySelector("#error-banner"),
  errorTitle: document.querySelector("#error-title"),
  errorMessage: document.querySelector("#error-message"),
  dismissError: document.querySelector("#dismiss-error"),
  resultNotice: document.querySelector("#result-notice"),
  completedMetric: document.querySelector("#completed-metric"),
  successMetric: document.querySelector("#success-metric"),
  tierCountMetric: document.querySelector("#tier-count-metric"),
  tierCountCopy: document.querySelector("#tier-count-copy"),
  classifiedMetric: document.querySelector("#classified-metric"),
  classifiedCount: document.querySelector("#classified-count"),
  unknownMetric: document.querySelector("#unknown-metric"),
  unknownCount: document.querySelector("#unknown-count"),
  failedMetric: document.querySelector("#failed-metric"),
  failedCount: document.querySelector("#failed-count"),
  latencyMetric: document.querySelector("#latency-metric"),
  sampleMatrix: document.querySelector("#sample-matrix"),
  matrixLegend: document.querySelector("#matrix-legend"),
  distributionDonut: document.querySelector("#distribution-donut"),
  donutValue: document.querySelector("#donut-value"),
  distributionLegend: document.querySelector("#distribution-legend"),
  selectedIndex: document.querySelector("#selected-index"),
  evidenceTitle: document.querySelector("#evidence-title"),
  emptyEvidence: document.querySelector("#empty-evidence"),
  evidenceList: document.querySelector("#evidence-list"),
  streamDetails: document.querySelector("#stream-details"),
  failureDetails: document.querySelector("#failure-details"),
  recordFilter: document.querySelector("#record-filter"),
  recordBody: document.querySelector("#record-body"),
  exportJson: document.querySelector("#export-json"),
  exportCsv: document.querySelector("#export-csv"),
};

let currentSnapshot = createInitialSnapshot();
let currentJobId = null;
let eventSource = null;
let eventStreamSession = 0;
let reconnectTimer = null;
let elapsedTimer = null;
let selectedSampleIndex = null;
let analysisBusy = false;
let modelLoading = false;
let modelsReady = false;
let modelListSource = null;
let verificationOpen = false;
let verificationBusy = false;
let verificationChallenge = null;
let verificationTrace = [];
let verificationStartedAt = null;
let verificationSession = 0;
let verificationReturnFocus = null;
let pendingAnalysis = null;
let cooldownUntil = 0;
let cooldownTimer = null;
const sampleDetailCache = new Map();
const sampleDetailRequests = new Map();
const sampleDetailErrors = new Map();
let sampleDetailSession = 0;

initialize();

function initialize() {
  buildSampleMatrix();
  wireInteractions();
  render(currentSnapshot);
  syncControls();
}

function createInitialSnapshot() {
  return {
    id: null,
    status: "idle",
    target: null,
    stage: "准备一次可信的分布采样",
    selectedModel: null,
    startedAt: null,
    completedAt: null,
    error: null,
    config: {
      totalRequests: FIXED_TOTAL,
      concurrency: 50,
      maxAttempts: 5,
      retryMinMs: 1_000,
      retryMaxMs: 3_000,
    },
    breakdown: {
      total: FIXED_TOTAL,
      completed: 0,
      pending: FIXED_TOTAL,
      classified: 0,
      unknown: 0,
      failed: 0,
      attempts: 0,
      successRate: 0,
      averageLatencyMs: null,
      plans: [],
      unknownPercent: 0,
      failedPercent: 0,
    },
    samples: Array.from({ length: FIXED_TOTAL }, (_, index) => ({
      index,
      status: "queued",
      attempts: 0,
    })),
  };
}

function buildSampleMatrix() {
  const fragment = document.createDocumentFragment();
  for (let index = 0; index < FIXED_TOTAL; index += 1) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sample-cell";
    button.dataset.index = String(index);
    button.textContent = String(index + 1).padStart(2, "0");
    button.setAttribute("aria-label", `样本 ${index + 1}：等待`);
    fragment.append(button);
  }
  elements.sampleMatrix.replaceChildren(fragment);
}

function wireInteractions() {
  elements.form.addEventListener("submit", startAnalysis);
  elements.cancelButton.addEventListener("click", cancelAnalysis);
  elements.keyToggle.addEventListener("click", toggleKeyVisibility);
  elements.loadModels.addEventListener("click", loadAvailableModels);
  elements.modelSelect.addEventListener("change", handleModelChange);
  elements.baseUrl.addEventListener("input", invalidateModelSelection);
  elements.apiKey.addEventListener("input", invalidateModelSelection);
  elements.verificationClose.addEventListener(
    "click",
    closeVerification,
  );
  elements.verificationCancel.addEventListener(
    "click",
    closeVerification,
  );
  elements.verificationOverlay.addEventListener(
    "click",
    handleVerificationBackdrop,
  );
  elements.verificationOverlay.addEventListener(
    "keydown",
    handleVerificationKeydown,
  );
  elements.verificationSlider.addEventListener(
    "pointerdown",
    beginVerificationTrace,
  );
  elements.verificationSlider.addEventListener(
    "keydown",
    beginKeyboardVerificationTrace,
  );
  elements.verificationSlider.addEventListener(
    "input",
    recordVerificationTrace,
  );
  elements.verificationSlider.addEventListener(
    "change",
    submitVerification,
  );
  window.addEventListener("resize", positionVerificationVisuals);
  elements.dismissError.addEventListener("click", hideError);
  elements.recordFilter.addEventListener("change", renderRecords);
  elements.exportJson.addEventListener("click", exportJson);
  elements.exportCsv.addEventListener("click", exportCsv);
  elements.sampleMatrix.addEventListener("click", (event) => {
    const cell = event.target.closest(".sample-cell");
    if (!cell) return;
    selectSample(Number(cell.dataset.index), true);
  });
  elements.recordBody.addEventListener("click", (event) => {
    const button = event.target.closest("[data-inspect]");
    if (!button) return;
    selectSample(Number(button.dataset.inspect), true);
  });
}

async function loadAvailableModels() {
  hideError();

  const baseUrl = elements.baseUrl.value.trim();
  let apiKey = elements.apiKey.value.trim();
  if (!baseUrl || !apiKey) {
    showError("缺少必要信息", "请先填写接口地址和 API Key，再读取模型。");
    (!baseUrl ? elements.baseUrl : elements.apiKey).focus();
    return;
  }

  modelLoading = true;
  modelsReady = false;
  modelListSource = null;
  resetModelSelect("正在读取模型…");
  setModelStatus("正在从当前接口读取可用模型…", "is-loading");
  syncControls();

  try {
    const response = await fetch("/api/models", {
      method: "POST",
      headers: {
        ...API_INTENT_HEADERS,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ baseUrl, apiKey }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw apiErrorFromPayload(
        payload,
        "无法读取模型列表。",
        response.status,
      );
    }

    const models = [
      ...new Set(
        (Array.isArray(payload?.models) ? payload.models : [])
          .map((model) => String(model ?? "").trim())
          .filter(Boolean),
      ),
    ];
    if (models.length === 0) {
      throw new Error("当前接口没有返回可供分析的模型。");
    }

    const recommended = models.includes(payload?.selected)
      ? payload.selected
      : models[0];
    const fragment = document.createDocumentFragment();
    for (const model of models) {
      const option = document.createElement("option");
      option.value = model;
      option.textContent =
        model === recommended ? `${model} — 推荐` : model;
      fragment.append(option);
    }
    elements.modelSelect.replaceChildren(fragment);
    elements.modelSelect.value = recommended;
    modelsReady = true;
    modelListSource = payload?.source || "models_endpoint";

    if (modelListSource === "fallback") {
      setModelStatus(
        `模型接口不可用，已加载 ${models.length} 个兼容候选；请确认中转支持 ${recommended}。`,
        "is-warning",
      );
    } else {
      setModelStatus(
        `已读取 ${models.length} 个模型，推荐 ${recommended}；可为本次分析改选。`,
        "is-success",
      );
    }
  } catch (error) {
    resetModelSelect("读取失败，请重试");
    setModelStatus(
      error?.message || "模型列表读取失败。",
      "is-error",
    );
    showError("无法读取模型", error?.message || "无法连接本地服务。");
  } finally {
    apiKey = "";
    modelLoading = false;
    syncControls();
  }
}

function handleModelChange() {
  const model = elements.modelSelect.value;
  if (!modelsReady || !model) {
    syncControls();
    return;
  }

  if (modelListSource === "fallback") {
    setModelStatus(
      `本次将使用 ${model}；这是兼容候选，接口未返回真实模型列表。`,
      "is-warning",
    );
  } else {
    setModelStatus(`本次分析将使用 ${model}。`, "is-success");
  }
  syncControls();
}

function invalidateModelSelection() {
  if (analysisBusy || modelLoading) return;
  if (
    !modelsReady &&
    !elements.modelSelect.value &&
    elements.modelSelect.options.length === 1
  ) {
    syncControls();
    return;
  }

  modelsReady = false;
  modelListSource = null;
  resetModelSelect("先读取可用模型");
  setModelStatus(
    "地址或密钥已变化，请重新读取模型；默认优先 GPT-5.5，其次 GPT-5.4。",
  );
  syncControls();
}

function resetModelSelect(label) {
  const option = document.createElement("option");
  option.value = "";
  option.textContent = label;
  elements.modelSelect.replaceChildren(option);
}

function setModelStatus(message, stateClass = "") {
  elements.modelStatus.textContent = message;
  elements.modelStatus.className =
    `field-hint model-status ${stateClass}`.trim();
}

async function openVerification() {
  const session = ++verificationSession;
  verificationReturnFocus = document.activeElement;
  verificationOpen = true;
  verificationBusy = true;
  elements.verificationOverlay.hidden = false;
  document.body.classList.add("is-verifying");
  syncControls();
  elements.verificationClose.focus();
  await loadVerificationChallenge(session);
}

async function loadVerificationChallenge(
  session,
  retryMessage = "",
) {
  verificationBusy = true;
  verificationChallenge = null;
  verificationTrace = [];
  verificationStartedAt = null;
  elements.verificationSlider.value = "0";
  elements.verificationSlider.disabled = true;
  elements.verificationTrack.className = "verification-track";
  positionVerificationVisuals();
  setVerificationStatus(
    retryMessage
      ? `${retryMessage} 正在刷新验证…`
      : "正在生成一次性验证…",
    retryMessage ? "is-error" : "is-checking",
  );
  syncControls();

  try {
    if (retryMessage) {
      await new Promise((resolve) => window.setTimeout(resolve, 550));
    }
    if (session !== verificationSession || !verificationOpen) return;

    const response = await fetch("/api/verification/challenge", {
      method: "POST",
      headers: API_INTENT_HEADERS,
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw apiErrorFromPayload(
        payload,
        "无法创建滑块验证。",
        response.status,
      );
    }
    if (session !== verificationSession || !verificationOpen) return;

    const target = Number(payload?.target);
    if (!Number.isFinite(target) || target < 0 || target > 1_000) {
      throw new Error("本地服务返回了无效的滑块位置。");
    }

    verificationChallenge = {
      id: String(payload.id),
      target,
      tolerance: Number(payload.tolerance) || 40,
    };
    verificationBusy = false;
    elements.verificationSlider.disabled = false;
    elements.verificationTrack.className = "verification-track";
    positionVerificationVisuals();
    setVerificationStatus(
      retryMessage
        ? "验证已刷新，请从左侧重新拖动"
        : "从最左侧开始拖动",
    );
    syncControls();
    elements.verificationSlider.focus();
  } catch (error) {
    if (session !== verificationSession || !verificationOpen) return;
    if (error?.retryAfterSeconds) {
      beginCooldown(
        Date.now() + error.retryAfterSeconds * 1_000,
      );
    }
    closeVerification();
    showError(
      error?.code === "rate_limited"
        ? "仍在安全冷却"
        : "无法开始验证",
      error?.message || "无法连接本地验证服务。",
    );
  }
}

function beginVerificationTrace() {
  if (verificationBusy || !verificationChallenge) return;
  verificationStartedAt = performance.now();
  verificationTrace = [
    [Number(elements.verificationSlider.value), 0],
  ];
  elements.verificationTrack.className = "verification-track";
  setVerificationStatus("正在记录拖动轨迹…");
}

function beginKeyboardVerificationTrace(event) {
  if (
    ![
      "ArrowLeft",
      "ArrowRight",
      "Home",
      "End",
      "PageUp",
      "PageDown",
    ].includes(event.key)
  ) {
    return;
  }
  if (verificationStartedAt === null) beginVerificationTrace();
}

function recordVerificationTrace() {
  if (verificationBusy || !verificationChallenge) return;
  if (verificationStartedAt === null) beginVerificationTrace();

  const position = Number(elements.verificationSlider.value);
  const elapsed = Math.max(
    0,
    Math.round((performance.now() - verificationStartedAt) * 10) / 10,
  );
  const previous = verificationTrace.at(-1);
  if (
    verificationTrace.length < 180 &&
    (!previous ||
      previous[0] !== position ||
      elapsed - previous[1] >= 16)
  ) {
    verificationTrace.push([position, elapsed]);
  }
  positionVerificationVisuals();
}

async function submitVerification() {
  if (
    verificationBusy ||
    !verificationChallenge ||
    verificationStartedAt === null
  ) {
    return;
  }

  recordVerificationTrace();
  const finalPosition = Number(elements.verificationSlider.value);
  if (
    Math.abs(finalPosition - verificationChallenge.target) >
    verificationChallenge.tolerance
  ) {
    elements.verificationTrack.classList.add("is-error");
    setVerificationStatus(
      "还没有与缺口对齐，请继续拖动",
      "is-error",
    );
    return;
  }

  const session = verificationSession;
  verificationBusy = true;
  elements.verificationSlider.disabled = true;
  elements.verificationTrack.className =
    "verification-track is-checking";
  setVerificationStatus("正在由服务端核验轨迹…", "is-checking");
  syncControls();

  try {
    const response = await fetch("/api/verification/verify", {
      method: "POST",
      headers: {
        ...API_INTENT_HEADERS,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        challengeId: verificationChallenge.id,
        finalPosition,
        trace: verificationTrace,
      }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw apiErrorFromPayload(
        payload,
        "滑块验证失败。",
        response.status,
      );
    }
    if (session !== verificationSession || !verificationOpen) return;

    elements.verificationTrack.className =
      "verification-track is-success";
    setVerificationStatus("验证通过，正在启动分析…", "is-success");
    await new Promise((resolve) => window.setTimeout(resolve, 260));
    if (session !== verificationSession || !verificationOpen) return;

    const analysis = pendingAnalysis;
    pendingAnalysis = null;
    closeVerification({
      keepPending: true,
      restoreFocus: false,
    });
    if (!analysis) {
      showError(
        "无法启动分析",
        "待分析信息已经失效，请重新点击开始分析。",
      );
      return;
    }
    await createAnalysis(analysis, payload.proof);
  } catch (error) {
    if (session !== verificationSession || !verificationOpen) return;
    if (error?.retryAfterSeconds) {
      beginCooldown(
        Date.now() + error.retryAfterSeconds * 1_000,
      );
      closeVerification();
      showError("仍在安全冷却", error.message);
      return;
    }
    await loadVerificationChallenge(
      session,
      error?.message || "滑块验证失败。",
    );
  }
}

function closeVerification(options = {}) {
  const keepPending = options?.keepPending === true;
  const restoreFocus = options?.restoreFocus !== false;
  verificationSession += 1;
  verificationOpen = false;
  verificationBusy = false;
  verificationChallenge = null;
  verificationTrace = [];
  verificationStartedAt = null;
  elements.verificationOverlay.hidden = true;
  elements.verificationSlider.disabled = true;
  document.body.classList.remove("is-verifying");
  if (!keepPending) pendingAnalysis = null;
  syncControls();

  if (
    restoreFocus &&
    verificationReturnFocus instanceof HTMLElement
  ) {
    verificationReturnFocus.focus();
  }
  verificationReturnFocus = null;
}

function handleVerificationBackdrop(event) {
  if (event.target === elements.verificationOverlay) {
    closeVerification();
  }
}

function handleVerificationKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeVerification();
    return;
  }
  if (event.key !== "Tab") return;

  const focusable = [
    elements.verificationClose,
    elements.verificationSlider,
    elements.verificationCancel,
  ].filter((element) => !element.disabled);
  if (focusable.length === 0) return;
  const currentIndex = focusable.indexOf(document.activeElement);
  const nextIndex =
    currentIndex === -1
      ? event.shiftKey
        ? focusable.length - 1
        : 0
      : event.shiftKey
        ? (currentIndex - 1 + focusable.length) % focusable.length
        : (currentIndex + 1) % focusable.length;
  event.preventDefault();
  focusable[nextIndex].focus();
}

function positionVerificationVisuals() {
  if (!elements.verificationTrack) return;
  const width = elements.verificationTrack.clientWidth;
  if (width <= 0) return;

  const thumbSize = window.matchMedia("(max-width: 620px)").matches
    ? 48
    : 44;
  const sliderPosition =
    Number(elements.verificationSlider.value || 0) / 1_000;
  const sliderCenter =
    thumbSize / 2 + (width - thumbSize) * sliderPosition;
  elements.verificationFill.style.width = `${sliderCenter}px`;

  if (verificationChallenge) {
    const targetCenter =
      thumbSize / 2 +
      (width - thumbSize) *
        (verificationChallenge.target / 1_000);
    elements.verificationTarget.style.left = `${targetCenter}px`;
  }
}

function setVerificationStatus(message, stateClass = "") {
  elements.verificationStatus.textContent = message;
  elements.verificationStatus.className =
    `verification-status ${stateClass}`.trim();
}

function apiErrorFromPayload(payload, fallbackMessage, status) {
  const error = new Error(payload?.error?.message || fallbackMessage);
  error.code = payload?.error?.code || "request_failed";
  error.status = status;
  error.retryAfterSeconds = Number(
    payload?.error?.retryAfterSeconds || 0,
  );
  return error;
}

function beginCooldown(value) {
  const timestamp =
    typeof value === "number" ? value : Date.parse(String(value));
  if (!Number.isFinite(timestamp)) return;
  cooldownUntil = Math.max(cooldownUntil, timestamp);
  if (cooldownTimer) window.clearInterval(cooldownTimer);
  cooldownTimer = window.setInterval(updateCooldownUi, 1_000);
  updateCooldownUi();
}

function updateCooldownUi() {
  const remaining = remainingCooldownMs();
  if (remaining <= 0) {
    cooldownUntil = 0;
    if (cooldownTimer) window.clearInterval(cooldownTimer);
    cooldownTimer = null;
    elements.protectionCopy.textContent =
      "启动前需完成滑块验证；同一 IP 或设备每 5 分钟仅可分析一次。";
  } else {
    elements.protectionCopy.textContent =
      `安全冷却中：${formatCooldown(remaining)} 后可再次分析。`;
  }
  syncControls();
}

function remainingCooldownMs() {
  return Math.max(0, cooldownUntil - Date.now());
}

function formatCooldown(milliseconds) {
  const totalSeconds = Math.max(
    0,
    Math.ceil(milliseconds / 1_000),
  );
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

async function startAnalysis(event) {
  event.preventDefault();
  hideError();

  const baseUrl = elements.baseUrl.value.trim();
  const apiKey = elements.apiKey.value.trim();
  const model = elements.modelSelect.value;
  if (!baseUrl || !apiKey) {
    showError("缺少必要信息", "请同时填写接口地址和 API Key。");
    (!baseUrl ? elements.baseUrl : elements.apiKey).focus();
    return;
  }
  if (!modelsReady || !model) {
    showError(
      "尚未选择模型",
      "请先读取当前接口的模型列表，并选择本次分析要使用的模型。",
    );
    elements.loadModels.focus();
    return;
  }
  if (remainingCooldownMs() > 0) {
    showError(
      "仍在安全冷却",
      `同一 IP 或设备每 5 分钟只能启动一次分析，请在 ${formatCooldown(remainingCooldownMs())} 后再试。`,
    );
    return;
  }

  pendingAnalysis = { baseUrl, apiKey, model };
  await openVerification();
}

async function createAnalysis(
  { baseUrl, apiKey, model },
  verificationProof,
) {
  hideError();

  closeEventStream();
  stopElapsedTimer();
  resetSampleDetails();
  planColorRegistry.clear();
  selectedSampleIndex = null;
  currentJobId = null;
  currentSnapshot = {
    ...createInitialSnapshot(),
    status: "queued",
    stage: "正在创建本地分析任务",
    target: safeDisplayUrl(baseUrl),
    selectedModel: model,
    startedAt: new Date().toISOString(),
  };
  setBusy(true);
  render(currentSnapshot);

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        ...API_INTENT_HEADERS,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        baseUrl,
        apiKey,
        model,
        verificationProof,
      }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw apiErrorFromPayload(
        payload,
        "无法创建分析任务。",
        response.status,
      );
    }

    currentJobId = payload.jobId;
    beginCooldown(payload.nextAllowedAt);
    elements.apiKey.value = "";
    modelsReady = false;
    modelListSource = null;
    setModelStatus(
      `本次已锁定 ${model}；下次运行请重新填写密钥并读取模型。`,
      "is-success",
    );
    syncControls();
    startElapsedTimer();
    connectEventStream(payload.events);
  } catch (error) {
    if (error?.retryAfterSeconds) {
      beginCooldown(
        Date.now() + error.retryAfterSeconds * 1_000,
      );
    }
    currentSnapshot.status = "failed";
    currentSnapshot.stage = "无法启动分析";
    currentSnapshot.error = {
      message: error?.message || "无法连接本地服务。",
    };
    setBusy(false);
    render(currentSnapshot);
    showError("无法启动分析", currentSnapshot.error.message);
  }
}

function connectEventStream(eventsPath) {
  closeEventStream();
  const session = eventStreamSession;
  const source = new EventSource(eventsPath);
  eventSource = source;
  source.addEventListener("snapshot", (event) => {
    if (session !== eventStreamSession || source !== eventSource) return;
    try {
      currentSnapshot = JSON.parse(event.data);
      currentJobId = currentSnapshot.id;
      render(currentSnapshot);
      if (isTerminal(currentSnapshot.status)) {
        finishTerminalAnalysis();
      }
    } catch {
      showError("数据解析失败", "本地服务返回了无法识别的进度数据。");
      recoverSnapshot(session);
    }
  });
  source.onerror = () => {
    if (session !== eventStreamSession || source !== eventSource) return;
    if (!isTerminal(currentSnapshot.status)) {
      recoverSnapshot(session);
    }
  };
}

async function recoverSnapshot(expectedSession = eventStreamSession) {
  if (
    !currentJobId ||
    expectedSession !== eventStreamSession
  ) {
    return;
  }
  const jobId = currentJobId;
  closeEventStream();
  const recoverySession = eventStreamSession;
  try {
    const response = await fetch(`/api/jobs/${jobId}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message);
    if (
      recoverySession !== eventStreamSession ||
      currentJobId !== jobId
    ) {
      return;
    }
    currentSnapshot = payload;
    render(currentSnapshot);
    if (!isTerminal(payload.status)) {
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        if (
          recoverySession === eventStreamSession &&
          currentJobId === jobId &&
          !isTerminal(currentSnapshot.status)
        ) {
          connectEventStream(`/api/jobs/${jobId}/events`);
        }
      }, 900);
    } else {
      finishTerminalAnalysis();
    }
  } catch {
    if (
      recoverySession !== eventStreamSession ||
      currentJobId !== jobId
    ) {
      return;
    }
    stopElapsedTimer();
    setBusy(false);
    showError(
      "进度连接已中断",
      "无法继续读取任务进度。任务可能仍在本地服务中执行。",
    );
  }
}

async function cancelAnalysis() {
  if (!currentJobId || isTerminal(currentSnapshot.status)) return;
  elements.cancelButton.disabled = true;
  try {
    const response = await fetch(`/api/jobs/${currentJobId}/cancel`, {
      method: "POST",
      headers: API_INTENT_HEADERS,
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message);
    currentSnapshot = payload;
    render(currentSnapshot);
    finishTerminalAnalysis({ showFailure: false });
  } catch (error) {
    elements.cancelButton.disabled = false;
    showError("停止失败", error?.message || "无法停止当前任务。");
  }
}

function render(snapshot) {
  if (
    selectedSampleIndex === null &&
    snapshot.status === "failed"
  ) {
    selectedSampleIndex =
      snapshot.samples?.find(
        (sample) => sample.status === "failed",
      )?.index ?? null;
  }
  registerPlanColors(snapshot.breakdown?.plans || []);
  renderStatus(snapshot);
  renderResultNotice(snapshot);
  renderMetrics(snapshot.breakdown);
  renderMatrix(snapshot.samples);
  renderMatrixLegend(snapshot.breakdown);
  renderDistribution(snapshot.breakdown);
  renderRecords();
  renderEvidence();

  const canExport =
    Boolean(snapshot.id) && (snapshot.breakdown?.completed ?? 0) > 0;
  elements.exportJson.disabled = !canExport;
  elements.exportCsv.disabled = !canExport;
}

function renderStatus(snapshot) {
  const breakdown = snapshot.breakdown || createInitialSnapshot().breakdown;
  const completed = breakdown.completed || 0;
  const total = breakdown.total || FIXED_TOTAL;
  const progress = Math.min(100, Math.round((completed / total) * 100));
  const label = isSubscriptionDataUnavailable(snapshot)
    ? "预检终止"
    : JOB_LABELS[snapshot.status] || "等待输入";

  elements.statusBadge.className = `status-badge is-${snapshot.status || "idle"}`;
  elements.statusBadge.lastChild.textContent = ` ${label}`;
  elements.jobId.textContent = snapshot.id
    ? `JOB ${snapshot.id.slice(0, 8).toUpperCase()}`
    : "JOB —";
  elements.stageTitle.textContent =
    snapshot.stage || "准备一次可信的分布采样";
  elements.stageDescription.textContent = statusDescription(snapshot);
  elements.targetMeta.textContent = snapshot.target || "—";
  elements.targetMeta.title = snapshot.target || "";
  elements.modelMeta.textContent = snapshot.selectedModel || "—";
  elements.modelMeta.title = snapshot.selectedModel || "";
  elements.elapsedMeta.textContent = formatElapsed(snapshot);
  elements.progressFill.style.width = `${progress}%`;
  elements.progressTrack.setAttribute("aria-valuenow", String(progress));
  elements.progressCopy.textContent = `已完成 ${completed} / ${total}`;
  elements.attemptCopy.textContent = `累计尝试 ${breakdown.attempts || 0} 次`;
}

function statusDescription(snapshot) {
  if (snapshot.status === "idle") {
    return "运行后，这里会实时显示模型验证、并发采样、随机重试与完成状态。";
  }
  if (snapshot.status === "completed") {
    if (needsPassThroughNotice(snapshot)) {
      return "分析已完成，但所有成功响应均未透传可识别的 Codex 订阅字段。";
    }
    return `本次采样已结束，共识别 ${snapshot.breakdown?.classified || 0} 个有效订阅等级。`;
  }
  if (snapshot.status === "failed") {
    if (isSubscriptionDataUnavailable(snapshot)) {
      return "首个样本未返回可识别的订阅字段，剩余 99 次请求未执行。";
    }
    return "任务已自动停止并关闭实时连接；失败前完成的样本仍可检查。";
  }
  if (snapshot.status === "cancelled") {
    return "任务已停止，已完成的样本仍可查看和导出。";
  }
  if (snapshot.status === "queued" || snapshot.status === "preparing") {
    return "先验证地址、密钥和可用模型，避免直接触发大批量无效请求。";
  }
  return "正在并发采集独立样本；可点击已完成的格子查看订阅证据。";
}

function isSubscriptionDataUnavailable(snapshot) {
  return snapshot?.error?.code === "subscription_data_unavailable";
}

function renderResultNotice(snapshot) {
  elements.resultNotice.hidden = !needsPassThroughNotice(snapshot);
}

function needsPassThroughNotice(snapshot) {
  const breakdown = snapshot?.breakdown;
  return (
    snapshot?.status === "completed" &&
    Number(breakdown?.classified || 0) === 0 &&
    Number(breakdown?.unknown || 0) > 0 &&
    (!Array.isArray(breakdown?.plans) ||
      breakdown.plans.length === 0)
  );
}

function renderMetrics(breakdown = {}) {
  const total = breakdown.total || FIXED_TOTAL;
  const tierCount = breakdown.plans?.length || 0;
  const missingPassThrough =
    tierCount === 0 &&
    Number(breakdown.classified || 0) === 0 &&
    Number(breakdown.unknown || 0) > 0;

  setMetric(elements.completedMetric, breakdown.completed || 0, `/${total}`);
  elements.successMetric.textContent =
    breakdown.completed > 0
      ? `${breakdown.classified || 0} 个已识别 · ${breakdown.failed || 0} 个失败`
      : "等待开始采样";
  setMetric(elements.tierCountMetric, tierCount, "种");
  elements.tierCountCopy.textContent =
    tierCount > 0
      ? "完全按接口返回值统计"
      : missingPassThrough
        ? "请上游开放订阅字段透传"
        : "按返回的 tier 自动去重";
  setMetric(
    elements.classifiedMetric,
    formatPercent(toPercent(breakdown.classified || 0, total)),
    "%",
  );
  elements.classifiedCount.textContent = `${breakdown.classified || 0} 个样本`;
  setMetric(
    elements.unknownMetric,
    formatPercent(breakdown.unknownPercent),
    "%",
  );
  elements.unknownCount.textContent = `${breakdown.unknown || 0} 个样本`;
  setMetric(
    elements.failedMetric,
    formatPercent(breakdown.failedPercent),
    "%",
  );
  elements.failedCount.textContent = `${breakdown.failed || 0} 个样本`;
  setMetric(
    elements.latencyMetric,
    breakdown.averageLatencyMs ?? "—",
    "ms",
  );
}

function renderMatrixLegend(breakdown = {}) {
  const items = (breakdown.plans || []).map((plan) => ({
    label: plan.label,
    color: colorForPlan(plan.key),
  }));
  if (breakdown.unknown > 0) {
    items.push({ label: "未识别", color: "#8997a2" });
  }
  if (breakdown.failed > 0) {
    items.push({ label: "失败", color: "#d25748" });
  }
  if (items.length === 0) {
    items.push({ label: "等待样本", color: "#c3cdd3" });
  }

  const fragment = document.createDocumentFragment();
  for (const item of items) {
    const wrapper = document.createElement("span");
    const swatch = document.createElement("i");
    swatch.style.background = item.color;
    wrapper.append(swatch, document.createTextNode(item.label));
    fragment.append(wrapper);
  }
  elements.matrixLegend.replaceChildren(fragment);
}

function setMetric(element, value, suffix) {
  element.replaceChildren(
    document.createTextNode(String(value)),
    Object.assign(document.createElement("small"), { textContent: suffix }),
  );
}

function renderMatrix(samples = []) {
  const cells = elements.sampleMatrix.children;
  for (let index = 0; index < FIXED_TOTAL; index += 1) {
    const sample = samples[index] || {
      index,
      status: "queued",
      attempts: 0,
    };
    const cell = cells[index];
    const status = sample.status || "queued";
    const planKey = sample.plan?.key || null;
    const planLabel = sample.plan?.label || null;
    const stateLabel = planLabel || STATUS_LABELS[status] || status;

    cell.className = `sample-cell is-${status}`;
    cell.classList.toggle("is-selected", selectedSampleIndex === index);
    cell.style.setProperty("--cell-color", colorForPlan(planKey));
    cell.setAttribute(
      "aria-label",
      `样本 ${index + 1}：${stateLabel}，尝试 ${sample.attempts || 0} 次`,
    );
    cell.title = `#${String(index + 1).padStart(3, "0")} · ${stateLabel} · ${sample.attempts || 0} 次尝试`;
  }
}

function renderDistribution(breakdown = {}) {
  const slices = [];
  for (const plan of breakdown.plans || []) {
    if (plan.count > 0) {
      slices.push({
        key: plan.key,
        label: plan.label,
        count: plan.count,
        percent: plan.percent,
        color: colorForPlan(plan.key),
      });
    }
  }
  if (breakdown.unknown > 0) {
    slices.push({
      key: "unknown",
      label: "未识别",
      count: breakdown.unknown,
      percent: breakdown.unknownPercent,
      color: "#8997a2",
    });
  }
  if (breakdown.failed > 0) {
    slices.push({
      key: "failed",
      label: "失败",
      count: breakdown.failed,
      percent: breakdown.failedPercent,
      color: "#d25748",
    });
  }
  if (breakdown.pending > 0) {
    slices.push({
      key: "pending",
      label: "尚未完成",
      count: breakdown.pending,
      percent: toPercent(breakdown.pending, breakdown.total || FIXED_TOTAL),
      color: "#e6ecef",
    });
  }

  let cursor = 0;
  const segments = slices.map((slice) => {
    const start = cursor;
    cursor += slice.percent;
    return `${slice.color} ${start}% ${cursor}%`;
  });
  elements.distributionDonut.style.background = segments.length
    ? `conic-gradient(${segments.join(", ")})`
    : "conic-gradient(#e6ecef 0 100%)";
  elements.distributionDonut.setAttribute(
    "aria-label",
    slices.length
      ? slices.map((slice) => `${slice.label} ${slice.percent}%`).join("，")
      : "尚无订阅分布",
  );
  elements.donutValue.textContent = String(breakdown.classified || 0);

  if (slices.length === 0 || (slices.length === 1 && slices[0].key === "pending")) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = "完成采样后显示订阅分布。";
    elements.distributionLegend.replaceChildren(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const slice of slices) {
    const row = document.createElement("div");
    row.className = "distribution-row";

    const label = document.createElement("span");
    const swatch = document.createElement("i");
    swatch.className = "distribution-swatch";
    swatch.style.background = slice.color;
    label.append(swatch, document.createTextNode(slice.label));

    const percent = document.createElement("strong");
    percent.textContent = `${formatPercent(slice.percent)}%`;
    const count = document.createElement("small");
    count.textContent = `${slice.count}/100`;
    row.append(label, percent, count);
    fragment.append(row);
  }
  elements.distributionLegend.replaceChildren(fragment);
}

function renderRecords() {
  const filter = elements.recordFilter.value;
  const samples = currentSnapshot.samples || [];
  const fragment = document.createDocumentFragment();

  for (const sample of samples) {
    if (!matchesFilter(sample, filter)) continue;
    const row = document.createElement("tr");
    row.classList.toggle("is-selected", sample.index === selectedSampleIndex);

    const indexCell = document.createElement("td");
    indexCell.className = "record-number";
    indexCell.textContent = `#${String(sample.index + 1).padStart(3, "0")}`;

    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = "record-status";
    status.style.setProperty("--record-color", statusColor(sample));
    status.textContent = STATUS_LABELS[sample.status] || sample.status;
    statusCell.append(status);

    const planCell = document.createElement("td");
    if (sample.plan?.label) {
      const plan = document.createElement("span");
      plan.className = "record-plan";
      plan.style.setProperty("--record-color", colorForPlan(sample.plan.key));
      plan.textContent = sample.plan.label;
      planCell.append(plan);
    } else {
      planCell.textContent = "—";
    }

    const attemptsCell = textCell(String(sample.attempts || 0));
    const httpCell = textCell(sample.httpStatus ?? "—");
    const latencyCell = textCell(
      Number.isFinite(sample.latencyMs) ? `${sample.latencyMs} ms` : "—",
    );
    const sourceCell = textCell(shortSource(sample.source));
    sourceCell.title = sample.source || "";

    const actionCell = document.createElement("td");
    const inspect = document.createElement("button");
    inspect.type = "button";
    inspect.className = "row-inspect";
    inspect.dataset.inspect = String(sample.index);
    inspect.textContent = "查看";
    inspect.setAttribute("aria-label", `查看样本 ${sample.index + 1} 的证据`);
    actionCell.append(inspect);

    row.append(
      indexCell,
      statusCell,
      planCell,
      attemptsCell,
      httpCell,
      latencyCell,
      sourceCell,
      actionCell,
    );
    fragment.append(row);
  }

  if (!fragment.childNodes.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.textContent = "当前筛选条件下没有请求记录。";
    cell.style.textAlign = "center";
    cell.style.padding = "28px";
    row.append(cell);
    fragment.append(row);
  }

  elements.recordBody.replaceChildren(fragment);
}

function renderEvidence() {
  const summary =
    selectedSampleIndex === null
      ? null
      : currentSnapshot.samples?.[selectedSampleIndex];
  const sample = resolveDetailedSample(summary);
  if (!sample) {
    elements.emptyEvidence.hidden = false;
    elements.evidenceList.hidden = true;
    elements.streamDetails.hidden = true;
    elements.streamDetails.replaceChildren();
    elements.failureDetails.hidden = true;
    elements.failureDetails.replaceChildren();
    elements.selectedIndex.textContent = "#—";
    elements.evidenceTitle.textContent = "样本证据";
    return;
  }

  elements.emptyEvidence.hidden = true;
  elements.evidenceList.hidden = false;
  elements.selectedIndex.textContent = `#${String(sample.index + 1).padStart(3, "0")}`;
  elements.evidenceTitle.textContent = sample.plan?.label
    ? `${sample.plan.label} · 订阅证据`
    : `${STATUS_LABELS[sample.status] || sample.status} · 样本证据`;

  const evidence = sample.evidence || {};
  const primary = evidence.primary || {};
  const credits = evidence.credits || {};
  const items = [
    ["样本状态", STATUS_LABELS[sample.status] || sample.status],
    ["订阅等级", sample.plan?.label || "未读取到"],
    ["原始 Tier", sample.rawPlan || "—"],
    ["命中字段", sample.source || "—", true],
    ["HTTP / 延迟", `${sample.httpStatus ?? "—"} / ${sample.latencyMs ?? "—"} ms`],
    ["尝试次数", String(sample.attempts || 0)],
    ["活跃限额", evidence.activeLimit || "—"],
    ["主窗口用量", formatUsageWindow(primary)],
    ["Credits", formatCredits(credits)],
    ["上游请求 ID", evidence.upstreamRequestId || "—", true],
  ];

  if (sample.error?.message) {
    items.push(["错误信息", sample.error.message, true]);
  }
  if (Array.isArray(evidence.additionalLimits) && evidence.additionalLimits.length) {
    items.push([
      "附加限额",
      evidence.additionalLimits
        .map(
          (limit) =>
            `${limit.name || limit.id}: ${formatUsageWindow(limit.primary)}`,
        )
        .join("；"),
      true,
    ]);
  }

  const fragment = document.createDocumentFragment();
  for (const [label, value, wide] of items) {
    const wrapper = document.createElement("div");
    if (wide) wrapper.className = "is-wide";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value;
    wrapper.append(term, detail);
    fragment.append(wrapper);
  }
  elements.evidenceList.replaceChildren(fragment);
  renderStreamDetails(sample);
  renderFailureDetails(sample);
  loadSampleDetailsIfNeeded(summary);
}

function renderStreamDetails(sample) {
  const trace = sample.responseTrace;
  elements.streamDetails.replaceChildren();
  elements.streamDetails.hidden =
    !trace || !Array.isArray(trace.records);
  if (elements.streamDetails.hidden) return;

  const heading = document.createElement("div");
  heading.className = "stream-details-heading";
  const title = document.createElement("h3");
  title.textContent =
    `完整流式响应 · ${trace.recordCount ?? trace.records.length} 条`;
  const note = document.createElement("p");
  note.textContent = [
    trace.transport || "未知传输",
    trace.terminalEvent || "无终态事件",
    Number.isFinite(trace.bodyBytes)
      ? formatBytes(trace.bodyBytes)
      : "大小未知",
  ].join(" · ");
  heading.append(title, note);

  elements.streamDetails.append(
    heading,
    createStreamMetaGrid(trace),
    createStreamRecordList(trace),
  );
}

function renderFailureDetails(sample) {
  const failures = Array.isArray(sample.failureDetails)
    ? sample.failureDetails
    : [];
  elements.failureDetails.replaceChildren();
  elements.failureDetails.hidden = failures.length === 0;
  if (failures.length === 0) return;

  const heading = document.createElement("div");
  heading.className = "failure-details-heading";
  const title = document.createElement("h3");
  title.textContent = `失败尝试 · ${failures.length}`;
  const note = document.createElement("p");
  note.textContent =
    "以下内容已移除 API Key、Authorization、Cookie 等敏感信息。";
  heading.append(title, note);
  elements.failureDetails.append(heading);

  failures.forEach((failure, failureIndex) => {
    const details = document.createElement("details");
    details.className = "failure-attempt";
    details.open = failureIndex === failures.length - 1;

    const summary = document.createElement("summary");
    const summaryTitle = document.createElement("strong");
    const status =
      failure.response?.status ??
      failure.error?.status ??
      null;
    summaryTitle.textContent =
      `尝试 ${failure.attempt || failureIndex + 1} · ${
        status ? `HTTP ${status}` : "未收到 HTTP 响应"
      }`;
    const summaryMeta = document.createElement("span");
    summaryMeta.textContent =
      `${failure.latencyMs ?? 0} ms · ${failure.error?.code || "unknown_error"}`;
    summary.append(summaryTitle, summaryMeta);
    details.append(summary);

    const content = document.createElement("div");
    content.className = "failure-attempt-content";
    content.append(
      createFailureMetaGrid(sample.requestSummary, failure),
      createDiagnosticBlock(
        "安全请求正文",
        formatRequestBody(sample.requestSummary?.body),
      ),
      createDiagnosticBlock(
        "上游返回报错",
        failure.response?.body ||
          failure.error?.message ||
          "上游未返回响应正文。",
        failure.response?.bodyTruncated,
      ),
    );
    if (failure.responseTrace) {
      content.append(
        createDiagnosticBlock(
          "失败前收到的流式记录",
          formatStreamRecords(failure.responseTrace),
          failure.responseTrace.truncated,
        ),
      );
    }
    details.append(content);
    elements.failureDetails.append(details);
  });
}

function createStreamMetaGrid(trace) {
  const grid = document.createElement("dl");
  grid.className = "failure-meta-grid stream-meta-grid";
  const items = [
    ["传输", trace.transport || "—"],
    ["终态事件", trace.terminalEvent || "—"],
    [
      "事件 / 记录",
      `${trace.eventCount ?? 0} / ${trace.recordCount ?? trace.records?.length ?? 0}`,
    ],
    [
      "响应大小",
      Number.isFinite(trace.bodyBytes)
        ? formatBytes(trace.bodyBytes)
        : "—",
    ],
    ["上游请求 ID", trace.requestId || "—"],
    [
      "HTTP / 耗时",
      `${trace.status ?? "—"} / ${trace.latencyMs ?? "—"} ms`,
    ],
  ];
  for (const [label, value] of items) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = value;
    wrapper.append(term, detail);
    grid.append(wrapper);
  }
  return grid;
}

function createStreamRecordList(trace) {
  const list = document.createElement("div");
  list.className = "stream-record-list";
  const records = Array.isArray(trace.records) ? trace.records : [];
  if (records.length === 0) {
    const empty = document.createElement("p");
    empty.className = "stream-record-empty";
    const detailError = sampleDetailErrors.get(
      sampleDetailKey(currentSnapshot.id, selectedSampleIndex),
    );
    empty.textContent = detailError
      ? `完整事件读取失败：${detailError}`
      : (trace.recordCount ?? 0) > 0
        ? "正在按需读取完整流式事件…"
        : "该响应没有可展示的流式事件。";
    list.append(empty);
    return list;
  }

  records.forEach((record, index) => {
    const details = document.createElement("details");
    details.className = "stream-record";
    details.open = index === records.length - 1;
    const summary = document.createElement("summary");
    const title = document.createElement("strong");
    title.textContent =
      `#${String(record.index ?? index + 1).padStart(3, "0")} · ${record.event || "message"}`;
    const type = document.createElement("span");
    type.textContent = record.type || "message";
    summary.append(title, type);
    const pre = document.createElement("pre");
    pre.textContent = formatStreamRecordData(record.data);
    details.append(summary, pre);
    list.append(details);
  });

  if (trace.truncated) {
    const warning = document.createElement("p");
    warning.className = "stream-record-warning";
    warning.textContent =
      "事件序列已达到安全存储上限，末尾记录未写入日志。";
    list.append(warning);
  }
  return list;
}

function formatStreamRecords(trace) {
  const records = Array.isArray(trace?.records)
    ? trace.records
    : [];
  if (records.length === 0) return "—";
  return records
    .map((record, index) => {
      const event = record.event || record.type || "message";
      return [
        `#${String(record.index ?? index + 1).padStart(3, "0")}`,
        `event: ${event}`,
        `data: ${formatStreamRecordData(record.data)}`,
      ].join("\n");
    })
    .join("\n\n");
}

function formatStreamRecordData(value) {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "事件内容无法格式化。";
  }
}

function createFailureMetaGrid(request, failure) {
  const response = failure.response || {};
  const grid = document.createElement("dl");
  grid.className = "failure-meta-grid";
  const items = [
    ["请求", `${request?.method || "POST"} ${request?.endpoint || "—"}`],
    ["协议", request?.protocol || "OpenAI Responses"],
    ["错误", failure.error?.message || "未知错误"],
    ["Content-Type", response.contentType || "—"],
    ["上游请求 ID", response.requestId || "—"],
    ["CF-Ray / Retry-After", `${response.cfRay || "—"} / ${response.retryAfter || "—"}`],
  ];
  for (const [label, value] of items) {
    const wrapper = document.createElement("div");
    if (label === "请求" || label === "错误") {
      wrapper.className = "is-wide";
    }
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = value;
    wrapper.append(term, detail);
    grid.append(wrapper);
  }
  return grid;
}

function createDiagnosticBlock(titleText, bodyText, truncated = false) {
  const section = document.createElement("section");
  section.className = "diagnostic-block";
  const heading = document.createElement("div");
  const title = document.createElement("h4");
  title.textContent = titleText;
  heading.append(title);
  if (truncated) {
    const badge = document.createElement("span");
    badge.textContent = "已截断至 4 KB";
    heading.append(badge);
  }
  const pre = document.createElement("pre");
  pre.textContent = bodyText || "—";
  section.append(heading, pre);
  return section;
}

function formatRequestBody(body) {
  if (!body) return "—";
  if (typeof body === "string") return body;
  try {
    return JSON.stringify(body, null, 2);
  } catch {
    return "请求正文无法格式化。";
  }
}

function selectSample(index, scrollToEvidence) {
  if (!Number.isInteger(index) || index < 0 || index >= FIXED_TOTAL) return;
  selectedSampleIndex = index;
  renderMatrix(currentSnapshot.samples);
  renderRecords();
  renderEvidence();
  if (scrollToEvidence && window.matchMedia("(max-width: 900px)").matches) {
    document
      .querySelector(".evidence-panel")
      .scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function resetSampleDetails() {
  sampleDetailSession += 1;
  sampleDetailCache.clear();
  sampleDetailRequests.clear();
  sampleDetailErrors.clear();
}

function sampleDetailKey(jobId, index) {
  return jobId && Number.isInteger(index)
    ? `${jobId}:${index}`
    : "";
}

function resolveDetailedSample(summary) {
  if (!summary) return null;
  const key = sampleDetailKey(currentSnapshot.id, summary.index);
  const cached = key ? sampleDetailCache.get(key) : null;
  if (
    cached &&
    cached.status === summary.status &&
    cached.attempts === summary.attempts
  ) {
    return cached;
  }
  return summary;
}

function loadSampleDetailsIfNeeded(summary) {
  if (
    !summary ||
    !currentSnapshot.id ||
    !["classified", "unknown", "failed"].includes(summary.status)
  ) {
    return;
  }
  const traces = [
    summary.responseTrace,
    ...(summary.failureDetails || []).map(
      (failure) => failure.responseTrace,
    ),
  ].filter(Boolean);
  if (
    !traces.some(
      (trace) =>
        (trace.recordCount ?? 0) >
        (Array.isArray(trace.records) ? trace.records.length : 0),
    )
  ) {
    return;
  }

  const jobId = currentSnapshot.id;
  const key = sampleDetailKey(jobId, summary.index);
  if (
    !key ||
    sampleDetailCache.has(key) ||
    sampleDetailRequests.has(key) ||
    sampleDetailErrors.has(key)
  ) {
    return;
  }

  const session = sampleDetailSession;
  const requestPromise = fetch(
    `/api/jobs/${encodeURIComponent(jobId)}/samples/${summary.index + 1}`,
  )
    .then(async (response) => {
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.sample) {
        throw apiErrorFromPayload(
          payload,
          "无法读取完整流式事件。",
          response.status,
        );
      }
      if (
        session !== sampleDetailSession ||
        currentSnapshot.id !== jobId
      ) {
        return;
      }
      sampleDetailCache.set(key, payload.sample);
      sampleDetailErrors.delete(key);
      if (selectedSampleIndex === summary.index) {
        renderEvidence();
      }
    })
    .catch((error) => {
      if (
        session !== sampleDetailSession ||
        currentSnapshot.id !== jobId
      ) {
        return;
      }
      sampleDetailErrors.set(
        key,
        error?.message || "样本明细已过期。",
      );
      if (selectedSampleIndex === summary.index) {
        renderEvidence();
      }
    })
    .finally(() => {
      sampleDetailRequests.delete(key);
    });
  sampleDetailRequests.set(key, requestPromise);
}

function setBusy(busy) {
  analysisBusy = busy;
  syncControls();
}

function finishTerminalAnalysis(options = {}) {
  const status = currentSnapshot.status;
  const showFailure = options.showFailure !== false;
  const subscriptionDataUnavailable =
    isSubscriptionDataUnavailable(currentSnapshot);
  closeEventStream();
  stopElapsedTimer();
  currentJobId = null;
  pendingAnalysis = null;
  modelsReady = false;
  modelListSource = null;
  resetModelSelect("先读取可用模型");

  if (status === "failed") {
    setModelStatus(
      subscriptionDataUnavailable
        ? "首个样本未返回订阅字段，剩余请求未执行。"
        : "分析已自动停止；请重新填写 API Key 并读取模型后重试。",
      "is-error",
    );
  } else if (status === "cancelled") {
    setModelStatus(
      "分析已停止；下次运行请重新填写 API Key 并读取模型。",
      "is-warning",
    );
  } else {
    setModelStatus(
      "分析已完成；下次运行请重新填写 API Key 并读取模型。",
      "is-success",
    );
  }

  setBusy(false);
  if (status === "failed" && showFailure) {
    showError(
      subscriptionDataUnavailable
        ? "无法获取订阅数据"
        : "分析已自动停止",
      currentSnapshot.error?.message || "上游接口未能完成采样。",
    );
  }
}

function syncControls() {
  const cooldownActive = remainingCooldownMs() > 0;
  const locked = analysisBusy || modelLoading || verificationOpen;
  elements.baseUrl.disabled = locked;
  elements.apiKey.disabled = locked;
  elements.keyToggle.disabled = locked;
  elements.loadModels.disabled = locked;
  elements.modelSelect.disabled = locked || !modelsReady;
  elements.startButton.disabled =
    locked ||
    cooldownActive ||
    !modelsReady ||
    !elements.modelSelect.value;
  elements.startButton.firstElementChild.textContent =
    analysisBusy
      ? "分析正在进行"
      : verificationOpen
        ? "等待滑块验证"
        : cooldownActive
          ? `安全冷却 ${formatCooldown(remainingCooldownMs())}`
          : !modelsReady
            ? "读取模型后开始分析"
            : "开始 100 次分析";
  elements.startButton.classList.toggle("is-busy", analysisBusy);
  elements.startButton.setAttribute(
    "aria-busy",
    String(analysisBusy),
  );
  elements.loadModels.textContent = modelLoading
    ? "读取中…"
    : modelsReady
      ? "重新读取"
      : "读取模型";
  elements.cancelButton.hidden = !analysisBusy;
  elements.cancelButton.disabled = false;
}

function toggleKeyVisibility() {
  const showing = elements.apiKey.type === "text";
  elements.apiKey.type = showing ? "password" : "text";
  elements.keyToggle.textContent = showing ? "显示" : "隐藏";
  elements.keyToggle.setAttribute("aria-pressed", String(!showing));
  elements.keyToggle.setAttribute(
    "aria-label",
    showing ? "显示 API Key" : "隐藏 API Key",
  );
}

function showError(title, message) {
  elements.errorTitle.textContent = title;
  elements.errorMessage.textContent = message;
  elements.errorBanner.hidden = false;
}

function hideError() {
  elements.errorBanner.hidden = true;
}

function startElapsedTimer() {
  stopElapsedTimer();
  elapsedTimer = window.setInterval(() => {
    elements.elapsedMeta.textContent = formatElapsed(currentSnapshot);
  }, 1_000);
}

function stopElapsedTimer() {
  if (elapsedTimer) window.clearInterval(elapsedTimer);
  elapsedTimer = null;
}

function closeEventStream() {
  eventStreamSession += 1;
  if (reconnectTimer) window.clearTimeout(reconnectTimer);
  reconnectTimer = null;
  if (eventSource) eventSource.close();
  eventSource = null;
}

function exportJson() {
  const payload = {
    exportedAt: new Date().toISOString(),
    jobId: currentSnapshot.id,
    target: currentSnapshot.target,
    status: currentSnapshot.status,
    model: currentSnapshot.selectedModel,
    startedAt: currentSnapshot.startedAt,
    completedAt: currentSnapshot.completedAt,
    config: currentSnapshot.config,
    breakdown: currentSnapshot.breakdown,
    samples: currentSnapshot.samples,
  };
  downloadFile(
    `planscope-${fileTimestamp()}.json`,
    JSON.stringify(payload, null, 2),
    "application/json",
  );
}

function exportCsv() {
  const headings = [
    "sample",
    "status",
    "plan",
    "raw_plan",
    "attempts",
    "http_status",
    "latency_ms",
    "source",
    "active_limit",
    "primary_used_percent",
    "primary_window_minutes",
    "upstream_request_id",
    "error_code",
    "error",
    "failure_request_id",
    "failure_response_body",
    "failure_response_truncated",
    "stream_transport",
    "stream_terminal_event",
    "stream_event_count",
  ];
  const rows = (currentSnapshot.samples || []).map((sample) => {
    const failure = sample.failureDetails?.at?.(-1);
    return [
      sample.index + 1,
      sample.status,
      sample.plan?.label || "",
      sample.rawPlan || "",
      sample.attempts || 0,
      sample.httpStatus ?? "",
      sample.latencyMs ?? "",
      sample.source || "",
      sample.evidence?.activeLimit || "",
      sample.evidence?.primary?.usedPercent ?? "",
      sample.evidence?.primary?.windowMinutes ?? "",
      sample.evidence?.upstreamRequestId || "",
      sample.error?.code || failure?.error?.code || "",
      sample.error?.message || failure?.error?.message || "",
      failure?.response?.requestId || "",
      failure?.response?.body || "",
      failure?.response?.bodyTruncated ? "true" : "false",
      sample.responseTrace?.transport || "",
      sample.responseTrace?.terminalEvent || "",
      sample.responseTrace?.recordCount ??
        sample.responseTrace?.records?.length ??
        0,
    ];
  });
  const csv = [headings, ...rows]
    .map((row) => row.map(csvCell).join(","))
    .join("\n");
  downloadFile(
    `planscope-${fileTimestamp()}.csv`,
    `\uFEFF${csv}`,
    "text/csv;charset=utf-8",
  );
}

function downloadFile(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  const text = String(value ?? "");
  const safeText = /^[\s]*[=+\-@]/.test(text)
    ? `'${text}`
    : text;
  return `"${safeText.replaceAll('"', '""')}"`;
}

function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  return cell;
}

function matchesFilter(sample, filter) {
  if (filter === "all") return true;
  if (filter === "pending") {
    return ["queued", "running", "waiting_retry"].includes(sample.status);
  }
  return sample.status === filter;
}

function colorForPlan(key) {
  if (!key) return "#8997a2";
  if (!planColorRegistry.has(key)) {
    const index = planColorRegistry.size;
    const color =
      PLAN_COLOR_PALETTE[index] ??
      `hsl(${Math.round((index * 137.508) % 360)} 58% 40%)`;
    planColorRegistry.set(key, color);
  }
  return planColorRegistry.get(key);
}

function registerPlanColors(plans) {
  for (const plan of plans) {
    if (plan?.key) colorForPlan(plan.key);
  }
}

function statusColor(sample) {
  if (sample.status === "classified") return colorForPlan(sample.plan?.key);
  if (sample.status === "failed") return "#d25748";
  if (sample.status === "unknown") return "#8997a2";
  if (sample.status === "waiting_retry") return "#d99117";
  if (sample.status === "running") return "#315be8";
  return "#c3cdd3";
}

function shortSource(source) {
  if (!source) return "—";
  return source
    .replace("response_header:", "header · ")
    .replace("response_body:", "body · ");
}

function formatUsageWindow(windowData = {}) {
  if (
    windowData.usedPercent === null ||
    windowData.usedPercent === undefined
  ) {
    return "—";
  }
  const windowText = windowData.windowMinutes
    ? ` / ${formatMinutes(windowData.windowMinutes)}`
    : "";
  return `${windowData.usedPercent}%${windowText}`;
}

function formatCredits(credits = {}) {
  if (credits.unlimited === true) return "无限";
  if (credits.balance !== null && credits.balance !== undefined) {
    return `余额 ${credits.balance}`;
  }
  if (credits.hasCredits === true) return "可用";
  if (credits.hasCredits === false) return "不可用";
  return "—";
}

function formatMinutes(minutes) {
  const value = Number(minutes);
  if (!Number.isFinite(value)) return `${minutes} 分钟`;
  if (value % 10_080 === 0) return `${value / 10_080} 周`;
  if (value % 1_440 === 0) return `${value / 1_440} 天`;
  if (value % 60 === 0) return `${value / 60} 小时`;
  return `${value} 分钟`;
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1_024) return `${Math.round(bytes)} B`;
  if (bytes < 1_024 * 1_024) {
    return `${(bytes / 1_024).toFixed(1)} KB`;
  }
  return `${(bytes / (1_024 * 1_024)).toFixed(1)} MB`;
}

function formatPercent(value) {
  return Number(value || 0).toFixed(1);
}

function toPercent(count, total) {
  if (!total) return 0;
  return Math.round((count / total) * 1_000) / 10;
}

function formatElapsed(snapshot) {
  if (!snapshot.startedAt) return "00:00";
  const start = new Date(snapshot.startedAt).getTime();
  const end = snapshot.completedAt
    ? new Date(snapshot.completedAt).getTime()
    : Date.now();
  const seconds = Math.max(0, Math.floor((end - start) / 1_000));
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

function safeDisplayUrl(value) {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return value;
  }
}

function fileTimestamp() {
  return new Date().toISOString().replaceAll(":", "-").replace(/\..+$/, "");
}

function isTerminal(status) {
  return ["completed", "failed", "cancelled"].includes(status);
}
