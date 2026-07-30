const FIXED_TOTAL = 100;

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
  startButton: document.querySelector("#start-button"),
  cancelButton: document.querySelector("#cancel-button"),
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
  recordFilter: document.querySelector("#record-filter"),
  recordBody: document.querySelector("#record-body"),
  exportJson: document.querySelector("#export-json"),
  exportCsv: document.querySelector("#export-csv"),
};

let currentSnapshot = createInitialSnapshot();
let currentJobId = null;
let eventSource = null;
let elapsedTimer = null;
let selectedSampleIndex = null;

initialize();

function initialize() {
  buildSampleMatrix();
  wireInteractions();
  render(currentSnapshot);
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

async function startAnalysis(event) {
  event.preventDefault();
  hideError();

  const baseUrl = elements.baseUrl.value.trim();
  const apiKey = elements.apiKey.value.trim();
  if (!baseUrl || !apiKey) {
    showError("缺少必要信息", "请同时填写接口地址和 API Key。");
    (!baseUrl ? elements.baseUrl : elements.apiKey).focus();
    return;
  }

  closeEventStream();
  stopElapsedTimer();
  planColorRegistry.clear();
  selectedSampleIndex = null;
  currentJobId = null;
  currentSnapshot = {
    ...createInitialSnapshot(),
    status: "queued",
    stage: "正在创建本地分析任务",
    target: safeDisplayUrl(baseUrl),
    startedAt: new Date().toISOString(),
  };
  setBusy(true);
  render(currentSnapshot);

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseUrl, apiKey }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(payload?.error?.message || "无法创建分析任务。");
    }

    currentJobId = payload.jobId;
    elements.apiKey.value = "";
    startElapsedTimer();
    connectEventStream(payload.events);
  } catch (error) {
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
  eventSource = new EventSource(eventsPath);
  eventSource.addEventListener("snapshot", (event) => {
    try {
      currentSnapshot = JSON.parse(event.data);
      currentJobId = currentSnapshot.id;
      render(currentSnapshot);
      if (isTerminal(currentSnapshot.status)) {
        closeEventStream();
        stopElapsedTimer();
        setBusy(false);
        if (currentSnapshot.status === "failed") {
          showError(
            "分析未完成",
            currentSnapshot.error?.message || "上游接口未能完成采样。",
          );
        }
      }
    } catch {
      showError("数据解析失败", "本地服务返回了无法识别的进度数据。");
    }
  });
  eventSource.onerror = () => {
    if (!isTerminal(currentSnapshot.status)) {
      recoverSnapshot();
    }
  };
}

async function recoverSnapshot() {
  if (!currentJobId) return;
  closeEventStream();
  try {
    const response = await fetch(`/api/jobs/${currentJobId}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message);
    currentSnapshot = payload;
    render(currentSnapshot);
    if (!isTerminal(payload.status)) {
      window.setTimeout(
        () => connectEventStream(`/api/jobs/${currentJobId}/events`),
        900,
      );
    } else {
      stopElapsedTimer();
      setBusy(false);
    }
  } catch {
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
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message);
    currentSnapshot = payload;
    render(currentSnapshot);
    closeEventStream();
    stopElapsedTimer();
    setBusy(false);
  } catch (error) {
    elements.cancelButton.disabled = false;
    showError("停止失败", error?.message || "无法停止当前任务。");
  }
}

function render(snapshot) {
  registerPlanColors(snapshot.breakdown?.plans || []);
  renderStatus(snapshot);
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
  const label = JOB_LABELS[snapshot.status] || "等待输入";

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
    return `本次采样已结束，共识别 ${snapshot.breakdown?.classified || 0} 个有效订阅等级。`;
  }
  if (snapshot.status === "failed") {
    return "已保留失败前完成的样本，可在下方检查记录和具体原因。";
  }
  if (snapshot.status === "cancelled") {
    return "任务已停止，已完成的样本仍可查看和导出。";
  }
  if (snapshot.status === "queued" || snapshot.status === "preparing") {
    return "先验证地址、密钥和可用模型，避免直接触发大批量无效请求。";
  }
  return "正在并发采集独立样本；可点击已完成的格子查看订阅证据。";
}

function renderMetrics(breakdown = {}) {
  const total = breakdown.total || FIXED_TOTAL;
  const tierCount = breakdown.plans?.length || 0;

  setMetric(elements.completedMetric, breakdown.completed || 0, `/${total}`);
  elements.successMetric.textContent =
    breakdown.completed > 0
      ? `${breakdown.classified || 0} 个已识别 · ${breakdown.failed || 0} 个失败`
      : "等待开始采样";
  setMetric(elements.tierCountMetric, tierCount, "种");
  elements.tierCountCopy.textContent =
    tierCount > 0 ? "完全按接口返回值统计" : "按返回的 tier 自动去重";
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
  const sample =
    selectedSampleIndex === null
      ? null
      : currentSnapshot.samples?.[selectedSampleIndex];
  if (!sample) {
    elements.emptyEvidence.hidden = false;
    elements.evidenceList.hidden = true;
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

function setBusy(busy) {
  elements.startButton.disabled = busy;
  elements.startButton.firstElementChild.textContent = busy
    ? "分析正在进行"
    : "开始 100 次分析";
  elements.cancelButton.hidden = !busy;
  elements.cancelButton.disabled = false;
  elements.baseUrl.disabled = busy;
  elements.apiKey.disabled = busy;
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
    "error",
  ];
  const rows = (currentSnapshot.samples || []).map((sample) => [
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
    sample.error?.message || "",
  ]);
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
  return `"${text.replaceAll('"', '""')}"`;
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
