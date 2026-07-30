const API_HEADERS = Object.freeze({
  "X-PlanScope-Request": "1",
});

const STATUS_LABELS = Object.freeze({
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
});

const elements = {
  loading: document.querySelector("#admin-loading"),
  login: document.querySelector("#admin-login"),
  loginDescription: document.querySelector(
    "#admin-login-description",
  ),
  loginForm: document.querySelector("#admin-login-form"),
  password: document.querySelector("#admin-password"),
  passwordToggle: document.querySelector(
    "#admin-password-toggle",
  ),
  loginButton: document.querySelector("#admin-login-button"),
  loginMessage: document.querySelector("#admin-login-message"),
  dashboard: document.querySelector("#admin-dashboard"),
  refresh: document.querySelector("#admin-refresh"),
  logout: document.querySelector("#admin-logout"),
  filters: document.querySelector("#admin-filters"),
  query: document.querySelector("#history-query"),
  status: document.querySelector("#history-status"),
  count: document.querySelector("#history-count"),
  body: document.querySelector("#history-body"),
  more: document.querySelector("#history-more"),
  loaded: document.querySelector("#history-loaded"),
  error: document.querySelector("#admin-error"),
  errorCopy: document.querySelector("#admin-error-copy"),
  metricTotal: document.querySelector("#metric-total"),
  metricDomains: document.querySelector("#metric-domains"),
  metricCompleted: document.querySelector("#metric-completed"),
  metricCompletedCopy: document.querySelector(
    "#metric-completed-copy",
  ),
  metricRecent: document.querySelector("#metric-recent"),
  requestLogRefresh: document.querySelector(
    "#request-log-refresh",
  ),
  requestLogFilters: document.querySelector(
    "#request-log-filters",
  ),
  requestLogQuery: document.querySelector("#request-log-query"),
  requestLogMethod: document.querySelector("#request-log-method"),
  requestLogStatus: document.querySelector("#request-log-status"),
  requestLogCount: document.querySelector("#request-log-count"),
  requestLogBody: document.querySelector("#request-log-body"),
  requestLogMore: document.querySelector("#request-log-more"),
  requestLogLoaded: document.querySelector("#request-log-loaded"),
  requestLogError: document.querySelector("#request-log-error"),
  requestLogErrorCopy: document.querySelector(
    "#request-log-error-copy",
  ),
  requestLogTotal: document.querySelector("#request-log-total"),
  requestLogSuccess: document.querySelector(
    "#request-log-success",
  ),
  requestLogClientError: document.querySelector(
    "#request-log-client-error",
  ),
  requestLogServerError: document.querySelector(
    "#request-log-server-error",
  ),
  requestLogLatency: document.querySelector(
    "#request-log-latency",
  ),
  dialog: document.querySelector("#history-dialog"),
  dialogTitle: document.querySelector("#history-dialog-title"),
  dialogSubtitle: document.querySelector(
    "#history-dialog-subtitle",
  ),
  detailGrid: document.querySelector("#history-detail-grid"),
  distribution: document.querySelector("#history-distribution"),
};

let records = [];
let nextOffset = null;
let total = 0;
let busy = false;
let searchTimer = null;
let requestLogs = [];
let requestLogNextOffset = null;
let requestLogTotal = 0;
let requestLogSearchTimer = null;

initialize();

async function initialize() {
  wireInteractions();
  try {
    const session = await apiRequest("/api/admin/session");
    elements.loading.hidden = true;
    if (!session.enabled) {
      showLogin({ disabled: true });
      return;
    }
    if (!session.authenticated) {
      showLogin();
      return;
    }
    showDashboard();
    await loadHistory({ reset: true });
    await loadRequestLogs({ reset: true });
  } catch (error) {
    elements.loading.hidden = true;
    showLogin();
    setLoginMessage(error.message);
  }
}

function wireInteractions() {
  elements.loginForm.addEventListener("submit", login);
  elements.passwordToggle.addEventListener(
    "click",
    togglePassword,
  );
  elements.refresh.addEventListener("click", () =>
    loadHistory({ reset: true }),
  );
  elements.requestLogRefresh.addEventListener("click", () =>
    loadRequestLogs({ reset: true }),
  );
  elements.logout.addEventListener("click", logout);
  elements.filters.addEventListener("submit", (event) => {
    event.preventDefault();
    loadHistory({ reset: true });
  });
  elements.query.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(
      () => loadHistory({ reset: true }),
      260,
    );
  });
  elements.status.addEventListener("change", () =>
    loadHistory({ reset: true }),
  );
  elements.more.addEventListener("click", () =>
    loadHistory({ reset: false }),
  );
  elements.requestLogFilters.addEventListener(
    "submit",
    (event) => {
      event.preventDefault();
      loadRequestLogs({ reset: true });
    },
  );
  elements.requestLogQuery.addEventListener("input", () => {
    clearTimeout(requestLogSearchTimer);
    requestLogSearchTimer = setTimeout(
      () => loadRequestLogs({ reset: true }),
      260,
    );
  });
  elements.requestLogMethod.addEventListener("change", () =>
    loadRequestLogs({ reset: true }),
  );
  elements.requestLogStatus.addEventListener("change", () =>
    loadRequestLogs({ reset: true }),
  );
  elements.requestLogMore.addEventListener("click", () =>
    loadRequestLogs({ reset: false }),
  );
  elements.body.addEventListener("click", (event) => {
    const button = event.target.closest("[data-history-id]");
    if (!button) return;
    const record = records.find(
      (entry) => entry.id === button.dataset.historyId,
    );
    if (record) showDetails(record);
  });
  elements.dialog.addEventListener("click", (event) => {
    if (event.target === elements.dialog) elements.dialog.close();
  });
}

async function login(event) {
  event.preventDefault();
  if (busy) return;

  const password = elements.password.value;
  if (!password) {
    setLoginMessage("请输入管理密码。");
    elements.password.focus();
    return;
  }

  setBusy(true);
  setLoginMessage("");
  try {
    await apiRequest("/api/admin/login", {
      method: "POST",
      json: { password },
    });
    elements.password.value = "";
    showDashboard();
    setBusy(false);
    await loadHistory({ reset: true });
    await loadRequestLogs({ reset: true });
  } catch (error) {
    setLoginMessage(error.message);
    elements.password.focus();
    elements.password.select();
  } finally {
    setBusy(false);
  }
}

async function logout() {
  if (busy) return;
  setBusy(true);
  try {
    await apiRequest("/api/admin/logout", { method: "POST" });
  } catch {
    // Clearing the visible authenticated state is still safe if the
    // network response is interrupted.
  } finally {
    records = [];
    requestLogs = [];
    elements.dialog.close();
    showLogin();
    setBusy(false);
  }
}

async function loadHistory({ reset }) {
  if (busy) return;
  setBusy(true);
  hideError();
  if (reset) {
    records = [];
    nextOffset = 0;
    renderLoadingRow();
  }

  const params = new URLSearchParams({
    limit: "50",
    offset: String(nextOffset ?? 0),
  });
  const query = elements.query.value.trim();
  const status = elements.status.value;
  if (query) params.set("q", query);
  if (status) params.set("status", status);

  try {
    const result = await apiRequest(
      `/api/admin/history?${params.toString()}`,
    );
    records = reset
      ? result.records
      : [...records, ...result.records];
    nextOffset = result.nextOffset;
    total = result.total;
    renderHistory(result.stats);
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      setLoginMessage("管理会话已过期，请重新登录。");
      return;
    }
    showError(error.message);
    if (records.length === 0) renderErrorRow();
  } finally {
    setBusy(false);
  }
}

async function loadRequestLogs({ reset }) {
  if (busy) return;
  setBusy(true);
  hideRequestLogError();
  if (reset) {
    requestLogs = [];
    requestLogNextOffset = 0;
    renderRequestLogLoadingRow();
  }

  const params = new URLSearchParams({
    limit: "50",
    offset: String(requestLogNextOffset ?? 0),
  });
  const query = elements.requestLogQuery.value.trim();
  const method = elements.requestLogMethod.value;
  const status = elements.requestLogStatus.value;
  if (query) params.set("q", query);
  if (method) params.set("method", method);
  if (status) params.set("status", status);

  try {
    const result = await apiRequest(
      `/api/admin/request-logs?${params.toString()}`,
    );
    requestLogs = reset
      ? result.records
      : [...requestLogs, ...result.records];
    requestLogNextOffset = result.nextOffset;
    requestLogTotal = result.total;
    renderRequestLogs(result.stats, result.retentionSeconds);
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      setLoginMessage("管理会话已过期，请重新登录。");
      return;
    }
    showRequestLogError(error.message);
    if (requestLogs.length === 0) renderRequestLogErrorRow();
  } finally {
    setBusy(false);
  }
}

function renderRequestLogs(stats = {}, retentionSeconds = 86_400) {
  elements.requestLogBody.replaceChildren();

  if (requestLogs.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.className = "admin-table-state";
    cell.textContent =
      elements.requestLogQuery.value ||
      elements.requestLogMethod.value ||
      elements.requestLogStatus.value
        ? "没有符合当前筛选条件的请求日志。"
        : "最近 24 小时还没有请求日志。";
    row.append(cell);
    elements.requestLogBody.append(row);
  } else {
    const fragment = document.createDocumentFragment();
    for (const record of requestLogs) {
      fragment.append(createRequestLogRow(record));
    }
    elements.requestLogBody.append(fragment);
  }

  const retentionHours = Math.round(retentionSeconds / 3_600);
  elements.requestLogCount.textContent =
    `共 ${requestLogTotal} 条匹配记录；仅保留最近 ${retentionHours} 小时`;
  elements.requestLogLoaded.textContent =
    `已加载 ${requestLogs.length} / ${requestLogTotal} 条`;
  elements.requestLogMore.hidden = requestLogNextOffset === null;
  elements.requestLogTotal.textContent = String(stats.total ?? 0);
  elements.requestLogSuccess.textContent = String(
    stats.success ?? 0,
  );
  elements.requestLogClientError.textContent = String(
    stats.clientError ?? 0,
  );
  elements.requestLogServerError.textContent = String(
    stats.serverError ?? 0,
  );
  elements.requestLogLatency.textContent = Number.isFinite(
    stats.averageDurationMs,
  )
    ? formatDuration(stats.averageDurationMs)
    : "—";
}

function createRequestLogRow(record) {
  const row = document.createElement("tr");

  const dateCell = document.createElement("td");
  dateCell.className = "admin-date";
  const dateMain = document.createElement("strong");
  const dateSub = document.createElement("span");
  const date = formatDateParts(record.occurredAt);
  dateMain.textContent = date.date;
  dateSub.textContent = date.time;
  dateCell.append(dateMain, dateSub);

  const methodCell = document.createElement("td");
  const method = document.createElement("span");
  method.className =
    `admin-method is-${String(record.method).toLowerCase()}`;
  method.textContent = record.method;
  methodCell.append(method);

  const pathCell = document.createElement("td");
  pathCell.className = "admin-log-path";
  const path = document.createElement("code");
  path.textContent = record.path;
  path.title = record.path;
  pathCell.append(path);

  const statusCell = document.createElement("td");
  const status = document.createElement("span");
  status.className =
    `admin-http-status is-${Math.trunc(record.statusCode / 100)}xx`;
  status.textContent = String(record.statusCode);
  statusCell.append(status);

  const durationCell = document.createElement("td");
  durationCell.className = "admin-log-duration";
  durationCell.textContent = formatDuration(record.durationMs);

  const clientCell = document.createElement("td");
  clientCell.className = "admin-log-hash";
  clientCell.textContent = record.clientHash ?? "—";
  clientCell.title = record.clientHash ?? "";

  const deviceCell = document.createElement("td");
  deviceCell.className = "admin-log-hash";
  deviceCell.textContent = record.deviceHash ?? "—";
  deviceCell.title = record.deviceHash ?? "";

  const metaCell = document.createElement("td");
  metaCell.className = "admin-log-meta";
  const error = document.createElement("strong");
  const requestId = document.createElement("span");
  error.textContent = record.errorCode ?? "—";
  error.title = record.errorCode ?? "";
  requestId.textContent = record.requestId;
  requestId.title = record.requestId;
  metaCell.append(error, requestId);

  row.append(
    dateCell,
    methodCell,
    pathCell,
    statusCell,
    durationCell,
    clientCell,
    deviceCell,
    metaCell,
  );
  return row;
}

function renderHistory(stats) {
  renderMetrics(stats);
  elements.body.replaceChildren();

  if (records.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.className = "admin-table-state";
    cell.textContent =
      elements.query.value || elements.status.value
        ? "没有符合当前筛选条件的记录。"
        : "还没有分析记录。完成一次分析后，汇总结果会显示在这里。";
    row.append(cell);
    elements.body.append(row);
  } else {
    const fragment = document.createDocumentFragment();
    for (const record of records) {
      fragment.append(createHistoryRow(record));
    }
    elements.body.append(fragment);
  }

  elements.count.textContent = `共 ${total} 条匹配记录；历史中只保留汇总字段`;
  elements.loaded.textContent = `已加载 ${records.length} / ${total} 条`;
  elements.more.hidden = nextOffset === null;
}

function createHistoryRow(record) {
  const row = document.createElement("tr");

  const dateCell = document.createElement("td");
  dateCell.className = "admin-date";
  const dateMain = document.createElement("strong");
  const dateSub = document.createElement("span");
  const date = formatDateParts(record.completedAt ?? record.recordedAt);
  dateMain.textContent = date.date;
  dateSub.textContent = date.time;
  dateCell.append(dateMain, dateSub);

  const targetCell = document.createElement("td");
  targetCell.className = "admin-target";
  const domain = document.createElement("strong");
  domain.textContent = record.domain;
  domain.title = record.domain;
  const origin = document.createElement("span");
  origin.textContent = record.origin;
  origin.title = record.origin;
  targetCell.append(domain, origin);

  const modelCell = document.createElement("td");
  modelCell.textContent = record.model;
  modelCell.title = record.model;

  const statusCell = document.createElement("td");
  const status = document.createElement("span");
  status.className = `admin-status is-${record.status}`;
  status.textContent = STATUS_LABELS[record.status] ?? record.status;
  statusCell.append(status);

  const plansCell = document.createElement("td");
  plansCell.append(createPlanList(record));

  const samplesCell = document.createElement("td");
  samplesCell.textContent = `${record.completed} / ${record.total}`;

  const durationCell = document.createElement("td");
  durationCell.textContent = formatDuration(record.durationMs);

  const actionCell = document.createElement("td");
  const action = document.createElement("button");
  action.type = "button";
  action.className = "admin-detail-button";
  action.dataset.historyId = record.id;
  action.textContent = "查看";
  actionCell.append(action);

  row.append(
    dateCell,
    targetCell,
    modelCell,
    statusCell,
    plansCell,
    samplesCell,
    durationCell,
    actionCell,
  );
  return row;
}

function createPlanList(record) {
  const list = document.createElement("div");
  list.className = "admin-plan-list";
  const entries = [
    ...(record.plans ?? []),
    ...(record.unknownPercent > 0
      ? [
          {
            label: "未识别",
            percent: record.unknownPercent,
          },
        ]
      : []),
    ...(record.failedPercent > 0
      ? [{ label: "失败", percent: record.failedPercent }]
      : []),
  ];

  if (entries.length === 0) {
    const empty = document.createElement("span");
    empty.className = "admin-plan-pill";
    empty.textContent = "暂无结果";
    list.append(empty);
    return list;
  }

  for (const entry of entries.slice(0, 3)) {
    const pill = document.createElement("span");
    pill.className = "admin-plan-pill";
    const label = document.createElement("span");
    const value = document.createElement("strong");
    label.textContent = entry.label;
    value.textContent = `${formatPercent(entry.percent)}%`;
    pill.append(label, value);
    list.append(pill);
  }
  if (entries.length > 3) {
    const more = document.createElement("span");
    more.className = "admin-plan-pill";
    more.textContent = `+${entries.length - 3}`;
    list.append(more);
  }
  return list;
}

function renderMetrics(stats = {}) {
  elements.metricTotal.textContent = String(stats.total ?? 0);
  elements.metricDomains.textContent = String(stats.domains ?? 0);
  elements.metricCompleted.textContent = String(
    stats.completed ?? 0,
  );
  elements.metricCompletedCopy.textContent =
    `失败 ${stats.failed ?? 0} · 取消 ${stats.cancelled ?? 0}`;
  elements.metricRecent.textContent = String(stats.recent24h ?? 0);
}

function showDetails(record) {
  elements.dialogTitle.textContent = record.domain;
  elements.dialogSubtitle.textContent =
    `${formatFullDate(record.completedAt ?? record.recordedAt)} · ${record.model}`;
  elements.detailGrid.replaceChildren();

  const details = [
    ["任务状态", STATUS_LABELS[record.status] ?? record.status],
    ["完成样本", `${record.completed} / ${record.total}`],
    ["识别样本", String(record.classified)],
    ["未识别", String(record.unknown)],
    ["失败样本", String(record.failed)],
    ["累计尝试", String(record.attempts)],
    ["平均响应", formatLatency(record.averageLatencyMs)],
    ["任务耗时", formatDuration(record.durationMs)],
    ["错误代码", record.errorCode ?? "—"],
  ];
  for (const [label, value] of details) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    description.title = value;
    wrapper.append(term, description);
    elements.detailGrid.append(wrapper);
  }

  renderDistribution(record);
  elements.dialog.showModal();
}

function renderDistribution(record) {
  elements.distribution.replaceChildren();
  const entries = [
    ...(record.plans ?? []),
    {
      key: "unknown",
      label: "未识别",
      percent: record.unknownPercent,
      count: record.unknown,
    },
    {
      key: "failed",
      label: "失败",
      percent: record.failedPercent,
      count: record.failed,
    },
  ].filter((entry) => entry.percent > 0 || entry.count > 0);

  if (entries.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "该任务没有可展示的已完成样本。";
    elements.distribution.append(empty);
    return;
  }

  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "history-distribution-row";
    const label = document.createElement("span");
    const progress = document.createElement("progress");
    const value = document.createElement("span");
    label.textContent = entry.label;
    label.title = entry.label;
    progress.max = 100;
    progress.value = entry.percent;
    progress.setAttribute(
      "aria-label",
      `${entry.label} ${formatPercent(entry.percent)}%`,
    );
    value.textContent =
      `${formatPercent(entry.percent)}% · ${entry.count ?? 0}`;
    row.append(label, progress, value);
    elements.distribution.append(row);
  }
}

function showLogin({ disabled = false } = {}) {
  elements.loading.hidden = true;
  elements.dashboard.hidden = true;
  elements.login.hidden = false;
  elements.loginButton.disabled = disabled;
  elements.password.disabled = disabled;
  if (disabled) {
    elements.loginDescription.textContent =
      "管理后台当前未启用。请为服务配置至少 16 字节的 ADMIN_PASSWORD 后重新启动。";
    setLoginMessage("未配置管理密码，历史数据不会对外开放。");
  } else {
    elements.loginDescription.textContent =
      "输入启动服务时配置或输出的管理密码。密码只用于本次登录验证，不会写入浏览器存储或分析历史。";
    setLoginMessage("");
    setTimeout(() => elements.password.focus(), 0);
  }
}

function showDashboard() {
  elements.loading.hidden = true;
  elements.login.hidden = true;
  elements.dashboard.hidden = false;
  setLoginMessage("");
}

function togglePassword() {
  const visible = elements.password.type === "text";
  elements.password.type = visible ? "password" : "text";
  elements.passwordToggle.textContent = visible ? "显示" : "隐藏";
  elements.passwordToggle.setAttribute(
    "aria-label",
    visible ? "显示管理密码" : "隐藏管理密码",
  );
  elements.passwordToggle.setAttribute(
    "aria-pressed",
    String(!visible),
  );
  elements.password.focus();
}

function setBusy(value) {
  busy = value;
  elements.loginButton.disabled =
    value || elements.password.disabled;
  elements.refresh.disabled = value;
  elements.requestLogRefresh.disabled = value;
  elements.logout.disabled = value;
  elements.more.disabled = value;
  elements.requestLogMore.disabled = value;
}

function setLoginMessage(message) {
  elements.loginMessage.textContent = message;
}

function showError(message) {
  elements.error.hidden = false;
  elements.errorCopy.textContent = message;
}

function hideError() {
  elements.error.hidden = true;
  elements.errorCopy.textContent = "";
}

function showRequestLogError(message) {
  elements.requestLogError.hidden = false;
  elements.requestLogErrorCopy.textContent = message;
}

function hideRequestLogError() {
  elements.requestLogError.hidden = true;
  elements.requestLogErrorCopy.textContent = "";
}

function renderLoadingRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.className = "admin-table-state";
  cell.textContent = "正在读取历史记录…";
  row.append(cell);
  elements.body.replaceChildren(row);
}

function renderErrorRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.className = "admin-table-state";
  cell.textContent = "暂时无法读取记录，请稍后刷新。";
  row.append(cell);
  elements.body.replaceChildren(row);
}

function renderRequestLogLoadingRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.className = "admin-table-state";
  cell.textContent = "正在读取请求日志…";
  row.append(cell);
  elements.requestLogBody.replaceChildren(row);
}

function renderRequestLogErrorRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.className = "admin-table-state";
  cell.textContent = "暂时无法读取请求日志，请稍后刷新。";
  row.append(cell);
  elements.requestLogBody.replaceChildren(row);
}

async function apiRequest(path, options = {}) {
  const headers = { ...API_HEADERS };
  let body;
  if (Object.hasOwn(options, "json")) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  }

  const response = await fetch(path, {
    method: options.method ?? "GET",
    headers,
    body,
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(
      payload?.error?.message ?? `请求失败（HTTP ${response.status}）`,
    );
    error.status = response.status;
    error.code = payload?.error?.code;
    throw error;
  }
  return payload;
}

function formatDateParts(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { date: "—", time: "—" };
  return {
    date: new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(date),
    time: new Intl.DateTimeFormat("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(date),
  };
}

function formatFullDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "时间未知";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatDuration(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1_000) return `${value}ms`;
  const seconds = Math.round(value / 100) / 10;
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function formatLatency(value) {
  return Number.isFinite(value) ? `${value}ms` : "—";
}

function formatPercent(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(1) : "0.0";
}
