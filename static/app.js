const state = {
  files: [],
  devices: [],
  ai: {
    enabled: false,
    configured: false,
  },
};

const els = {
  healthDot: document.querySelector("#health-dot"),
  healthText: document.querySelector("#health-text"),
  fileSelect: document.querySelector("#file-select"),
  deviceSelect: document.querySelector("#device-select"),
  severitySelect: document.querySelector("#severity-select"),
  limitSelect: document.querySelector("#limit-select"),
  compactCheck: document.querySelector("#compact-check"),
  keywordInput: document.querySelector("#keyword-input"),
  refreshBtn: document.querySelector("#refresh-btn"),
  analyzeBtn: document.querySelector("#analyze-btn"),
  aiBtn: document.querySelector("#ai-btn"),
  errorBox: document.querySelector("#error-box"),
  todayCount: document.querySelector("#today-count"),
  scanCount: document.querySelector("#scan-count"),
  alertCount: document.querySelector("#alert-count"),
  problemCount: document.querySelector("#problem-count"),
  rulesCount: document.querySelector("#rules-count"),
  latestTitle: document.querySelector("#latest-title"),
  latestMeta: document.querySelector("#latest-meta"),
  logsBody: document.querySelector("#logs-body"),
  logCountText: document.querySelector("#log-count-text"),
  analysisList: document.querySelector("#analysis-list"),
  analysisCountText: document.querySelector("#analysis-count-text"),
  aiStatusText: document.querySelector("#ai-status-text"),
  aiModeSelect: document.querySelector("#ai-mode-select"),
  aiPerDeviceSelect: document.querySelector("#ai-per-device-select"),
  aiResult: document.querySelector("#ai-result"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function query(params) {
  const result = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      result.set(key, value);
    }
  });
  return result.toString();
}

async function api(path, params = {}) {
  const qs = query(params);
  const response = await fetch(qs ? `${path}?${qs}` : path);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }
  return response.json();
}

function showError(error) {
  els.errorBox.textContent = error.message || String(error);
  els.errorBox.classList.remove("d-none");
}

function clearError() {
  els.errorBox.classList.add("d-none");
  els.errorBox.textContent = "";
}

function severityBadge(severity) {
  const safe = escapeHtml(severity || "info");
  return `<span class="badge-severity sev-${safe}">${safe}</span>`;
}

function filters(includeSeverity = true) {
  const params = {
    file: els.fileSelect.value,
    limit: els.limitSelect.value,
    keyword: els.keywordInput.value.trim(),
    device: els.deviceSelect.value,
    compact: els.compactCheck.checked,
  };
  if (includeSeverity) {
    params.severity = els.severitySelect.value;
  }
  return params;
}

async function loadHealth() {
  try {
    const data = await api("/health");
    els.healthDot.classList.add("ok");
    els.healthDot.classList.remove("bad");
    els.healthText.textContent = data.log_root_exists ? "服务正常" : "服务正常，日志目录未挂载";
    state.ai = data.ai || { enabled: false, configured: false };
    updateAIStatus();
  } catch (error) {
    els.healthDot.classList.add("bad");
    els.healthDot.classList.remove("ok");
    els.healthText.textContent = "服务异常";
    state.ai = { enabled: false, configured: false };
    updateAIStatus();
  }
}

function updateAIStatus() {
  if (!state.ai.enabled) {
    els.aiStatusText.textContent = "AI 模式未启用";
    els.aiBtn.disabled = true;
    return;
  }
  if (!state.ai.configured) {
    els.aiStatusText.textContent = "AI 已启用，但缺少 OPENAI_API_KEY";
    els.aiBtn.disabled = true;
    return;
  }
  els.aiStatusText.textContent = `已启用 · ${state.ai.model || "AI 模型"} · 最多 ${state.ai.max_lines || 1000} 行`;
  els.aiBtn.disabled = false;
}

async function loadFiles() {
  const data = await api("/api/files");
  state.files = data.files || [];
  state.devices = data.devices || [];

  const currentFile = els.fileSelect.value;
  els.fileSelect.innerHTML = '<option value="">全部日志</option>' + state.files.map((file) => {
    const label = `${file.path} (${formatBytes(file.size)})`;
    return `<option value="${escapeHtml(file.path)}">${escapeHtml(label)}</option>`;
  }).join("");
  if (state.files.some((item) => item.path === currentFile)) {
    els.fileSelect.value = currentFile;
  }

  const currentDevice = els.deviceSelect.value;
  els.deviceSelect.innerHTML = '<option value="">全部设备</option>' + state.devices.map((device) => {
    return `<option value="${escapeHtml(device)}">${escapeHtml(device)}</option>`;
  }).join("");
  if (state.devices.includes(currentDevice)) {
    els.deviceSelect.value = currentDevice;
  }
}

async function loadSummary() {
  const data = await api("/api/summary");
  els.todayCount.textContent = data.today_log_count ?? "-";
  els.scanCount.textContent = `最近扫描 ${data.scanned_log_count ?? 0} 行`;
  els.alertCount.textContent = data.alert_count ?? "-";
  els.problemCount.textContent = data.problem_count ?? "-";
  els.rulesCount.textContent = `规则 ${data.rules_count ?? 0} 条`;

  if (data.latest_serious_problem) {
    const issue = data.latest_serious_problem;
    els.latestTitle.textContent = issue.title || "未命名问题";
    els.latestMeta.textContent = `${issue.severity || "-"} · ${issue.end_time || "未知时间"}`;
  } else {
    els.latestTitle.textContent = "暂无";
    els.latestMeta.textContent = "未检测到严重问题";
  }
}

async function loadLogs() {
  els.logsBody.innerHTML = '<tr><td colspan="5" class="empty-cell">正在加载日志...</td></tr>';
  const data = await api("/api/logs", filters(true));
  const rawCount = data.raw_count ?? data.count ?? 0;
  if (data.compacted && rawCount !== data.count) {
    els.logCountText.textContent = `显示 ${data.count || 0} 条合并日志，来自 ${rawCount} 条原始日志`;
  } else {
    els.logCountText.textContent = `显示 ${data.count || 0} 条日志`;
  }

  if (!data.entries || data.entries.length === 0) {
    els.logsBody.innerHTML = '<tr><td colspan="5" class="empty-cell">没有匹配的日志</td></tr>';
    return;
  }

  els.logsBody.innerHTML = data.entries.map((entry) => {
    return `<tr>
      <td>${renderTime(entry)}</td>
      <td>${escapeHtml(entry.device || "-")}</td>
      <td>${severityBadge(entry.severity)}</td>
      <td>${renderSummary(entry)}</td>
      <td>${renderRawLog(entry)}</td>
    </tr>`;
  }).join("");
}

function renderTime(entry) {
  if (entry.grouped && entry.first_time && entry.last_time && entry.first_time !== entry.last_time) {
    return `<div>${escapeHtml(entry.first_time)}</div><div class="time-range">${escapeHtml(entry.last_time)}</div>`;
  }
  return escapeHtml(entry.time || "-");
}

function renderSummary(entry) {
  const summary = escapeHtml(entry.chinese_summary || "-");
  if (!entry.grouped || Number(entry.repeat_count || 1) <= 1) {
    return summary;
  }
  return `<div>${summary}</div><span class="repeat-pill">合并 ${Number(entry.repeat_count)} 条</span>`;
}

function renderRawLog(entry) {
  if (!entry.grouped || !entry.raw_samples || entry.raw_samples.length === 0) {
    return `<div class="raw-log">${escapeHtml(entry.raw || "")}</div>`;
  }
  const sourceFiles = (entry.source_files || []).filter(Boolean).join(", ");
  const samples = entry.raw_samples.map((item) => {
    return `<div class="raw-sample">${escapeHtml(item)}</div>`;
  }).join("");
  return `<div class="compact-meta">连续近似日志 · ${Number(entry.repeat_count || 0)} 条${sourceFiles ? ` · ${escapeHtml(sourceFiles)}` : ""}</div>${samples}`;
}

async function loadAnalysis() {
  els.analysisList.innerHTML = '<div class="empty-cell">正在分析问题...</div>';
  const params = filters(false);
  params.limit = Math.max(Number(params.limit || 500), 2000);
  const data = await api("/api/analyze", params);
  els.analysisCountText.textContent = `扫描 ${data.scanned_logs || 0} 条日志，发现 ${data.count || 0} 个问题`;

  if (!data.problems || data.problems.length === 0) {
    els.analysisList.innerHTML = '<div class="empty-cell">未检测到需要关注的问题</div>';
    return;
  }

  els.analysisList.innerHTML = data.problems.map(renderIssue).join("");
}

async function loadAIAnalysis() {
  clearError();
  els.aiResult.classList.remove("has-content");
  els.aiResult.classList.add("empty-cell");
  els.aiResult.textContent = "正在调用 AI 分析当前筛选日志...";
  els.aiBtn.disabled = true;
  try {
    const params = filters(true);
    params.ai_mode = els.aiModeSelect.value;
    params.per_device_limit = els.aiPerDeviceSelect.value;
    const data = await api("/api/ai-analyze", params);
    els.aiResult.classList.remove("empty-cell");
    els.aiResult.classList.add("has-content");
    const selection = data.selection || {};
    const deviceSummary = (selection.devices || [])
      .filter((item) => Number(item.selected || 0) > 0)
      .map((item) => `${item.device}: ${item.selected}/${item.available}`)
      .join("，");
    els.aiResult.textContent = [
      `模型：${data.model || "-"}`,
      `发送日志行数：${data.sent_lines || 0}（已脱敏）`,
      `选择模式：${selection.mode === "balanced" ? "按设备重要日志" : "当前最近日志"}`,
      selection.mode === "balanced" ? `每设备最多：${selection.per_device_limit || "-"} 条` : "",
      deviceSummary ? `设备覆盖：${deviceSummary}` : "",
      "",
      data.analysis || "AI 未返回内容",
    ].filter(Boolean).join("\n");
  } catch (error) {
    showError(error);
    els.aiResult.classList.add("empty-cell");
    els.aiResult.classList.remove("has-content");
    els.aiResult.textContent = "AI 分析失败，请检查服务端 ENABLE_AI、OPENAI_API_KEY、模型名和网络连接。";
  } finally {
    updateAIStatus();
  }
}

function renderIssue(issue) {
  const causes = (issue.possible_causes || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const steps = (issue.suggested_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const logs = (issue.related_logs || []).slice(0, 5).map((item) => {
    const prefix = [item.time, item.device, item.source_file].filter(Boolean).join(" · ");
    return `<div class="related-log">${escapeHtml(prefix)}\n${escapeHtml(item.raw)}</div>`;
  }).join("");

  return `<article class="issue">
    <div class="issue-header">
      <h3 class="issue-title">${escapeHtml(issue.title || "未命名问题")}</h3>
      ${severityBadge(issue.severity)}
    </div>
    <div class="issue-meta">
      ${escapeHtml(issue.start_time || "未知")} - ${escapeHtml(issue.end_time || "未知")}
      · 设备：${escapeHtml((issue.devices || []).join(", ") || "-")}
    </div>
    <div>${escapeHtml(issue.chinese_explanation || "")}</div>
    <div class="issue-section">
      <strong>可能原因</strong>
      <ul>${causes}</ul>
    </div>
    <div class="issue-section">
      <strong>建议处理步骤</strong>
      <ul>${steps}</ul>
    </div>
    <div class="issue-section">
      <strong>相关原始日志</strong>
      ${logs || '<div class="text-secondary small">无</div>'}
    </div>
  </article>`;
}

function formatBytes(bytes) {
  const size = Number(bytes || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

async function refreshAll() {
  clearError();
  try {
    await loadHealth();
    await loadFiles();
    await Promise.all([loadSummary(), loadLogs(), loadAnalysis()]);
  } catch (error) {
    showError(error);
  }
}

async function refreshLogsOnly() {
  clearError();
  try {
    await Promise.all([loadLogs(), loadSummary()]);
  } catch (error) {
    showError(error);
  }
}

async function refreshAnalysisOnly() {
  clearError();
  try {
    await Promise.all([loadAnalysis(), loadSummary()]);
  } catch (error) {
    showError(error);
  }
}

els.refreshBtn.addEventListener("click", refreshLogsOnly);
els.analyzeBtn.addEventListener("click", refreshAnalysisOnly);
els.aiBtn.addEventListener("click", loadAIAnalysis);
els.fileSelect.addEventListener("change", refreshAll);
els.deviceSelect.addEventListener("change", refreshLogsOnly);
els.severitySelect.addEventListener("change", refreshLogsOnly);
els.limitSelect.addEventListener("change", refreshLogsOnly);
els.compactCheck.addEventListener("change", refreshLogsOnly);
els.keywordInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    refreshLogsOnly();
  }
});

refreshAll();
