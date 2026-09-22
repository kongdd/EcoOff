const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
const fields = [$("interval"), $("allow"), $("allow-parent"), $("deny")];
let dirty = false;
let loaded = false;
let refreshing = false;
let toastTimer;
const collapsed = new Set();

fields.forEach((field) => field.addEventListener("input", () => { dirty = true; }));

function setText(id, value) {
  $(id).textContent = value;
}

function renderConfig(config) {
  if (loaded && dirty) return;
  $("interval").value = config.scan_interval_secs;
  $("allow").value = config.allow.join("\n");
  $("allow-parent").value = config.allow_parent.join("\n");
  $("deny").value = config.deny.join("\n");
  loaded = true;
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function renderProcesses(processes) {
  const nodes = new Map(processes.map((process) => [process.pid, { ...process, children: [] }]));
  const roots = [];
  nodes.forEach((node) => {
    const parent = nodes.get(node.parent_pid);
    if (parent && parent !== node) parent.children.push(node);
    else roots.push(node);
  });
  const sort = (items) => items.sort((a, b) =>
    a.name.localeCompare(b.name) || a.pid - b.pid);
  nodes.forEach((node) => sort(node.children));
  sort(roots);

  const rows = [];
  const append = (process, depth) => {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    const wrap = document.createElement("span");
    const toggle = document.createElement(process.children.length ? "button" : "span");
    wrap.className = "process-name";
    for (let i = 0; i < depth; i += 1) wrap.append(document.createElement("i"));
    toggle.className = process.children.length ? "tree-toggle" : "tree-space";
    if (process.children.length) {
      const closed = collapsed.has(process.pid);
      toggle.type = "button";
      toggle.classList.toggle("closed", closed);
      toggle.title = closed ? "展开" : "折叠";
      toggle.setAttribute("aria-expanded", String(!closed));
      toggle.addEventListener("click", () => {
        if (collapsed.has(process.pid)) collapsed.delete(process.pid);
        else collapsed.add(process.pid);
        renderProcesses(processes);
      });
    }
    wrap.append(toggle, document.createTextNode(process.name));
    name.append(wrap);

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `state${process.ok ? "" : " error"}`;
    badge.textContent = process.ok ? "已优化" : process.detail;
    status.append(badge);
    row.append(name, cell(process.pid), cell(process.parent), status);
    rows.push(row);
    if (!collapsed.has(process.pid)) {
      process.children.forEach((child) => append(child, depth + 1));
    }
  };
  roots.forEach((root) => append(root, 0));
  $("process-list").replaceChildren(...rows);
  $("process-empty").hidden = processes.length > 0;
  setText("process-badge", `${processes.length} 个`);
}

function render(data) {
  $("status-pill").classList.toggle("online", data.active);
  $("status-pill").lastChild.textContent = data.active ? "运行中" : "已停止";
  setText("last-scan", data.last_scan ? `最近扫描 ${data.last_scan}` : "正在首次扫描…");
  setText("matched-count", data.processes.length);
  setText("scanned-count", data.scanned || "—");
  setText("interval-count", data.config.scan_interval_secs);
  setText("config-path", `配置文件 · ${data.config_path}`);
  setText("log-path", data.log_path);
  renderProcesses(data.processes);
  renderConfig(data.config);

  const output = $("log-output");
  const follow = output.scrollHeight - output.scrollTop - output.clientHeight < 40;
  output.textContent = data.logs.length ? data.logs.join("\n") : "暂无日志";
  if (follow) output.scrollTop = output.scrollHeight;
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    render(await invoke("dashboard"));
  } catch (error) {
    $("status-pill").classList.remove("online");
    $("status-pill").lastChild.textContent = "连接失败";
    showToast(String(error), true);
  } finally {
    refreshing = false;
  }
}

function names(id) {
  return $(id).value.split(/\r?\n|,/).map((name) => name.trim()).filter(Boolean);
}

function showToast(message, error = false) {
  const toast = $("toast");
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.className = error ? "show error" : "show";
  toastTimer = setTimeout(() => { toast.className = ""; }, 2200);
}

$("save").addEventListener("click", async () => {
  const button = $("save");
  button.disabled = true;
  try {
    await invoke("save_config", {
      config: {
        scan_interval_secs: Number($("interval").value),
        allow: names("allow"),
        allow_parent: names("allow-parent"),
        deny: names("deny"),
      },
    });
    dirty = false;
    showToast("配置已保存并应用");
    await refresh();
  } catch (error) {
    showToast(String(error), true);
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll("nav a").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll("nav a").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});

refresh();
setInterval(refresh, 2000);
