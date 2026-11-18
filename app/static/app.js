// Vanilla-JS front end. Three steps: (1) Generate plan  (2) Review + Approve  (3) Deploy / Undeploy + monitor.
// "Generate plan" chains the existing API calls: upload -> AI analysis -> read-only Discover (Kafka ->
// worker -> SSH) -> interface mapping -> configs -> review. Approve starts the deployment automatically.
// Manual editing lives under "Advanced".
const $ = (s) => document.querySelector(s);
const esc = (t) => String(t ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let PID = null, PROJECT = null, openJob = null, uploadedKey = null, JOBS = [];

function toast(msg, ms = 6000) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(t._h); t._h = setTimeout(() => (t.hidden = true), ms); }

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", ...(opts.headers || {}) } });
  const body = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) { const d = body?.detail ?? body; const err = new Error(typeof d === "string" ? d : (d.message || JSON.stringify(d))); err.detail = d; err.status = r.status; throw err; }
  return body;
}

async function busy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast("⚠ " + e.message); if (e.detail?.issues) renderIssueList($("#review"), e.detail.issues); }
  finally { btn.disabled = false; }
}

// local clock time + durations (the API stores UTC ISO timestamps)
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
function fmtDur(a, b) {
  if (!a || !b) return "";
  const s = Math.max(0, Math.round((new Date(b) - new Date(a)) / 1000));
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

// ---------------------------------------------------------------- status text next to "Generate plan"
// state: run (blue) | ok (green) | fail (red) | "" (hidden)
function status(state, text) {
  const el = $("#genStatus"); el.className = `status ${state || ""}`; el.textContent = text || ""; el.hidden = !text;
}
const STEP = { upload: "Uploading diagram", ai: "AI is analysing the diagram", discover: "Reading the routers' real interfaces",
  map: "Mapping the plan to the routers", generate: "Generating Cisco IOS / OSPF configs", review: "Running validation checks" };
const ORDER = Object.keys(STEP);
function step(k, detail = "") {
  status("run", `Step ${ORDER.indexOf(k) + 1}/${ORDER.length} · ${STEP[k]}…${detail ? " " + detail : ""}`);
}

// ---------------------------------------------------------------- 1 generate plan
$("#file").addEventListener("change", () => {
  const f = $("#file").files[0]; if (!f) return;
  $("#preview").src = URL.createObjectURL(f); $("#preview").hidden = false; $("#noPreview").hidden = true;
});

// ---------------------------------------------------------------- popup window for failures
class PipelineError extends Error { constructor(kind, message, detail) { super(message); this.kind = kind; this.detail = detail; } }

function showError({ title, message, detail = "", actions = [] }) {
  $("#errTitle").textContent = title; $("#errMsg").textContent = message;
  $("#errDetail").textContent = detail; $("#errMore").hidden = !detail;
  const box = $("#errActions"); box.innerHTML = "";
  for (const a of [...actions, { label: "Close" }]) {
    const b = document.createElement("button"); b.textContent = a.label; if (a.primary) b.className = "primary";
    b.onclick = () => { $("#errDialog").close(); if (a.run) a.run(); };
    box.appendChild(b);
  }
  if (!$("#errDialog").open) $("#errDialog").showModal();
}
window.addEventListener("error", (e) => showError({ title: "The page hit an unexpected error", message: "Reload the page (Ctrl+F5). If it happens again, send this message to the developer.", detail: String(e.message || e.error) }));
window.addEventListener("unhandledrejection", (e) => showError({ title: "Unexpected error", message: String(e.reason?.message || e.reason), detail: String(e.reason?.stack || "") }));

function explain(err) {
  const m = err.message || ""; const retry = { label: "Retry", primary: true, run: () => $("#btnGenerate").click() };
  if (err.kind === "ai") {
    const overloaded = /\b(503|429|UNAVAILABLE|busy|high demand|quota)\b/i.test(m);
    return { title: overloaded ? "Gemini is overloaded right now (HTTP 503)" : "AI analysis failed",
      message: overloaded ? "Google's servers are too busy to answer. This is on Google's side - your key and setup are fine. The app already retried and tried the free backup models. Wait a minute and click Retry, or continue with the sample plan."
                          : "The AI could not produce a usable plan. Retry, or continue with the sample plan and correct it under Advanced.",
      detail: m, actions: [retry, { label: "Use sample plan", run: useSampleThenGenerate }] };
  }
  if (err.kind === "discover") {
    const hint = /auth/i.test(m) ? "A router rejected the SSH login: check SSH_USERNAME / SSH_PASSWORD in .env and the router's 'username' + 'line vty 0 4 / login local'."
      : /unreachable|timeout|refused|no answer/i.test(m) ? "A router could not be reached: check that GNS3, the GNS3 VM and R1/R2 are running and ping 192.168.239.11/.12 works."
      : "Check the worker log: docker compose logs worker";
    return { title: "Could not read the routers", message: hint, detail: m, actions: [retry] };
  }
  if (err.kind === "map") return { title: "Your input is needed", message: m, actions: [{ label: "Open Advanced", primary: true, run: () => { openAdvanced(); $("#s-advanced").scrollIntoView({ behavior: "smooth" }); } }] };
  if (err.kind === "upload") return { title: "Choose a diagram first", message: m, actions: [{ label: "Choose file", primary: true, run: () => $("#file").click() }] };
  return { title: "Plan generation stopped", message: m, detail: JSON.stringify(err.detail || "", null, 2), actions: [retry] };
}

async function useSampleThenGenerate() {
  const s = await api("/api/samples/exam_plan");
  await api(`/api/projects/${PID}/extraction`, { method: "PUT", body: JSON.stringify({ extraction: s }) });
  $("#btnGenerate").click();
}

// ---------------------------------------------------------------- button: spinner + elapsed time
function startLoading(btn, verb) {
  btn.dataset.label = btn.textContent; btn.disabled = true; btn.classList.add("loading");
  const t0 = Date.now();
  const tick = () => { const s = Math.floor((Date.now() - t0) / 1000); btn.textContent = `${verb}… ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
  tick(); btn._timer = setInterval(tick, 1000);
}
function stopLoading(btn) { clearInterval(btn._timer); btn.classList.remove("loading"); btn.textContent = btn.dataset.label; btn.disabled = false; }

$("#btnGenerate").onclick = async (e) => {
  const btn = e.currentTarget; if (btn.disabled) return;
  startLoading(btn, "Generating");
  try { await runPipeline(); }
  catch (err) { status("fail", `✖ ${STEP[err.stage] || "Plan generation"} failed - ${err.kind === "ai" && /503|busy|UNAVAILABLE/i.test(err.message) ? "Gemini is overloaded (503)" : err.message.slice(0, 160)}`); showError(explain(err)); }
  finally { stopLoading(btn); await refresh().catch(() => {}); }
};

function fail(stage, kind, message, detail) { const e = new PipelineError(kind, message, detail); e.stage = stage; return e; }

async function runPipeline() {
  // 1. upload (new project only when a different file was chosen)
  const f = $("#file").files[0];
  const key = f ? `${f.name}|${f.size}|${f.lastModified}` : null;
  if (f && key !== uploadedKey) {
    step("upload", f.name);
    const fd = new FormData(); fd.append("file", f); fd.append("notes", $("#notes").value);
    const r = await fetch("/api/projects", { method: "POST", body: fd }); const b = await r.json();
    if (!r.ok) throw fail("upload", "upload", b.detail || "upload failed");
    PID = b.project_id; uploadedKey = key; location.hash = PID; PROJECT = null; JOBS = []; openJob = null;
  } else if (!PID) throw fail("upload", "upload", "Choose the topology diagram (PNG or JPG) in step 1, then click Generate plan.");
  PROJECT = await api(`/api/projects/${PID}`);

  // 2. AI analysis (skipped when an extraction already exists, e.g. after manual edits)
  if (!PROJECT.extraction) {
    step("ai");
    const t0 = Date.now(); let running = true;
    const poll = (async () => {  // live status from the server: model, retries, backups
      while (running) {
        try {
          const p = await api(`/api/projects/${PID}/progress`);
          if (running && p.message) step("ai", `(${Math.round((Date.now() - t0) / 1000)} s) ${p.message}`);
        } catch (_) { /* keep polling */ }
        await sleep(1000);
      }
    })();
    try { await api(`/api/projects/${PID}/extract`, { method: "POST" }); }
    catch (err) { running = false; await poll; throw fail("ai", "ai", err.message); }
    running = false; await poll;
    PROJECT = await api(`/api/projects/${PID}`);
  }
  const routers = PROJECT.extraction.devices.filter((d) => d.role === "router");

  // 3. discover real interface names on every router that has not been discovered yet
  const missing = routers.filter((r) => !PROJECT.discovery[r.hostname]);
  if (missing.length) {
    step("discover", `(job sent to Kafka for ${missing.map((r) => r.hostname).join(", ")})`);
    const { jobs } = await api(`/api/projects/${PID}/discover`, { method: "POST" });
    const results = await waitJobs(jobs, 180, (s) => step("discover", s));
    const failed = results.filter((j) => j.status !== "SUCCESS");
    if (failed.length) throw fail("discover", "discover", failed.map((j) => `${j.device}: ${j.message || j.status}`).join("; "));
    PROJECT = await api(`/api/projects/${PID}`);
  }

  // 4. mapping + router IDs
  step("map");
  if (routers.some((r) => r.interfaces.some((i) => !i.name))) {
    await api(`/api/projects/${PID}/mapping/suggest`, { method: "POST" });
    PROJECT = await api(`/api/projects/${PID}`);
  }
  const rts = PROJECT.extraction.devices.filter((d) => d.role === "router");
  const unmapped = rts.flatMap((r) => r.interfaces.filter((i) => !i.name).map((i) => `${r.hostname}/${i.ip}`));
  if (unmapped.length) { openAdvanced(); throw fail("map", "map", "The routers have fewer free interfaces than the plan needs. Pick the interfaces for " + unmapped.join(", ") + " under Advanced, click Save mapping, then Generate plan again."); }
  if (rts.some((r) => !r.router_id)) {
    step("map", "- waiting for you to confirm the router IDs in the popup");
    const ids = await askRouterIds(rts);
    if (!ids) throw fail("map", "map", "OSPF router IDs are required. Click Generate plan again and confirm them, or add them to the notes (e.g. 'R1 router-id 1.1.1.1').");
    rts.forEach((r) => { if (!r.router_id) r.router_id = ids[r.hostname]; });
  }
  const mapping = Object.fromEntries(rts.map((r) => [r.hostname, Object.fromEntries(r.interfaces.map((i) => [i.id, i.name]))]));
  const router_ids = Object.fromEntries(rts.map((r) => [r.hostname, r.router_id]));
  await api(`/api/projects/${PID}/mapping`, { method: "PUT", body: JSON.stringify({ mapping, router_ids }) });

  // 5. generate
  step("generate");
  try { await api(`/api/projects/${PID}/generate`, { method: "POST" }); }
  catch (err) { if (err.detail?.issues) renderIssueList($("#review"), err.detail.issues); throw fail("generate", "generate", "The plan has errors that must be fixed before configs can be generated: " + err.message, err.detail); }

  // 6. review
  step("review");
  const rev = await api(`/api/projects/${PID}/review`, { method: "POST" });
  await refresh().catch(() => {});
  $("#s-review").scrollIntoView({ behavior: "smooth" });
  if (!rev.ok) {
    const errs = rev.issues.filter((i) => i.level === "error");
    throw fail("review", "review", "The configs were generated but the checks found blocking errors: " +
      errs.map((i) => `${i.code} (${i.message})`).join("; "), { issues: errs });
  }
  const warn = rev.issues.filter((i) => i.level === "warning").length;
  status("ok", `✔ Plan ready - VALID${warn ? ` with ${warn} warning(s)` : ""}. Review the configs in step 2, then Approve.`);
}

async function waitJobs(ids, timeoutS, onTick) {
  const t0 = Date.now();
  while (true) {
    const jobs = await Promise.all(ids.map((id) => api(`/api/jobs/${id}`)));
    const done = jobs.filter((j) => ["SUCCESS", "FAILED"].includes(j.status));
    if (done.length === jobs.length) return jobs;
    if ((Date.now() - t0) / 1000 > timeoutS) return jobs.map((j) => (done.includes(j) ? j : { ...j, status: "TIMEOUT", message: "no answer from the worker" }));
    onTick("(" + jobs.map((j) => `${j.device} ${j.status}`).join(" · ") + ")");
    await sleep(1500);
  }
}

function openAdvanced() { $("#s-advanced").open = true; }

// Router IDs are not in diagrams; the admin confirms them in a popup (suggestion: R<n> -> n.n.n.n).
function askRouterIds(routers) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  $("#ridFields").innerHTML = routers.map((r) => {
    const n = +(r.hostname.match(/(\d+)$/) || [])[1];
    const sug = r.router_id || (n >= 1 && n <= 255 ? `${n}.${n}.${n}.${n}` : "");
    return `<label>${esc(r.hostname)} router-id <input data-dev="${esc(r.hostname)}" value="${esc(sug)}" placeholder="e.g. 1.1.1.1"></label>`;
  }).join("");
  const dlg = $("#ridDialog"); dlg.showModal();
  return new Promise((resolve) => {
    const done = (v) => { dlg.close(); $("#ridOk").onclick = $("#ridCancel").onclick = null; dlg.oncancel = null; resolve(v); };
    $("#ridCancel").onclick = () => done(null); dlg.oncancel = (e) => { e.preventDefault(); done(null); };
    $("#ridOk").onclick = () => {
      const ids = {}; let bad = false;
      document.querySelectorAll("#ridFields input").forEach((i) => {
        const v = i.value.trim(); i.classList.toggle("missing", !ipv4.test(v)); if (!ipv4.test(v)) bad = true; ids[i.dataset.dev] = v;
      });
      if (!bad && new Set(Object.values(ids)).size !== Object.keys(ids).length) { bad = true; toast("Each router needs a different router ID."); }
      if (!bad) done(ids);
    };
  });
}

// ---------------------------------------------------------------- 2 review + approve
function renderReview(v) {
  if (!v) { $("#review").innerHTML = '<p class="muted">Not generated yet - start with step 1.</p>'; return; }
  const reach = Object.entries(v.reachability || {}).map(([k, ok]) => `${esc(k)}: ${ok ? "✔ SSH reachable" : "✖ unreachable"}`).join(" · ");
  $("#review").innerHTML = `<p><span class="badge ${v.ok ? "SUCCESS" : "FAILED"}">${v.ok ? "VALID" : "BLOCKED"}</span> <span class="muted">checked ${esc(fmtTime(v.ts))} · ${reach}</span></p><ul class="issues">${
    v.issues.filter((i) => i.level !== "info" || i.code !== "MGMT_REACHABLE").map((i) => `<li class="${i.level}"><b>${esc(i.code)}</b> ${longText(i.message)}</li>`).join("") || '<li class="info">No problems found</li>'}</ul>`;
}
function renderIssueList(el, issues) {
  el.innerHTML = `<ul class="issues">${(issues || []).map((i) => `<li class="${i.level}"><b>${esc(i.code)}</b> ${longText(i.message)}</li>`).join("")}</ul>`;
}
// long texts (e.g. Gemini error messages) show a short preview with a "more" toggle
function longText(t, max = 140) {
  t = String(t ?? "");
  return t.length <= max ? esc(t) : `<details class="more"><summary>${esc(t.slice(0, max))}… <span class="muted">more</span></summary>${esc(t)}</details>`;
}
function renderPlanTable(p) {
  const ex = p.extraction; const tb = $("#planTable tbody");
  $("#planTable").hidden = !ex; $("#planEmpty").hidden = !!ex;
  if (!ex) { tb.innerHTML = ""; return; }
  const kind = Object.fromEntries((ex.links || []).map((l) => [l.id, l.kind]));
  tb.innerHTML = ex.devices.filter((d) => d.role === "router").flatMap((d) => [
    `<tr class="rid"><td><b>${esc(d.hostname)}</b></td><td colspan="4" class="muted">router-id ${esc(d.router_id || "—")} · management ${esc(p.discovery[d.hostname]?.mgmt_interface || "?")} (never touched)</td></tr>`,
    ...d.interfaces.map((i) => `<tr><td></td><td>${esc(i.name || "— unmapped —")}</td><td>${esc(i.ip)} / ${esc(i.mask)}</td><td>${esc(i.link)}</td><td>${kind[i.link] === "lan" ? "LAN (passive)" : "OSPF neighbour link"}</td></tr>`)]).join("");
}
function renderAmbiguities(ex) {
  const ul = $("#ambiguities");
  ul.innerHTML = (ex?.ambiguities || []).map((a, i) =>
    `<li class="${a.resolved ? "info" : "warning"}">${a.resolved ? "✔ " : "⚑ "}<b>${esc(a.field)}</b>: ${longText(a.issue)}` +
    (a.suggestion ? `<span class="muted sug">→ ${esc(a.suggestion)}</span>` : "") +
    (a.resolved ? "" : ` <button data-amb="${i}">Mark resolved</button>`) + "</li>").join("") ||
    (ex ? `<li class="info">No flags (confidence ${ex.confidence})</li>` : '<li class="empty">No flags yet - the AI lists anything it could not read here.</li>');
  ul.querySelectorAll("button[data-amb]").forEach((b) => (b.onclick = () => busy(b, async () => {
    await api(`/api/projects/${PID}/ambiguities/resolve`, { method: "POST", body: JSON.stringify({ index: +b.dataset.amb }) });
    if ((PROJECT?.configs || []).length) await api(`/api/projects/${PID}/review`, { method: "POST" });
    await refresh();
  })));
}
function renderConfigs(cfgs) {
  $("#configs").innerHTML = (cfgs || []).map((c) => `<div class="cfg"><h4><span>${esc(c.device)} <span class="muted">${c.deployable ? "router · deployable" : "host · set manually in VPCS"}</span></span>${
    c.approval ? `<span class="badge SUCCESS">APPROVED by ${esc(c.approval.approver)}</span>` : (c.deployable ? '<span class="badge PENDING">NOT APPROVED</span>' : "")}</h4><pre>${esc(c.text)}</pre><div class="muted" style="padding:4px 10px">sha256 ${esc(c.sha256.slice(0, 16))}…</div></div>`).join("");
}
$("#btnReview").onclick = (e) => busy(e.target, async () => { need(); await api(`/api/projects/${PID}/review`, { method: "POST" }); await refresh(); });
$("#btnApprove").onclick = (e) => busy(e.target, async () => {
  need();
  if (!$("#approver").value.trim()) { $("#approver").classList.add("missing"); throw new Error("choose / enter the approver name"); }
  if (!$("#ackWarn").checked) throw new Error("tick 'I have reviewed the configurations and flags' first");
  if (!confirm("Approve these configurations? Deployment to R1 and R2 starts automatically after approval.")) return;
  const r = await api(`/api/projects/${PID}/approve`, { method: "POST",
    body: JSON.stringify({ approver: $("#approver").value, acknowledge_warnings: $("#ackWarn").checked }) });
  await refresh(); toast(`Approved ${r.approved.map((a) => a.device).join(", ")} - deploying…`);
  $("#s-deploy").scrollIntoView({ behavior: "smooth" });
  await startDeploy();  // approval was the last human step; Kafka -> worker -> SSH -> verify run on their own
});
async function startDeploy() {
  try {
    const d = await api(`/api/projects/${PID}/deploy`, { method: "POST" });
    toast(`Batch ${d.batch_id.slice(0, 8)} sent to Kafka: ${d.jobs.map((j) => j.device).join(", ")}`); pollJobs();
  } catch (err) {
    showError({ title: "Deployment could not start", message: err.message, detail: JSON.stringify(err.detail || "", null, 2),
      actions: [{ label: "Retry deploy", primary: true, run: startDeploy }] });
  }
}

// ---------------------------------------------------------------- 3 deploy / undeploy + monitor
$("#btnDeploy").onclick = (e) => busy(e.target, async () => {
  need(); if (!confirm("Send the approved configurations to Kafka for deployment?")) return;
  await startDeploy();
});

// Undeploy: explicit approval (name + confirm) -> reset jobs on Kafka -> worker re-checks -> SSH
$("#btnUndeploy").onclick = () => {
  if (!PID) { toast("Open or generate a project first (step 1)."); return; }
  $("#undApprover").value = $("#approver").value || ""; $("#undDialog").showModal(); $("#undApprover").focus();
};
$("#undCancel").onclick = () => $("#undDialog").close();
$("#undOk").onclick = async () => {
  const who = $("#undApprover").value.trim();
  if (!who) { $("#undApprover").classList.add("missing"); return; }
  $("#undDialog").close();
  try {
    const r = await api(`/api/projects/${PID}/undeploy`, { method: "POST", body: JSON.stringify({ approver: who }) });
    toast(`Undeploy approved by ${who} - reset jobs sent to Kafka for ${r.jobs.map((j) => j.device).join(", ")}`); pollJobs();
  } catch (err) {
    showError({ title: "Undeploy could not start", message: err.message, detail: JSON.stringify(err.detail || "", null, 2), actions: [] });
  }
};

// green / red banner for the latest deployment or undeploy
function renderFinal() {
  const all = (js, s) => js.length && js.every((j) => j.status === s); const anyS = (js, s) => js.some((j) => j.status === s);
  const acts = JOBS.filter((j) => ["deploy", "reset"].includes(j.job_type)).sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  const batch = acts[0]?.batch_id; const fin = $("#final");
  if (!batch) { fin.innerHTML = ""; return; }
  const inB = JOBS.filter((j) => j.batch_id === batch);
  const dep = inB.filter((j) => j.job_type === "deploy"), ver = inB.filter((j) => j.job_type === "verify"), rst = inB.filter((j) => j.job_type === "reset");
  const failed = inB.filter((j) => j.status === "FAILED");
  if (failed.length) fin.innerHTML = `<div class="final fail">✖ ${esc(failed.map((j) => `${j.job_type} ${j.device}: ${j.message}`).join(" · "))} - open "details" below for the router output.</div>`;
  else if (rst.length && all(rst, "SUCCESS")) fin.innerHTML = `<div class="final ok">✔ Undeployed: R1/R2 data-plane configuration removed (interface IPs + OSPF) - management SSH kept. Ready for a new deployment.</div>`;
  else if (ver.length && all(ver, "SUCCESS")) fin.innerHTML = `<div class="final ok">✔ R1 and R2 configured automatically · OSPF FULL · each router learned the remote LAN via OSPF. Final check: open PC1's console and run <code>ping 10.2.0.10</code>.</div>`;
  else if (anyS(inB, "RUNNING") || anyS(inB, "PENDING") || (dep.length && all(dep, "SUCCESS") && !ver.length))
    fin.innerHTML = `<div class="final run">${rst.length ? "Undeploying" : ver.length ? "Verifying OSPF" : "Deploying"}… ${esc(inB.map((j) => `${j.job_type} ${j.device} ${j.status}`).join(" · "))}</div>`;
  else fin.innerHTML = "";
}

async function pollJobs() {
  if (!PID) { JOBS = []; renderFinal(); return; }
  const jobs = await api(`/api/jobs?project_id=${PID}`);
  JOBS = jobs; renderFinal();
  // one popup / toast per finished batch (not for results that were already there when the page opened)
  const shown = (pollJobs._shown ||= new Set());
  const batches = [...new Set(jobs.filter((j) => ["deploy", "reset", "verify"].includes(j.job_type)).map((j) => j.batch_id))];
  const settled = (b) => { const js = jobs.filter((j) => j.batch_id === b); return js.every((j) => ["SUCCESS", "FAILED"].includes(j.status)) &&
    (js.some((j) => j.job_type !== "deploy") || js.some((j) => j.status === "FAILED")); };
  if (!pollJobs._init) { batches.filter(settled).forEach((b) => shown.add(b)); pollJobs._init = true; }
  for (const b of batches.filter((x) => settled(x) && !shown.has(x))) {
    shown.add(b);
    const js = jobs.filter((j) => j.batch_id === b); const bad = js.filter((j) => j.status === "FAILED");
    const kind = js.some((j) => j.job_type === "reset") ? "Undeploy" : bad.some((j) => j.job_type === "deploy") ? "Deployment" : "OSPF verification";
    if (bad.length) showError({ title: `${kind} failed`, message: bad.map((j) => `${j.device}: ${j.message}${j.rolled_back ? " (changes were rolled back)" : ""}`).join("\n"),
      detail: bad.map((j) => j.output || "").join("\n---\n").slice(-3000), actions: kind === "Undeploy" ? [] : [{ label: "Deploy again", primary: true, run: startDeploy }] });
    else toast(kind === "Undeploy" ? "✔ Undeploy finished - R1/R2 data plane reset, management kept." : "✔ Deployment verified: OSPF FULL and remote LANs learned. Now ping 10.2.0.10 from PC1.", 15000);
  }
  // redraw the table only when something actually changed (otherwise open details would flicker)
  const sig = JSON.stringify(jobs.map((j) => [j.id, j.status, j.finished_at, (j.events || []).length]));
  if (sig !== pollJobs._sig) { pollJobs._sig = sig; renderJobs(); }
  updateDeployButton();
}

// jobs table; "details" expands a drop-down row right under the job (click again to close)
const openDetails = new Set();
let justOpened = null;  // only the row the user just opened gets the slide-in animation
function renderJobs() {
  const tb = $("#jobs tbody");
  const keepOpen = new Map([...tb.querySelectorAll("tr.detail-row details[open]")].map((d) => [d.closest("tr").dataset.for + "|" + d.dataset.k, true]));
  tb.innerHTML = JOBS.map((j) => {
    const open = openDetails.has(j.id);
    return `<tr class="job-row${open ? " is-open" : ""}"><td><span class="badge ${j.status}">${j.status}</span></td><td>${esc(j.job_type)}</td><td>${esc(j.device)}</td><td>${esc(fmtTime(j.created_at))}</td><td>${esc(fmtTime(j.started_at))}</td><td>${esc(fmtTime(j.finished_at))}</td><td>${esc(fmtDur(j.started_at, j.finished_at))}</td><td>${longText(j.message || "", 90)}${j.rolled_back ? " <b>(rolled back)</b>" : ""}</td><td><button class="details-btn" data-job="${j.id}" aria-expanded="${open}">${open ? "hide ▴" : "details ▾"}</button></td></tr>` +
      (open ? `<tr class="detail-row" data-for="${j.id}"><td colspan="9">${renderJob(j, j.id === justOpened)}</td></tr>` : "");
  }).join("") || '<tr><td colspan="9" class="muted">No jobs yet</td></tr>';
  // keep inner <details> (Kafka message / device output) open across the 2-second refresh
  tb.querySelectorAll("tr.detail-row details[data-k]").forEach((d) => { if (keepOpen.has(d.closest("tr").dataset.for + "|" + d.dataset.k)) d.open = true; });
  tb.querySelectorAll("button[data-job]").forEach((b) => (b.onclick = () => {
    const id = b.dataset.job;
    if (openDetails.has(id)) { openDetails.delete(id); justOpened = null; } else { openDetails.add(id); justOpened = id; }
    renderJobs(); justOpened = null;
  }));
}

// Deploy is the automatic result of Approve; the button only re-deploys the approved plan
function updateDeployButton() {
  const btn = $("#btnDeploy"), hint = $("#deployHint");
  const cfgs = (PROJECT?.configs || []).filter((c) => c.deployable);
  const approved = cfgs.length && cfgs.every((c) => c.approval);
  const active = JOBS.some((j) => ["deploy", "verify", "reset"].includes(j.job_type) && ["PENDING", "RUNNING"].includes(j.status));
  const deployedBefore = JOBS.some((j) => j.job_type === "deploy");
  if (btn.classList.contains("loading")) return;
  btn.textContent = deployedBefore ? "Deploy again" : "Deploy";
  btn.disabled = !approved || active;
  btn.title = !approved ? "Approve the plan in step 2 first" : active ? "A job is still running" : "Send the same approved configuration again";
  hint.textContent = !approved ? "Deployment starts automatically when the plan is approved in step 2."
    : active ? "Working… the jobs below update live."
    : deployedBefore ? "Deploy again re-sends the same approved configuration (e.g. after Undeploy)."
    : "Approved - deployment starts automatically.";
}

// readable evidence for verify jobs (Task 8): neighbour, route, protocol and ping tables
const tick = (ok) => `<span class="${ok ? "ok-t" : "bad-t"}">${ok ? "✔" : "✖"}</span>`;
function table(head, rows) {
  return `<table class="ev"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${head.length}" class="muted">none</td></tr>`}</tbody></table>`;
}
function renderEvidence(c) {
  if (!c) return "";
  const n = c.neighbors_full, r = c.ospf_routes, rid = c.router_id, pr = c.ospf_process, pas = c.passive_interfaces, pg = c.pings;
  const want = new Set(n?.expected || []);
  return `<div class="evidence">
    <h3>${tick(n?.ok)} OSPF neighbours (show ip ospf neighbor)</h3>
    ${table(["Neighbour ID", "State", "Address", "Interface", "Expected"], (n?.actual || []).map((x) =>
      [esc(x.router_id), `<b class="${String(x.state).toUpperCase() === "FULL" ? "ok-t" : "bad-t"}">${esc(x.state)}/${esc(x.role)}</b>`, esc(x.address), esc(x.interface), want.has(x.router_id) ? "yes" : ""]))}
    <h3>${tick(r?.ok)} Routes learned through OSPF (show ip route ospf)</h3>
    ${table(["Prefix", "Expected", "Learned"], [...new Set([...(r?.expected || []), ...(r?.actual || [])])].map((p) =>
      [esc(p), (r?.expected || []).includes(p) ? "yes" : "", tick((r?.actual || []).includes(p))]))}
    <h3>${tick(pr?.ok && rid?.ok && pas?.ok)} OSPF process (show ip protocols)</h3>
    ${table(["Check", "Expected", "Actual", ""], [
      ["Process ID", esc(pr?.expected), esc(pr?.actual), tick(pr?.ok)],
      ["Router ID", esc(rid?.expected), esc(rid?.actual), tick(rid?.ok)],
      ["Passive interfaces", esc((pas?.expected || []).join(", ")), esc((pas?.actual || []).join(", ")), tick(pas?.ok)]])}
    ${pg ? `<h3>${tick(pg.ok)} Pings from the router</h3>${table(["Target", "Source", "Success", ""], (pg.results || []).map((p) =>
      [esc(p.target), esc(p.source), `${esc(p.success_rate)} % (${esc(p.received)}/${esc(p.sent)})`, tick(p.ok)]))}` : ""}
  </div>`;
}
function renderJob(j, animate = false) {
  const ev = j.job_type === "verify" ? renderEvidence(j.verification?.checks) : "";
  return `<div class="job-detail${animate ? " anim" : ""}">
    <div class="muted small">job ${esc(j.id.slice(0, 8))} · ${esc(j.job_type)} on ${esc(j.device)} · took ${esc(fmtDur(j.started_at, j.finished_at) || "…")}</div>${ev}
    <h3>Timeline</h3><ul class="issues">${(j.events || []).map((e) => `<li class="${e.status === "FAILED" ? "error" : e.status === "SUCCESS" ? "info" : ""}">${esc(fmtTime(e.ts))} <b>${esc(e.status)}</b> ${longText(e.message)}</li>`).join("")}</ul>
    ${j.applied_lines?.length ? `<h3>Applied lines</h3><pre>${esc(j.applied_lines.join("\n"))}</pre>` : ""}
    <details data-k="kafka"><summary>Kafka message</summary><pre>${esc(JSON.stringify(j.kafka_message, null, 2))}</pre></details>
    <details data-k="output"><summary>Device output</summary><pre>${esc(j.output || "(none yet)")}</pre></details>
  </div>`;
}

// ---------------------------------------------------------------- new run
$("#btnNewRun").onclick = () => {
  if (PID && !confirm("Start a new run? The current project stays saved; the page is cleared for a fresh diagram.")) return;
  PID = null; PROJECT = null; JOBS = []; openJob = null; uploadedKey = null; pollJobs._init = false; pollJobs._shown = new Set(); pollJobs._sig = undefined;
  history.replaceState(null, "", location.pathname);
  $("#file").value = ""; $("#notes").value = ""; $("#preview").hidden = true; $("#preview").removeAttribute("src"); $("#noPreview").hidden = false;
  $("#approver").value = ""; $("#ackWarn").checked = false;
  ["#configs", "#final", "#extractIssues"].forEach((s) => ($(s).innerHTML = "")); openDetails.clear();
  $("#jobs tbody").innerHTML = '<tr><td colspan="9" class="muted">No jobs yet</td></tr>';
  $("#extraction").value = ""; $("#mapTable tbody").innerHTML = ""; $("#routerIds").innerHTML = "";
  status("", ""); refresh(); window.scrollTo({ top: 0, behavior: "smooth" });
};

// ---------------------------------------------------------------- advanced (manual edits)
$("#btnSaveJson").onclick = (e) => busy(e.target, async () => {
  need(); let obj; try { obj = JSON.parse($("#extraction").value); } catch (x) { throw new Error("JSON parse error: " + x.message); }
  await api(`/api/projects/${PID}/extraction`, { method: "PUT", body: JSON.stringify({ extraction: obj }) });
  await refresh(); toast("Saved. Click Generate plan to rebuild the configs.");
});
$("#btnReanalyze").onclick = (e) => busy(e.target, async () => {
  need(); toast("The AI is reading the diagram…", 120000);
  await api(`/api/projects/${PID}/extract`, { method: "POST" }); await refresh(); toast("New AI result loaded. Click Generate plan.");
});
$("#btnSample").onclick = (e) => busy(e.target, async () => {
  need(); const s = await api("/api/samples/exam_plan");
  await api(`/api/projects/${PID}/extraction`, { method: "PUT", body: JSON.stringify({ extraction: s }) }); await refresh();
  toast("Sample plan loaded. Click Generate plan.");
});
$("#btnDiscover").onclick = (e) => busy(e.target, async () => {
  need(); const r = await api(`/api/projects/${PID}/discover`, { method: "POST" });
  await waitJobs(r.jobs, 180, () => {}); await refresh(); toast("Discovery finished.");
});
$("#btnSuggest").onclick = (e) => busy(e.target, async () => { need(); await api(`/api/projects/${PID}/mapping/suggest`, { method: "POST" }); await refresh(); });
$("#btnSaveMap").onclick = (e) => busy(e.target, async () => {
  need(); const mapping = {};
  document.querySelectorAll("#mapTable select").forEach((s) => { (mapping[s.dataset.dev] ||= {})[s.dataset.if] = s.value || null; });
  const router_ids = {};
  document.querySelectorAll("#routerIds input").forEach((i) => { router_ids[i.dataset.dev] = i.value.trim(); });
  await api(`/api/projects/${PID}/mapping`, { method: "PUT", body: JSON.stringify({ mapping, router_ids }) }); await refresh();
  toast("Mapping saved. Click Generate plan.");
});
function renderMapping(p) {
  const tb = $("#mapTable tbody"); const ex = p.extraction; if (!ex) { tb.innerHTML = ""; $("#routerIds").innerHTML = ""; return; }
  $("#routerIds").innerHTML = ex.devices.filter((d) => d.role === "router").map((d) =>
    `<label>${esc(d.hostname)} router-id <input data-dev="${esc(d.hostname)}" value="${esc(d.router_id || "")}" placeholder="e.g. 1.1.1.1" class="${d.router_id ? "" : "missing"}"></label>`).join("");
  tb.innerHTML = ex.devices.filter((d) => d.role === "router").flatMap((d) => d.interfaces.map((i) => {
    const disc = p.discovery[d.hostname] || {}; const opts = new Set(disc.data_interfaces || []); if (i.name) opts.add(i.name);
    const sel = `<select data-dev="${esc(d.hostname)}" data-if="${esc(i.id)}"><option value="">— unmapped —</option>${[...opts].map((o) => `<option ${o === i.name ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
    return `<tr><td>${esc(d.hostname)}</td><td>${esc(i.id)}</td><td>${esc(i.ip)} / ${esc(i.mask)}</td><td>${esc(i.link)}</td><td>${sel}</td></tr>`;
  })).join("");
}

// ---------------------------------------------------------------- shared
function need() { if (!PID) throw new Error("generate a plan first (step 1)"); }
async function refresh() {
  if (!PID) { renderReview(null); renderPlanTable({}); renderAmbiguities(null); renderFinal(); return; }
  PROJECT = await api(`/api/projects/${PID}`);
  if (PROJECT.image_url && $("#preview").hidden) { $("#preview").src = PROJECT.image_url; $("#preview").hidden = false; $("#noPreview").hidden = true; }
  if (PROJECT.notes && !$("#notes").value) $("#notes").value = PROJECT.notes;
  $("#extraction").value = PROJECT.extraction ? JSON.stringify(PROJECT.extraction, null, 2) : "";
  renderIssueList($("#extractIssues"), PROJECT.issues);
  renderAmbiguities(PROJECT.extraction); renderPlanTable(PROJECT); renderMapping(PROJECT);
  renderReview(PROJECT.validation); renderConfigs(PROJECT.configs); renderFinal(); updateDeployButton();
}

// approver fields become a drop-down of authorised names when APPROVERS is set in .env
async function setupApprovers() {
  let list = [];
  try { const r = await api("/api/approvers"); if (r.restricted) list = r.approvers; } catch (_) { return; }
  if (!list.length) return;
  for (const id of ["approver", "undApprover"]) {
    const old = $("#" + id); const sel = document.createElement("select");
    sel.id = id; sel.setAttribute("aria-label", "approver"); sel.title = "Authorised approvers (APPROVERS in .env)";
    sel.innerHTML = `<option value="">— select approver —</option>` + list.map((n) => `<option>${esc(n)}</option>`).join("");
    sel.onchange = () => sel.classList.remove("missing");
    old.replaceWith(sel);
  }
}
// ---------------------------------------------------------------- light / dark theme
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#btnTheme").textContent = t === "dark" ? "☀ Light" : "☾ Dark";
  try { localStorage.setItem("theme", t); } catch (e) {}
}
$("#btnTheme").onclick = () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
applyTheme(document.documentElement.dataset.theme || "light");

(async function init() {
  const dot = $("#health");
  try {
    const h = await api("/api/health");
    dot.className = "dot " + (h.simulate_devices ? "warn" : "ok");
    dot.title = `API connected · ${h.bus} · topic ${h.jobs_topic}${h.simulate_devices ? " · SIMULATED devices" : " · real routers"}`;
  } catch (e) { dot.className = "dot bad"; dot.title = "API not reachable"; }
  await setupApprovers();
  PID = location.hash.slice(1) || null;
  if (PID) { try { await refresh(); } catch (e) { PID = null; await refresh(); } } else { await refresh(); }
  setInterval(() => pollJobs().catch(() => {}), 2000);
})();
