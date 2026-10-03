const TRUST_HTML = `
  <section id="paneCaseList" hidden>
    <h2>Case List</h2>
    <div class="toolbar">
      <input type="search" id="cl_q" placeholder="Search title or ref">
      <select id="cl_status"><option value="">All Statuses</option><option>Open</option><option>Under Analysis</option><option>Pending Legal Review</option><option>Closed</option><option>Archived</option></select>
      <select id="cl_pri"><option value="">All Priorities</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select>
      <select id="cl_cat"><option value="">All Categories</option><option>Financial Fraud</option><option>Digital Arrest Scam</option><option>Mule Account</option><option>Data Theft/Insider</option><option>Ransomware</option><option>Other</option></select>
      <select id="cl_sort"><option value="created_at DESC">Newest first</option><option value="created_at ASC">Oldest first</option></select>
      <span class="muted" id="cl_count"></span>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>Reference</th><th>Title</th><th>Status</th><th>Priority</th><th>Category</th><th>Created</th></tr></thead>
        <tbody id="clBody"></tbody>
      </table>
    </div>
    <div class="toolbar" style="margin-top:10px">
      <button class="btn line sm" id="cl_prev">Previous</button>
      <span id="cl_page" class="muted" style="margin:0 10px">Page 1</span>
      <button class="btn line sm" id="cl_next">Next</button>
    </div>
  </section>
  <section id="paneOverview" hidden>
    <h2>Case Overview</h2>
    <div class="pad form">
      <label class="f">Title<input id="co_title"></label>
      <label class="f">Reference (e.g. SUT-2026-0001)<input id="co_ref"></label>
      <label class="f">FIR/Complaint #<input id="co_fir"></label>
      <label class="f">Crime Category
        <select id="co_cat">
          <option value="">-- Select --</option>
          <option>Financial Fraud</option><option>Digital Arrest Scam</option>
          <option>Mule Account</option><option>Data Theft/Insider</option>
          <option>Ransomware</option><option>Other</option>
        </select>
      </label>
      <label class="f">Unit<input id="co_unit"></label>
      <label class="f">Jurisdiction<input id="co_jur"></label>
      <label class="f">Priority
        <select id="co_pri"><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select>
      </label>
      <label class="f wide">Description<textarea id="co_desc" rows="3"></textarea></label>
      <div class="wide"><button class="btn" id="co_save">Save Metadata</button> <span id="co_hold_ui" style="margin-left:15px"><label><input type="checkbox" id="co_hold"> Legal Hold</label></span></div>
    </div>
    
    <h3 style="margin:20px 18px 10px">Status & Lifecycle</h3>
    <div class="pad form" style="background:#f9f9f9;border-radius:6px;margin:0 18px">
      <label class="f">Current Status<input id="co_status_curr" disabled></label>
      <label class="f">New Status
        <select id="co_status_new">
          <option>Open</option><option>Under Analysis</option>
          <option>Pending Legal Review</option><option>Closed</option><option>Archived</option>
        </select>
      </label>
      <label class="f wide">Reason for change<input id="co_status_reason" placeholder="Mandatory reason for audit log"></label>
      <div class="wide">
        <button class="btn" id="co_status_btn">Change Status</button>
        <button class="btn line" id="co_cert_btn" style="margin-left:15px">Download PDF Certificate</button>
      </div>
    </div>
  </section>
  <section id="paneMembers" hidden>
    <h2>Case members</h2>
    <div class="pad form" id="addMemberForm">
      <label class="f">Username<input id="mem_u" placeholder="Username to assign"></label>
      <label class="f">Role on this case
        <select id="mem_role"><option>investigator</option><option>examiner</option><option>supervisor</option><option>reviewer</option><option>auditor</option></select>
      </label>
      <div class="wide"><button class="btn" id="mem_add">Assign to case</button></div>
    </div>
    <div class="scroll"><table><thead><tr><th>Username</th><th>Name</th><th>Case Role</th><th>Assigned By</th><th>Assigned At</th></tr></thead><tbody id="memBody"></tbody></table></div>
  </section>

  <section id="panePermissions" hidden>
    <h2>Permissions Matrix</h2>
    <div class="pad muted" style="font-size:13px">This matrix shows the declarative permissions required for actions. Roles grant a specific set of permissions. Note: Admin and Auditor have global access to cases, while other roles require explicit case assignment.</div>
    <div class="scroll"><table id="permTable"></table></div>
  </section>

  <section id="paneAudit" hidden>
    <h2>Global Audit Trail</h2>
    <div class="toolbar" id="auditFilters">
      <input type="search" id="g_actor" placeholder="Actor (e.g. admin)">
      <input type="search" id="g_action" placeholder="Action (e.g. case_created)">
      <input type="search" id="g_case" placeholder="Case ID">
      <label class="muted" style="font-size:12px">From <input type="datetime-local" id="g_from"></label>
      <label class="muted" style="font-size:12px">To <input type="datetime-local" id="g_to"></label>
      <button class="btn sm" id="gFilterBtn">Filter</button>
      <button class="btn line sm" id="gClearBtn">Clear</button>
    </div>
    <div class="toolbar" style="border-top:1px solid #CFD7DF;margin-top:10px">
      <span id="gChainBadge"></span>
      <button class="btn line sm" id="gVerifyBtn">Verify Chain</button>
      <button class="btn line sm" id="gAnchorBtn">Seal/Anchor Chain</button>
      <button class="btn line sm" id="gBundleBtn">Download Bundle</button>
      <button class="btn line sm" id="gExportBtn">Export JSON/CSV</button>
      <button class="btn line sm" id="gTamperBtn" style="color:var(--bad)">Simulate Tamper</button>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>Seq</th><th>When (UTC)</th><th>Actor</th><th>Action</th><th>Case / Evidence</th><th>Detail & Hash</th></tr></thead>
        <tbody id="gAuditBody"></tbody>
      </table>
    </div>
  </section>

  <section id="paneSandbox" hidden>
    <h2>Synthetic Sandbox</h2>
    <div class="pad form">
      <div class="muted">Run synthetic injections in a "Digital Twin" of the case evidence. No actual execution is used.</div>
      <div class="wide" style="margin-bottom: 10px;">
        <button class="btn" id="sb_create">Create Sandbox</button>
        <span id="sb_id_display" class="mono muted" style="margin-left: 10px;"></span>
      </div>
      
      <div id="sb_inject_panel" hidden>
        <label class="f">Injection Template
          <select id="sb_template">
            <option value="clock_skew">Clock Skew</option>
            <option value="off_hours_usb">Off-hours USB</option>
            <option value="registry_autorun">Registry Autorun</option>
            <option value="forged_dns">Forged DNS</option>
            <option value="coercion_payment">Coercion Pattern</option>
          </select>
        </label>
        <div class="wide" style="margin-bottom: 10px;">
          <button class="btn line" id="sb_inject">Inject Artifact</button>
          <span id="sb_inj_count" class="muted" style="margin-left: 10px;">0 artifacts injected</span>
        </div>
        <div class="wide">
          <button class="btn" id="sb_run">Run Analysis</button>
          <button class="btn bad" id="sb_destroy" style="margin-left: 10px;">Destroy</button>
        </div>
      </div>
    </div>
    
    <div class="pad" id="sb_output_container" hidden>
      <h3>Analysis Scoreboard</h3>
      <table style="width: 100%; text-align: left; margin-bottom: 20px;">
        <tr><th>Injected</th><td id="score_injected"></td><th>Isolation</th><td id="score_isolation"></td></tr>
        <tr><th>Detected Total</th><td id="score_detected"></td><th>True Positives</th><td id="score_tp"></td></tr>
        <tr><th>Missed</th><td id="score_missed"></td><th>False Positives</th><td id="score_fp"></td></tr>
      </table>
      <h4>Detections</h4>
      <pre id="sb_output" style="background:#111;color:#eee;padding:10px;border-radius:4px;overflow-x:auto;max-height:400px"></pre>
    </div>
  </section>
`;

function initTrustTabs(registerTab) {
  // Inject HTML
  document.querySelector("main").insertAdjacentHTML("beforeend", TRUST_HTML);

  // Register Tabs
  registerTab("caselist", "Case List", loadCaseList);
  registerTab("overview", "Case Overview", loadOverview);
  registerTab("members", "Case members", loadMembers);
  registerTab("permissions", "Permissions Matrix", loadPermissions);
  registerTab("audit", "Global Audit", loadAudit);
  registerTab("sandbox", "Sandbox", null);

  // Hook into auth/refresh
  const origEnterApp = window.enterApp;
  window.enterApp = async function() {
    await origEnterApp();
    $("#auditTab").hidden = !can(["admin", "auditor"]);
    $("#sandboxTab").hidden = !_perms ? true : (_perms[me.role] || []).includes("sandbox:run");
  };

  const origRefreshAll = window.refreshAll;
  window.refreshAll = async function() {
    await origRefreshAll();
    if (!$("#paneCaseList").hidden) loadCaseList();
    if (!$("#paneOverview").hidden) loadOverview();
    if (!$("#paneMembers").hidden) loadMembers();
    if (!$("#paneAudit").hidden) loadAudit();
  };

  // Event Listeners
  $("#mem_add").onclick = async () => {
    if (!caseId) return;
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/members", { method: "POST", body: form({ username: $("#mem_u").value, role: $("#mem_role").value }) });
      toast("Member assigned."); $("#mem_u").value = ""; loadMembers();
    } catch (e) { toast(e.message); }
  };
  window.removeMember = async (username) => {
    if (!confirm("Remove " + username + "?")) return;
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/members/" + encodeURIComponent(username), { method: "DELETE" });
      toast("Member removed."); loadMembers();
    } catch(e) { toast(e.message); }
  };
  $("#co_save").onclick = async () => {
    if(!caseId) return;
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/metadata", { method: "POST", body: form({
        title: $("#co_title").value, human_reference: $("#co_ref").value, fir_number: $("#co_fir").value,
        crime_category: $("#co_cat").value, unit: $("#co_unit").value, jurisdiction: $("#co_jur").value,
        priority: $("#co_pri").value, description: $("#co_desc").value
      })});
      toast("Metadata updated.");
    } catch(e) { toast(e.message); }
  };
  $("#co_status_btn").onclick = async () => {
    if(!caseId) return;
    if(!$("#co_status_reason").value) return toast("Reason required");
    if(!confirm("Change status to " + $("#co_status_new").value + "?")) return;
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/status", { method: "POST", body: form({
        status: $("#co_status_new").value, reason: $("#co_status_reason").value
      })});
      toast("Status changed."); $("#co_status_reason").value = ""; loadOverview();
    } catch(e) { toast(e.message); }
  };
  $("#co_cert_btn").onclick = async () => {
    if(!caseId) return;
    try {
      const res = await fetch("/api/cases/" + encodeURIComponent(caseId) + "/certificate", {
        headers: { "X-Requested-With": "idff" }
      });
      if (!res.ok) { const j = await res.json(); throw new Error(j.detail || "Failed to generate certificate"); }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = caseId + "_certificate.pdf"; a.click();
      URL.revokeObjectURL(url);
      toast("Certificate downloaded.");
    } catch (e) { toast(e.message); }
  };
  $("#co_hold").onchange = async () => {
    if(!caseId) return;
    if(!confirm("Toggle legal hold?")) {
        $("#co_hold").checked = !$("#co_hold").checked;
        return;
    }
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/legal_hold", { method: "POST", body: form({ hold: $("#co_hold").checked ? 1 : 0 }) });
      toast("Legal hold updated.");
    } catch(e) { toast(e.message); $("#co_hold").checked = !$("#co_hold").checked; }
  };

  $("#gExportBtn").onclick = async () => {
    try {
      const r = await api("/api/audit/export");
      const blob = new Blob([JSON.stringify(r, null, 2)], {type: "application/json"});
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "global_audit_trail_" + new Date().toISOString().replace(/[:.]/g,"-") + ".json"; a.click();
    } catch (e) { toast(e.message); }
  };

  let currentSandbox = null;
  let injectCount = 0;

  $("#sb_create").onclick = async () => {
    if (!caseId) return toast("Select a case first.");
    try {
      const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/sandbox", { method: "POST" });
      currentSandbox = r.sandbox_id;
      injectCount = 0;
      $("#sb_id_display").textContent = currentSandbox;
      $("#sb_inject_panel").hidden = false;
      $("#sb_inj_count").textContent = "0 artifacts injected";
      $("#sb_create").disabled = true;
      $("#sb_output_container").hidden = true;
      toast("Sandbox created: " + currentSandbox);
    } catch (e) { toast(e.message); }
  };

  $("#sb_inject").onclick = async () => {
    if (!currentSandbox) return;
    try {
      const tpl = $("#sb_template").value;
      const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/sandbox/" + encodeURIComponent(currentSandbox) + "/inject", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ template: tpl, params: { title: "Injected " + tpl }, expected_detection_type: tpl })
      });
      injectCount++;
      $("#sb_inj_count").textContent = injectCount + " artifacts injected";
      toast("Artifact injected: " + r.injection_id);
    } catch (e) { toast(e.message); }
  };

  $("#sb_run").onclick = async () => {
    if (!currentSandbox) return;
    $("#sb_run").disabled = true; $("#sb_run").textContent = "Running...";
    try {
      const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/sandbox/" + encodeURIComponent(currentSandbox) + "/run", { method: "POST" });
      $("#score_injected").textContent = r.injected;
      $("#score_detected").textContent = r.detected;
      $("#score_tp").textContent = r.true_positives;
      $("#score_missed").textContent = r.missed;
      $("#score_fp").textContent = r.false_positives;
      $("#score_isolation").textContent = r.isolation_status;
      $("#sb_output").textContent = JSON.stringify(r.detections, null, 2);
      $("#sb_output_container").hidden = false;
      toast("Analysis complete.");
    } catch (e) { toast(e.message); }
    $("#sb_run").disabled = false; $("#sb_run").textContent = "Run Analysis";
  };

  $("#sb_destroy").onclick = async () => {
    if (!currentSandbox) return;
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/sandbox/" + encodeURIComponent(currentSandbox), { method: "DELETE" });
      currentSandbox = null;
      $("#sb_id_display").textContent = "";
      $("#sb_inject_panel").hidden = true;
      $("#sb_create").disabled = false;
      $("#sb_output_container").hidden = true;
      toast("Sandbox destroyed.");
    } catch (e) { toast(e.message); }
  };
}

// Logic functions
async function loadMembers() {
  if (!caseId) { $("#memBody").innerHTML = '<tr><td colspan="5" class="empty">No case selected.</td></tr>'; return; }
  try {
    const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/members");
    $("#memBody").innerHTML = r.length ? r.map(m => '<tr><td>'+esc(m.username)+'</td><td>'+esc(m.full_name)+'</td><td><span class="tag">'+esc(m.case_role)+'</span></td><td>'+esc(m.assigned_by)+'</td><td class="mono muted">'+esc(m.assigned_at.replace("T"," ").slice(0,19))+'</td><td><button class="btn sm line" onclick="removeMember(\''+esc(m.username)+'\')">Remove</button></td></tr>').join("") : '<tr><td colspan="6" class="empty">No members assigned explicitly.</td></tr>';
  } catch (e) { $("#memBody").innerHTML = '<tr><td colspan="6" class="empty">'+esc(e.message)+'</td></tr>'; }
}

async function loadOverview() {
  if (!caseId) return;
  try {
    const r = await api("/api/cases/" + encodeURIComponent(caseId));
    $("#co_title").value = r.title || "";
    $("#co_ref").value = r.human_reference || "";
    $("#co_fir").value = r.fir_number || "";
    $("#co_cat").value = r.crime_category || "";
    $("#co_unit").value = r.unit || "";
    $("#co_jur").value = r.jurisdiction || "";
    $("#co_pri").value = r.priority || "Medium";
    $("#co_desc").value = r.description || "";
    $("#co_status_curr").value = r.status || "Open";
    $("#co_status_new").value = r.status || "Open";
    $("#co_hold").checked = !!r.legal_hold;
  } catch(e) { toast(e.message); }
}

let _perms = null;
async function loadPermissions() {
  if (!_perms) _perms = await api("/api/permissions");
  const roles = Object.keys(_perms);
  const allPerms = [...new Set(Object.values(_perms).flat())].sort();
  let html = '<thead><tr><th>Permission</th>' + roles.map(r => '<th>'+esc(r)+'</th>').join("") + '</tr></thead><tbody>';
  for (const p of allPerms) {
    html += '<tr><td class="mono">'+esc(p)+'</td>' + roles.map(r => '<td style="text-align:center;font-weight:bold">' + (_perms[r].includes(p) ? '<span style="color:var(--ok)">✓</span>' : '<span style="color:var(--line)">-</span>') + '</td>').join("") + '</tr>';
  }
  html += '</tbody>';
  $("#permTable").innerHTML = html;
}

let gAuditData = { entries: [], chain: {} };

async function loadAudit() {
  if (!can(["admin", "auditor"])) return;
  try {
    const r = await api("/api/audit");
    gAuditData = r;
    renderAudit();
  } catch (e) { $("#gAuditBody").innerHTML = '<tr><td colspan="6" class="empty">'+esc(e.message)+'</td></tr>'; }
}

function renderAudit() {
  let entries = gAuditData.entries;
  
  const fAct = $("#g_actor").value.toLowerCase();
  const fAction = $("#g_action").value.toLowerCase();
  const fCase = $("#g_case").value.toLowerCase();
  const fFrom = $("#g_from").value;
  const fTo = $("#g_to").value;
  
  entries = entries.filter(e => {
    if (fAct && !(e.actor || "").toLowerCase().includes(fAct)) return false;
    if (fAction && !(e.action || "").toLowerCase().includes(fAction) && !(e.action || "").toUpperCase().includes(fAction)) return false;
    if (fCase && !(e.case_id || "").toLowerCase().includes(fCase)) return false;
    if (fFrom && e.ts < fFrom) return false;
    if (fTo && e.ts > fTo) return false;
    return true;
  });
  
  const chain = gAuditData.chain;
  $("#gChainBadge").className = "badge " + (chain.valid ? "VERIFIED" : "TAMPERED");
  $("#gChainBadge").innerHTML = chain.valid ? `Chain intact &middot; ${chain.entries_checked} entries checked` : `CHAIN BROKEN at entry ${chain.first_broken_seq}`;
  
  $("#gAuditBody").innerHTML = entries.map(e => {
    const broken = !chain.valid && e.seq >= chain.first_broken_seq;
    const stripColor = broken ? "var(--bad)" : "var(--ok)";
    return `<tr>
      <td class="mono muted"><div style="display:inline-block;width:4px;height:12px;background:${stripColor};margin-right:4px;border-radius:2px;vertical-align:middle"></div>${e.seq}</td>
      <td class="mono muted">${esc((e.ts||"").replace("T"," ").slice(0,19))}</td>
      <td>${esc(e.actor)}</td>
      <td><span class="tag">${esc(e.action)}</span></td>
      <td class="mono muted" style="font-size:12px">${esc(e.case_id || "-")}</td>
      <td>
        <details><summary class="muted mono" style="font-size:11px;cursor:pointer">Hash: ${esc((e.entry_hash||"").substring(0, 16))}...</summary>
        <div class="mono muted" style="font-size:10px;margin-top:4px;word-break:break-all">${esc(e.entry_hash)}</div>
        <pre style="margin-top:4px;background:#f6f8fa;padding:6px;border-radius:4px;font-size:11px">${esc(JSON.stringify(e.detail,null,2))}</pre>
        </details>
      </td>
    </tr>`;
  }).join("");
}

let clPage = 1;
async function loadCaseList() {
  try {
    let q = "?page=" + clPage;
    if ($("#cl_q").value) q += "&q=" + encodeURIComponent($("#cl_q").value);
    if ($("#cl_status").value) q += "&status=" + encodeURIComponent($("#cl_status").value);
    if ($("#cl_pri").value) q += "&priority=" + encodeURIComponent($("#cl_pri").value);
    if ($("#cl_cat").value) q += "&category=" + encodeURIComponent($("#cl_cat").value);
    if ($("#cl_sort").value) q += "&sort=" + encodeURIComponent($("#cl_sort").value);
    
    const r = await api("/api/cases" + q);
    $("#cl_count").textContent = r.total + " cases";
    $("#clBody").innerHTML = r.items.length ? r.items.map(c => '<tr><td class="mono">'+esc(c.human_reference || c.case_id)+'</td><td>'+esc(c.title)+'</td><td><span class="tag">'+esc(c.status)+'</span></td><td>'+esc(c.priority || "-")+'</td><td>'+esc(c.crime_category || "-")+'</td><td class="muted mono">'+esc((c.created_at||"").replace("T"," ").slice(0,19))+'</td></tr>').join("") : '<tr><td colspan="6" class="empty">No cases found.</td></tr>';
    $("#cl_page").textContent = "Page " + clPage;
    $("#cl_prev").disabled = clPage <= 1;
    $("#cl_next").disabled = clPage * 20 >= r.total;
  } catch (e) { toast(e.message); }
}

window.initTrustTabs = initTrustTabs;

// Set up UI event listeners for case list and audit
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    if ($("#cl_q")) $("#cl_q").oninput = () => { clPage = 1; loadCaseList(); };
    if ($("#cl_status")) $("#cl_status").onchange = () => { clPage = 1; loadCaseList(); };
    if ($("#cl_pri")) $("#cl_pri").onchange = () => { clPage = 1; loadCaseList(); };
    if ($("#cl_cat")) $("#cl_cat").onchange = () => { clPage = 1; loadCaseList(); };
    if ($("#cl_sort")) $("#cl_sort").onchange = () => { clPage = 1; loadCaseList(); };
    if ($("#cl_prev")) $("#cl_prev").onclick = () => { if(clPage>1) { clPage--; loadCaseList(); } };
    if ($("#cl_next")) $("#cl_next").onclick = () => { clPage++; loadCaseList(); };
    
    // Audit Trail
    if ($("#gFilterBtn")) {
      $("#gFilterBtn").onclick = () => renderAudit();
      $("#gClearBtn").onclick = () => {
        $("#g_actor").value = ""; $("#g_action").value = ""; $("#g_case").value = ""; $("#g_from").value = ""; $("#g_to").value = "";
        renderAudit();
      };
      $("#gVerifyBtn").onclick = async () => {
        try {
          const r = await api("/api/audit/verify");
          $("#gChainBadge").className = "badge " + (r.valid ? "VERIFIED" : "TAMPERED");
          $("#gChainBadge").innerHTML = r.valid ? `Verified! checked ${r.entries_checked} entries in ${r.elapsed_ms}ms` : `TAMPERED! First broken seq: ${r.first_broken_seq}`;
        } catch (e) { toast("Verify failed: " + e.message); }
      };
      $("#gExportBtn").onclick = async () => {
        try {
          const r = await api("/api/audit/export");
          const blob = new Blob([JSON.stringify(r.entries, null, 2)], {type: "application/json"});
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = "audit_trail.json"; a.click();
          URL.revokeObjectURL(url);
          toast("Exported " + r.entries.length + " rows");
        } catch (e) { toast("Export failed: " + e.message); }
      };
      $("#gAnchorBtn").onclick = async () => {
        if (!confirm("Seal current chain with an anchor?")) return;
        try {
          const r = await api("/api/audit/anchor", { method: "POST" });
          toast("Anchor generated. Seq: " + r.anchor.seq);
          loadAudit();
        } catch (e) { toast("Anchor failed: " + e.message); }
      };
      $("#gBundleBtn").onclick = async () => {
        try {
          const r = await api("/api/audit/bundle");
          const blob = new Blob([JSON.stringify(r, null, 2)], {type: "application/json"});
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = "audit_bundle.json"; a.click();
          URL.revokeObjectURL(url);
          toast("Exported bundle with certs and anchors.");
        } catch (e) { toast("Bundle failed: " + e.message); }
      };
      $("#gTamperBtn").onclick = async () => {
        if (!confirm("Simulate tampering in the database? This breaks the chain.")) return;
        try {
          const r = await api("/api/audit/tamper-simulation", { method: "POST" });
          toast("Tampered! Seq: " + r.tampered_seq + " Result: " + r.result);
          loadAudit();
        } catch (e) { toast("Tamper failed: " + e.message); }
      };
    }
  }, 1000);
});
