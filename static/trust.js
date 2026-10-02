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
      <div class="wide"><button class="btn" id="co_status_btn">Change Status</button></div>
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
    <div class="toolbar"><span id="gChainBadge"></span>
      <button class="btn line sm" id="gExportBtn">Export Signed Audit Trail</button>
    </div>
    <div class="scroll"><table><thead><tr><th>#</th><th>When (UTC)</th><th>Who</th><th>Action</th><th>Case</th><th>Evidence</th><th>Detail</th><th>Entry hash</th></tr></thead><tbody id="gAuditBody"></tbody></table></div>
  </section>

  <section id="paneSandbox" hidden>
    <h2>Synthetic Sandbox</h2>
    <div class="pad form">
      <div class="muted">Run a script in an isolated Docker container with the <code>FORENSIC_DATA_DIR</code> mounted read-only at <code>/data</code>.</div>
      <label class="f">Docker Image<input id="sb_image" value="alpine:latest"></label>
      <label class="f wide">Shell Script<textarea id="sb_script" rows="6" placeholder="#!/bin/sh&#10;ls -la /data"></textarea></label>
      <div class="wide"><button class="btn" id="sb_run">Run in Sandbox</button></div>
    </div>
    <div class="pad" id="sb_output_container" hidden>
      <h3>Execution Result (Saved as Evidence <span id="sb_ev_id" class="mono"></span>)</h3>
      <div class="muted">Exit code: <span id="sb_exit_code"></span></div>
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
    try {
      await api("/api/cases/" + encodeURIComponent(caseId) + "/status", { method: "POST", body: form({
        status: $("#co_status_new").value, reason: $("#co_status_reason").value
      })});
      toast("Status changed."); $("#co_status_reason").value = ""; loadOverview();
    } catch(e) { toast(e.message); }
  };
  $("#co_hold").onchange = async () => {
    if(!caseId) return;
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

  $("#sb_run").onclick = async () => {
    if (!caseId) return toast("Select a case first.");
    $("#sb_run").disabled = true; $("#sb_run").textContent = "Running...";
    $("#sb_output_container").hidden = true;
    try {
      const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/sandbox/run", {
        method: "POST", body: form({ script: $("#sb_script").value, image: $("#sb_image").value })
      });
      $("#sb_ev_id").textContent = r.evidence_id;
      $("#sb_exit_code").textContent = r.exit_code;
      $("#sb_output").textContent = r.output;
      $("#sb_output_container").hidden = false;
      toast("Sandbox execution complete. Output saved as evidence.");
      loadEvidence();
    } catch (e) { toast(e.message); }
    $("#sb_run").disabled = false; $("#sb_run").textContent = "Run in Sandbox";
  };
}

// Logic functions
async function loadMembers() {
  if (!caseId) { $("#memBody").innerHTML = '<tr><td colspan="5" class="empty">No case selected.</td></tr>'; return; }
  try {
    const r = await api("/api/cases/" + encodeURIComponent(caseId) + "/members");
    $("#memBody").innerHTML = r.length ? r.map(m => '<tr><td>'+esc(m.username)+'</td><td>'+esc(m.full_name)+'</td><td><span class="tag">'+esc(m.case_role)+'</span></td><td>'+esc(m.assigned_by)+'</td><td class="mono muted">'+esc(m.assigned_at.replace("T"," ").slice(0,19))+'</td><td><button class="btn sm line" onclick="removeMember(\\''+esc(m.username)+'\\')">Remove</button></td></tr>').join("") : '<tr><td colspan="6" class="empty">No members assigned explicitly.</td></tr>';
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

async function loadAudit() {
  if (!can(["admin", "auditor"])) return;
  try {
    const r = await api("/api/audit");
    $("#gChainBadge").className = "badge " + (r.chain.valid ? "VERIFIED" : "TAMPERED");
    $("#gChainBadge").textContent = r.chain.valid ? "Global Chain Verified" : "GLOBAL CHAIN BROKEN: " + r.chain.reason;
    $("#gAuditBody").innerHTML = r.entries.map(e => '<tr><td class="mono muted">'+e.seq+'</td><td class="mono muted">'+esc(e.timestamp.replace("T"," ").slice(0,19))+'</td><td>'+esc(e.actor)+'</td><td><span class="tag">'+esc(e.action)+'</span></td><td>'+esc(e.case_id || "-")+'</td><td>'+esc(e.evidence_id || "-")+'</td><td><pre>'+esc(JSON.stringify(e.detail,null,1))+'</pre></td><td class="mono muted" style="font-size:10px">'+esc(e.entry_hash)+'</td></tr>').join("");
  } catch (e) { $("#gAuditBody").innerHTML = '<tr><td colspan="8" class="empty">'+esc(e.message)+'</td></tr>'; }
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

// Set up UI event listeners for case list
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    $("#cl_q").oninput = () => { clPage = 1; loadCaseList(); };
    $("#cl_status").onchange = () => { clPage = 1; loadCaseList(); };
    $("#cl_pri").onchange = () => { clPage = 1; loadCaseList(); };
    $("#cl_cat").onchange = () => { clPage = 1; loadCaseList(); };
    $("#cl_sort").onchange = () => { clPage = 1; loadCaseList(); };
    $("#cl_prev").onclick = () => { if(clPage>1) { clPage--; loadCaseList(); } };
    $("#cl_next").onclick = () => { clPage++; loadCaseList(); };
  }, 1000);
});
