const TRUST_HTML = `
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
    $("#memBody").innerHTML = r.length ? r.map(m => '<tr><td>'+esc(m.username)+'</td><td>'+esc(m.full_name)+'</td><td><span class="tag">'+esc(m.case_role)+'</span></td><td>'+esc(m.assigned_by)+'</td><td class="mono muted">'+esc(m.assigned_at.replace("T"," ").slice(0,19))+'</td></tr>').join("") : '<tr><td colspan="5" class="empty">No members assigned explicitly.</td></tr>';
  } catch (e) { $("#memBody").innerHTML = '<tr><td colspan="5" class="empty">'+esc(e.message)+'</td></tr>'; }
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

window.initTrustTabs = initTrustTabs;
