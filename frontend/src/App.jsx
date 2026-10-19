import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Search,
  Scale,
  Download,
  Printer,
  ChevronRight,
  Database,
  Lock,
  Layers,
  Cpu,
  Clock,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  Sliders,
  X
} from 'lucide-react';

export default function App() {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-USB-THEFT-001');
  const [currentCase, setCurrentCase] = useState(null);
  
  // Panel 1: Anomalies
  const [anomalies, setAnomalies] = useState([]);
  const [loadingAnomalies, setLoadingAnomalies] = useState(false);
  
  // Panel 2: Summary
  const [summaryData, setSummaryData] = useState(null);
  const [focusQuery, setFocusQuery] = useState('');
  const [loadingSummary, setLoadingSummary] = useState(false);

  // Panel 3: Cross-Examination
  const [findingText, setFindingText] = useState('Employee user_x stole Quarterly_Financials.xlsx via USB drive');
  const [findingCitations, setFindingCitations] = useState(['EVT-0043', 'EVT-0047']);
  const [rebuttalBrief, setRebuttalBrief] = useState(null);
  const [loadingCrossExamine, setLoadingCrossExamine] = useState(false);
  const [evidenceAdded, setEvidenceAdded] = useState(false);

  // Modal: Event Inspector
  const [inspectEventId, setInspectEventId] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);

  // Initial load
  useEffect(() => {
    fetchHealth();
    fetchCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseData(selectedCaseId);
    }
  }, [selectedCaseId]);

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      setSystemHealth(data);
    } catch (e) {
      console.error('Health check failed', e);
    }
  };

  const fetchCases = async () => {
    try {
      const res = await fetch('/api/cases');
      const data = await res.json();
      setCases(data);
    } catch (e) {
      console.error('Failed to fetch cases', e);
    }
  };

  const loadCaseData = async (caseId) => {
    try {
      const res = await fetch(`/api/cases/${caseId}`);
      const data = await res.json();
      setCurrentCase(data);
      setEvidenceAdded(false);
      
      // Auto-trigger anomaly detection and summary for the selected case
      triggerAnomalies(caseId, data);
      triggerSummary(caseId, data);
      
      // Pre-fill finding text based on case
      if (caseId.includes('USB')) {
        setFindingText('Employee user_x exfiltrated confidential file Quarterly_Financials.xlsx to removable USB device');
        setFindingCitations(['EVT-0043', 'EVT-0047']);
      } else {
        setFindingText('Routine employee login and document handling during business hours');
        setFindingCitations(['EVT-B001', 'EVT-B005']);
      }
      setRebuttalBrief(null);
    } catch (e) {
      console.error('Failed to load case data', e);
    }
  };

  const triggerAnomalies = async (caseId, caseData) => {
    setLoadingAnomalies(true);
    try {
      const res = await fetch('/api/anomalies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId, case_data: caseData })
      });
      const data = await res.json();
      setAnomalies(data);
    } catch (e) {
      console.error('Failed to detect anomalies', e);
    } finally {
      setLoadingAnomalies(false);
    }
  };

  const triggerSummary = async (caseId, caseData, focus) => {
    setLoadingSummary(true);
    try {
      const res = await fetch('/api/summarize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId || selectedCaseId,
          case_data: caseData || currentCase,
          focus: focus !== undefined ? focus : focusQuery
        })
      });
      const data = await res.json();
      setSummaryData(data);
    } catch (e) {
      console.error('Failed to summarize', e);
    } finally {
      setLoadingSummary(false);
    }
  };

  const triggerCrossExamination = async () => {
    setLoadingCrossExamine(true);
    try {
      const res = await fetch('/api/cross-examine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: selectedCaseId,
          case_data: currentCase,
          finding_text: findingText,
          citations: findingCitations
        })
      });
      const data = await res.json();
      setRebuttalBrief(data);
      setEvidenceAdded(false);
    } catch (e) {
      console.error('Cross-examination failed', e);
    } finally {
      setLoadingCrossExamine(false);
    }
  };

  const simulateCorroboratingEvidence = async () => {
    if (!rebuttalBrief) return;
    setLoadingCrossExamine(true);

    // Three decisive corroborating forensic artifacts
    const newEvents = [
      {
        event_id: 'EVT-CORROB-XML-01',
        timestamp_utc: '2025-03-14T23:10:00Z',
        clock_uncertainty_sec: 0.0,
        source: 'windows_security_log',
        actor: 'forensic_investigator',
        action: 'other',
        object: 'C:\\Windows\\System32\\Tasks\\DailyArchiveJob.xml',
        details: {
          destination_drive: 'D:',
          action_exec: 'backup_sync.ps1 -Target D:\\ArchiveShare',
          mismatch: true,
          notes: 'Task definition proves archive target was network partition D:, NOT removable USB drive E:.'
        },
        evidence_hash: '5f9b4c2e1d0a876321456987abcdefe3344556677889900aabbccddeeff00112',
        raw_ref: 'DailyArchiveJob.xml:Task_Actions'
      },
      {
        event_id: 'EVT-CORROB-CCTV-02',
        timestamp_utc: '2025-03-14T23:15:00Z',
        clock_uncertainty_sec: 0.5,
        source: 'cctv',
        actor: 'forensic_investigator',
        action: 'other',
        object: 'Finance_Floor_Camera_04',
        details: {
          physical_presence: true,
          user_x_sitting: true,
          badge_swiped: 'BADGE-USER-X',
          notes: 'Biometric turnstile and high-res CCTV confirm user_x was physically present at workstation WS-FIN-04 during 22:25-22:36 IST.'
        },
        evidence_hash: '9a8b7c6d5e4f3210fedcba0987654321112233445566778899aabbccddeeff00',
        raw_ref: 'CCTV_FinanceBay_Camera4:22:25:00'
      },
      {
        event_id: 'EVT-CORROB-ASSET-03',
        timestamp_utc: '2025-03-14T23:20:00Z',
        clock_uncertainty_sec: 0.0,
        source: 'other',
        actor: 'it_asset_officer',
        action: 'other',
        object: 'Enterprise_IT_Asset_Database',
        details: {
          is_authorized_asset: false,
          serial_number: '4C530001280424107192',
          status: 'unregistered_personal_device',
          notes: 'Serial number 4C530001280424107192 does not exist in corporate hardware registry; confirmed personal unauthorized media.'
        },
        evidence_hash: '77889900aabbccddeeff11223344556699887766554433221100ffeeddccbbaa',
        raw_ref: 'AssetManagement_System_API:Serial_Query'
      }
    ];

    try {
      const res = await fetch(`/api/cross-examine/${selectedCaseId}/add-evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_events: newEvents })
      });
      const updated = await res.json();
      setRebuttalBrief(updated);
      setEvidenceAdded(true);
    } catch (e) {
      console.error('Failed to add evidence', e);
    } finally {
      setLoadingCrossExamine(false);
    }
  };

  const handleSelectAnomalyAsFinding = (anom) => {
    setFindingText(anom.suggested_finding || anom.explanation);
    setFindingCitations(anom.event_ids || []);
    // Trigger cross-examination immediately
    setTimeout(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 100);
  };

  const exportBriefJSON = () => {
    if (!rebuttalBrief) return;
    const blob = new Blob([JSON.stringify(rebuttalBrief, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RebuttalBrief_${selectedCaseId}_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const printCourtroomBrief = () => {
    if (!rebuttalBrief) return;
    const printWindow = window.open('', '_blank');
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Courtroom Rebuttal Brief - ${selectedCaseId}</title>
        <style>
          body { font-family: 'Times New Roman', serif; margin: 40px; color: #111; line-height: 1.5; }
          .header { text-align: center; border-bottom: 2px solid #000; padding-bottom: 15px; margin-bottom: 25px; }
          .title { font-size: 20px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
          .subtitle { font-size: 14px; margin-top: 5px; }
          .badge { display: inline-block; padding: 4px 10px; font-size: 12px; font-weight: bold; border: 1px solid #000; margin: 10px 0; }
          .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }
          .meta-table td { padding: 6px 10px; border: 1px solid #ccc; }
          .section-title { font-size: 16px; font-weight: bold; text-transform: uppercase; border-bottom: 1px solid #000; margin-top: 25px; margin-bottom: 10px; padding-bottom: 3px; }
          .finding-box { background: #f4f4f4; border-left: 4px solid #000; padding: 12px; margin-bottom: 20px; font-size: 14px; }
          .hypo-card { border: 1px solid #bbb; padding: 12px; margin-bottom: 15px; border-radius: 4px; }
          .status { font-weight: bold; text-transform: uppercase; }
          .status-open { color: #b45309; }
          .status-ruled_out { color: #15803d; text-decoration: line-through; }
          .status-stands { color: #b91c1c; }
          .cert-box { border: 1px solid #888; background: #fafafa; padding: 15px; font-size: 12px; margin-top: 30px; }
          @media print { body { margin: 20px; } button { display: none; } }
        </style>
      </head>
      <body>
        <div class="header">
          <div class="title">HIGH COURT OF JUDICATURE / SPECIAL SESSIONS COURT</div>
          <div class="subtitle">FORENSIC SCIENCE INVESTIGATION REPORT & ADVERSARIAL REBUTTAL BRIEF</div>
          <div class="badge">EVIDENTIAL STRENGTH ASSESSMENT: ${rebuttalBrief.finding_strength.toUpperCase()}</div>
        </div>

        <table class="meta-table">
          <tr>
            <td><strong>CASE ID:</strong> ${selectedCaseId}</td>
            <td><strong>DATE OF REPORT:</strong> ${new Date().toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</td>
          </tr>
          <tr>
            <td><strong>EXAMINER:</strong> AI Reasoning & Forensic Engine (SUTRAM)</td>
            <td><strong>GOVERNING LAW:</strong> Bharatiya Sakshya Adhiniyam, 2023 (Sec 63)</td>
          </tr>
        </table>

        <div class="section-title">I. Primary Prosecution Finding</div>
        <div class="finding-box">
          <strong>Finding Statement:</strong> ${rebuttalBrief.finding.text}<br/>
          <strong>Cited Timeline Evidentiary Anchors:</strong> ${rebuttalBrief.finding.citations.join(', ')}
        </div>

        <div class="section-title">II. Adversarial Self-Cross-Examination & Defense Hypotheses</div>
        <p style="font-size: 13px; color: #555;">The following alternative explanations were rigorously tested against all timeline records to identify evidential loopholes before trial submission:</p>
        
        ${rebuttalBrief.counter_hypotheses.map(h => `
          <div class="hypo-card">
            <div>
              <strong>${h.id}: ${h.alternative_explanation}</strong>
            </div>
            <div style="font-size: 12px; margin: 6px 0;">
              Status: <span class="status status-${h.status}">[${h.status.toUpperCase()}]</span> |
              Plausibility: <strong>${h.plausibility.toUpperCase()}</strong> |
              Supporting Signals: ${h.supporting_signals_in_case.length > 0 ? h.supporting_signals_in_case.join(', ') : 'None'}
            </div>
            ${h.rationale ? `<div style="font-size: 12px; color: #444; margin-bottom: 6px;"><em>Assessment Note:</em> ${h.rationale}</div>` : ''}
            <div style="font-size: 12px;"><strong>Artifacts Required to Rule Out:</strong></div>
            <ul style="font-size: 12px; margin-top: 3px; padding-left: 20px;">
              ${h.evidence_needed_to_rule_out.map(item => `<li>${item}</li>`).join('')}
            </ul>
          </div>
        `).join('')}

        <div class="section-title">III. Statutory Admissibility Notes</div>
        <ul style="font-size: 13px;">
          ${rebuttalBrief.admissibility_notes.map(note => `<li>${note}</li>`).join('')}
        </ul>

        <div class="cert-box">
          <strong>STATUTORY DECLARATION UNDER SECTION 63, BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023:</strong><br/>
          I hereby certify that the electronic outputs produced above originate from authenticated digital images acquired following standard cyber forensic protocols. Hashes have been cross-verified with SHA-256 signatures, and no unauthorized alteration occurred throughout the evaluation lifecycle.
          <br/><br/>
          Signature: __________________________ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Digital Seal: [ SUTRAM-AIRGAP-VERIFIED ]
        </div>

        <script>
          window.onload = function() { window.print(); }
        </script>
      </body>
      </html>
    `;
    printWindow.document.write(htmlContent);
    printWindow.document.close();
  };

  const inspectedEvent = currentCase?.events?.find(e => e.event_id === inspectEventId);

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
            <Scale className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                <span>SUTRAM</span>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">
                  सूत्रम्
                </span>
              </h1>
              <span className="text-xs text-slate-400 border-l border-slate-700 pl-2 hidden sm:inline">
                AI Reasoning & Adversarial Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">Digital Forensics for Indian Law Enforcement</p>
          </div>
        </div>

        {/* Status Pills */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 text-xs font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>AIR-GAPPED (ZERO EGRESS)</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-slate-300 text-xs font-mono">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>LLM: {systemHealth?.llm_provider?.toUpperCase() || 'MOCK'}</span>
          </div>

          {/* Case Selector */}
          <div className="flex items-center gap-2 bg-slate-800 border border-slate-700 rounded-lg px-2 py-1">
            <Database className="w-3.5 h-3.5 text-amber-400" />
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="bg-transparent text-xs text-slate-200 outline-none font-medium cursor-pointer"
            >
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id} className="bg-slate-900 text-slate-200">
                  {c.case_id}: {c.title}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => loadCaseData(selectedCaseId)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Reload Case Telemetry"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Main 3-Panel Grid */}
      <main className="flex-1 p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 max-w-[1900px] w-full mx-auto">
        {/* PANEL 1: ANOMALY DETECTION (3 cols) */}
        <section className="lg:col-span-3 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-3.5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h2 className="text-sm font-semibold text-white tracking-wide uppercase">Forensic Anomalies</h2>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {anomalies.length} Detected
            </span>
          </div>

          <div className="p-2 border-b border-slate-800/60 bg-slate-950/40 flex items-center justify-between text-[11px] text-slate-400 px-3">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span> Rules Layer
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-purple-400"></span> IsolationForest
            </span>
            <span>Sorted by Suspicion</span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-3">
            {loadingAnomalies ? (
              <div className="flex flex-col items-center justify-center h-48 text-slate-400 text-xs">
                <RefreshCw className="w-5 h-5 animate-spin mb-2 text-cyan-400" />
                Scanning chronological timeline...
              </div>
            ) : anomalies.length === 0 ? (
              <div className="text-center p-8 text-slate-400 text-xs bg-slate-950/40 rounded-lg border border-slate-800/80">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                <p className="font-medium text-slate-300">No Critical Anomalies</p>
                <p className="mt-1 text-[11px] text-slate-500">
                  Telemetry within normal baseline limits. The engine does not over-accuse routine operations.
                </p>
              </div>
            ) : (
              anomalies.map((anom) => {
                const isHigh = anom.score >= 0.90;
                return (
                  <div
                    key={anom.anomaly_id}
                    className={`p-3 rounded-lg border transition text-xs flex flex-col gap-2 ${
                      isHigh
                        ? 'bg-rose-950/20 border-rose-900/50 hover:border-rose-700/80'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                          anom.detection_method === 'rule_based'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                            : 'bg-purple-950 text-purple-300 border border-purple-800/60'
                        }`}
                      >
                        {anom.type.replace(/_/g, ' ')}
                      </span>
                      <div className="flex items-center gap-1 text-[11px] font-mono font-bold">
                        <span className={isHigh ? 'text-rose-400' : 'text-amber-400'}>
                          {(anom.score * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>

                    <p className="text-slate-300 text-[12px] leading-relaxed">{anom.explanation}</p>

                    <div className="flex flex-wrap items-center gap-1 mt-1">
                      <span className="text-[10px] text-slate-500 font-mono">Signals:</span>
                      {anom.event_ids.map((eid) => (
                        <button
                          key={eid}
                          onClick={() => setInspectEventId(eid)}
                          className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-cyan-900/80 text-cyan-300 border border-slate-700 transition"
                        >
                          {eid}
                        </button>
                      ))}
                    </div>

                    <button
                      onClick={() => handleSelectAnomalyAsFinding(anom)}
                      className="mt-1 text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center justify-end gap-1 font-medium transition"
                    >
                      Cross-Examine Finding <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* PANEL 2: AI-ASSISTED SUMMARIZATION & CITATIONS (4 cols) */}
        <section className="lg:col-span-4 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-3.5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white tracking-wide uppercase">AI Summary & Citations</h2>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Validator Active</span>
            </div>
          </div>

          {/* Search / Focus Query Bar */}
          <div className="p-2.5 border-b border-slate-800/80 bg-slate-950/60 flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Specific focus (e.g. USB exfiltration, RDP ingress)..."
                value={focusQuery}
                onChange={(e) => setFocusQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && triggerSummary(selectedCaseId, currentCase, focusQuery)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500 transition"
              />
            </div>
            <button
              onClick={() => triggerSummary(selectedCaseId, currentCase, focusQuery)}
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition flex items-center gap-1"
            >
              Summarize
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-3">
            {loadingSummary ? (
              <div className="flex flex-col items-center justify-center h-48 text-slate-400 text-xs">
                <RefreshCw className="w-5 h-5 animate-spin mb-2 text-cyan-400" />
                Synthesizing evidence with citation validation...
              </div>
            ) : !summaryData || summaryData.summary.length === 0 ? (
              <div className="text-center p-8 text-slate-400 text-xs">
                Click "Summarize" to generate verified factual findings.
              </div>
            ) : (
              <>
                <div className="space-y-2.5">
                  {summaryData.summary.map((claim, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs space-y-2"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-slate-200 leading-relaxed font-medium">{claim.claim}</p>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400 border border-slate-700 whitespace-nowrap">
                          {(claim.confidence * 100).toFixed(0)}% Conf
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-800/60">
                        <span className="text-[10px] text-slate-500 font-mono">Citations:</span>
                        {claim.citations.map((cid) => (
                          <button
                            key={cid}
                            onClick={() => setInspectEventId(cid)}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 transition flex items-center gap-1"
                          >
                            <span>{cid}</span>
                            <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                          </button>
                        ))}
                        <span className="ml-auto text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" /> Validated
                        </span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Limitations Box */}
                {summaryData.limitations && summaryData.limitations.length > 0 && (
                  <div className="mt-4 p-3 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs space-y-1.5">
                    <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[11px] uppercase tracking-wide">
                      <HelpCircle className="w-3.5 h-3.5" />
                      <span>Evidential Caveats & Limitations</span>
                    </div>
                    <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-1 pl-1">
                      {summaryData.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        </section>

        {/* PANEL 3: ADVERSARIAL SELF-CROSS-EXAMINATION (5 cols - HEADLINE FEATURE) */}
        <section className="lg:col-span-5 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-3.5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Scale className="w-4 h-4 text-police-gold" />
              <h2 className="text-sm font-semibold text-white tracking-wide uppercase">Adversarial Self-Cross-Examination</h2>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={exportBriefJSON}
                disabled={!rebuttalBrief}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 disabled:opacity-40 transition"
                title="Export Brief JSON"
              >
                <Download className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={printCourtroomBrief}
                disabled={!rebuttalBrief}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 disabled:opacity-40 text-xs font-medium flex items-center gap-1 transition"
                title="Print Formal Courtroom Brief"
              >
                <Printer className="w-3.5 h-3.5 text-amber-400" />
                <span>Court Brief</span>
              </button>
            </div>
          </div>

          {/* Finding Input Box */}
          <div className="p-3 border-b border-slate-800/80 bg-slate-950/60 space-y-2">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-semibold text-slate-300">Target Accusation / Finding:</span>
              <span className="font-mono text-cyan-400">Anchors: {findingCitations.join(', ')}</span>
            </div>
            <textarea
              rows={2}
              value={findingText}
              onChange={(e) => setFindingText(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-100 outline-none focus:border-amber-500 transition resize-none"
              placeholder="Enter candidate prosecution finding to cross-examine..."
            />
            <div className="flex items-center justify-between gap-2">
              <button
                onClick={triggerCrossExamination}
                disabled={loadingCrossExamine}
                className="flex-1 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition flex items-center justify-center gap-1.5 shadow"
              >
                {loadingCrossExamine ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Scale className="w-3.5 h-3.5" />
                )}
                <span>Cross-Examine Finding</span>
              </button>

              {rebuttalBrief && (
                <button
                  onClick={simulateCorroboratingEvidence}
                  disabled={loadingCrossExamine || evidenceAdded}
                  className={`py-1.5 px-3 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 border ${
                    evidenceAdded
                      ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      : 'bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border-cyan-800'
                  }`}
                  title="Simulate pulling Task Scheduler XML, CCTV records, and IT asset database"
                >
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{evidenceAdded ? 'Corroborated' : 'Pull Corroborating Artifacts'}</span>
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-3">
            {!rebuttalBrief ? (
              <div className="text-center p-12 text-slate-400 text-xs">
                <Scale className="w-10 h-10 text-amber-500/40 mx-auto mb-3" />
                <p className="font-semibold text-slate-300 text-sm">Attack Your Own Finding</p>
                <p className="mt-1 text-slate-500 max-w-sm mx-auto">
                  Click "Cross-Examine Finding" to activate the defense attorney engine. It will list alternative explanations, rule-out tests, and Indian statutory admissibility certificates.
                </p>
              </div>
            ) : (
              <>
                {/* Strength Meter */}
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
                    rebuttalBrief.finding_strength === 'strong'
                      ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                      : rebuttalBrief.finding_strength === 'moderate'
                      ? 'bg-amber-950/40 border-amber-800/80 text-amber-300'
                      : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
                  }`}
                >
                  <div>
                    <span className="text-[10px] font-mono tracking-wider uppercase block text-slate-400">
                      Objective Evidential Strength
                    </span>
                    <span className="text-sm font-bold uppercase tracking-wide">
                      {rebuttalBrief.finding_strength === 'strong' && 'COURTROOM PROOF (STRONG)'}
                      {rebuttalBrief.finding_strength === 'moderate' && 'MODERATE (ACTIONABLE LOOPHOLES)'}
                      {rebuttalBrief.finding_strength === 'weak' && 'HIGHLY VULNERABLE (WEAK)'}
                    </span>
                    <p className="text-[11px] text-slate-300 mt-0.5">
                      {rebuttalBrief.finding_strength === 'weak' &&
                        'The defense holds significant merit: 2 alternative explanations are supported by case events. Cross-examination will break the accusation unless corroborating artifacts are pulled.'}
                      {rebuttalBrief.finding_strength === 'strong' &&
                        'All defense counter-hypotheses have been forensically eliminated via corroborating evidence. Finding stands beyond reasonable doubt.'}
                      {rebuttalBrief.finding_strength === 'moderate' &&
                        'Alternative theories partially unverified. Pull listed artifacts to establish strict liability.'}
                    </p>
                  </div>
                  <div className="text-right">
                    <span
                      className={`text-xs px-2.5 py-1 rounded font-mono font-bold uppercase ${
                        rebuttalBrief.finding_strength === 'strong'
                          ? 'bg-emerald-900 text-emerald-200'
                          : rebuttalBrief.finding_strength === 'moderate'
                          ? 'bg-amber-900 text-amber-200'
                          : 'bg-rose-900 text-rose-200'
                      }`}
                    >
                      {rebuttalBrief.finding_strength}
                    </span>
                  </div>
                </div>

                {/* 3-Column Counter Hypotheses Matrix */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-[11px] font-semibold uppercase text-slate-400 px-1">
                    <span>Defense Theories & Loophole Audit</span>
                    <span>{rebuttalBrief.counter_hypotheses.length} Checked</span>
                  </div>

                  {rebuttalBrief.counter_hypotheses.map((hypo) => {
                    const isRuledOut = hypo.status === 'ruled_out';
                    return (
                      <div
                        key={hypo.id}
                        className={`p-3 rounded-lg border text-xs space-y-2 transition ${
                          isRuledOut
                            ? 'bg-slate-950/40 border-slate-800/80 opacity-75'
                            : hypo.plausibility === 'high'
                            ? 'bg-rose-950/20 border-rose-900/60'
                            : 'bg-slate-950/60 border-slate-800'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                              {hypo.id}
                            </span>
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                                isRuledOut
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : hypo.status === 'stands'
                                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                  : 'bg-amber-950 text-amber-400 border border-amber-800 animate-pulse'
                              }`}
                            >
                              {isRuledOut ? 'Ruled Out' : hypo.status.toUpperCase()}
                            </span>
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                                hypo.plausibility === 'high'
                                  ? 'text-rose-400 bg-rose-950/50'
                                  : hypo.plausibility === 'medium'
                                  ? 'text-amber-400 bg-amber-950/50'
                                  : 'text-slate-400 bg-slate-800'
                              }`}
                            >
                              Plausibility: {hypo.plausibility}
                            </span>
                          </div>
                        </div>

                        <p
                          className={`text-slate-200 leading-relaxed font-medium ${
                            isRuledOut ? 'line-through text-slate-400' : ''
                          }`}
                        >
                          {hypo.alternative_explanation}
                        </p>

                        {/* Supporting signals in case */}
                        {hypo.supporting_signals_in_case && hypo.supporting_signals_in_case.length > 0 && (
                          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                            <span className="text-[10px] font-mono text-slate-500">Supporting Signals:</span>
                            {hypo.supporting_signals_in_case.map((eid) => (
                              <button
                                key={eid}
                                onClick={() => setInspectEventId(eid)}
                                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 transition"
                              >
                                {eid}
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Rationale if present */}
                        {hypo.rationale && (
                          <p className="text-[11px] text-cyan-300/90 font-mono bg-cyan-950/30 p-1.5 rounded border border-cyan-900/40">
                            <strong>Audit Assessment:</strong> {hypo.rationale}
                          </p>
                        )}

                        {/* Evidence Needed To Rule Out */}
                        <div className="pt-2 border-t border-slate-800/60 space-y-1">
                          <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wide flex items-center gap-1">
                            <Search className="w-3 h-3" /> Concrete Artifacts to Pull NOW:
                          </span>
                          <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-0.5 pl-1">
                            {hypo.evidence_needed_to_rule_out.map((item, i) => (
                              <li key={i}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Indian Evidence Law Admissibility */}
                {rebuttalBrief.admissibility_notes && rebuttalBrief.admissibility_notes.length > 0 && (
                  <div className="mt-4 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                    <div className="flex items-center gap-1.5 text-police-gold font-semibold text-[11px] uppercase tracking-wide">
                      <Scale className="w-3.5 h-3.5" />
                      <span>Statutory Compliance (Bharatiya Sakshya Adhiniyam, 2023)</span>
                    </div>
                    <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-1 pl-1">
                      {rebuttalBrief.admissibility_notes.map((note, i) => (
                        <li key={i}>{note}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        </section>
      </main>

      {/* EVENT INSPECTOR MODAL */}
      {inspectEventId && inspectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded font-mono text-xs bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                  {inspectedEvent.event_id}
                </span>
                <span className="text-sm font-semibold text-white">Forensic Timeline Event Inspection</span>
              </div>
              <button
                onClick={() => setInspectEventId(null)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3 bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">TIMESTAMP (UTC):</span>
                  <span className="text-slate-200 font-semibold">{inspectedEvent.timestamp_utc}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">CLOCK UNCERTAINTY:</span>
                  <span className="text-slate-200 font-semibold">± {inspectedEvent.clock_uncertainty_sec} sec</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">SOURCE SENSOR:</span>
                  <span className="text-cyan-400 font-semibold">{inspectedEvent.source}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">ACTOR:</span>
                  <span className="text-amber-400 font-semibold">{inspectedEvent.actor}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">ACTION:</span>
                  <span className="text-purple-400 font-semibold">{inspectedEvent.action}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TARGET OBJECT:</span>
                  <span className="text-slate-200 font-semibold truncate block" title={inspectedEvent.object}>
                    {inspectedEvent.object}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-1 font-sans font-semibold">
                  Evidence SHA-256 Hash (Section 63 BSA Chain of Custody):
                </span>
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] text-emerald-400 break-all select-all">
                  {inspectedEvent.evidence_hash}
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-1 font-sans font-semibold">
                  Source Reference / Disk Offset:
                </span>
                <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[11px] text-slate-300">
                  {inspectedEvent.raw_ref}
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-1 font-sans font-semibold">
                  Free-form Event Details Payload:
                </span>
                <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto max-h-48">
                  {JSON.stringify(inspectedEvent.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-3 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setInspectEventId(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
