import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Home,
  FileText,
  Share2,
  Clock,
  ShieldCheck,
  BarChart3,
  Search,
  Bell,
  User,
  Image,
  File,
  Binary,
  Mail,
  FileType,
  Video,
  Braces,
  Archive,
  Lock,
  CheckCircle2,
  Hash,
  Activity,
  Link2,
  Filter,
  Maximize2,
  RefreshCw,
  AlertTriangle,
  Scale,
  Cpu,
  ChevronRight,
  Loader2,
  XCircle,
  Database,
} from 'lucide-react';

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: Home },
  { id: 'evidence', label: 'Evidence Files', icon: FileText },
  { id: 'correlation', label: 'Correlation Graph', icon: Share2 },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'integrity', label: 'Integrity Verification', icon: ShieldCheck },
  { id: 'ai', label: 'AI Reasoning', icon: Cpu },
  { id: 'reports', label: 'Reports', icon: BarChart3 },
];

function iconForName(name = '', type = '') {
  const n = (name + ' ' + type).toLowerCase();
  if (n.includes('jpg') || n.includes('png') || n.includes('image') || n.includes('cctv')) return Image;
  if (n.includes('eml') || n.includes('mail') || n.includes('outlook')) return Mail;
  if (n.includes('pdf')) return FileType;
  if (n.includes('mp4') || n.includes('video')) return Video;
  if (n.includes('json') || n.includes('xml') || n.includes('config')) return Braces;
  if (n.includes('zip') || n.includes('archive')) return Archive;
  if (n.includes('bin') || n.includes('dump') || n.includes('evtx')) return Binary;
  if (n.includes('log') || n.includes('txt') || n.includes('security')) return FileText;
  return File;
}

function GraphCanvas({ nodes = [], edges = [] }) {
  const W = 560;
  const H = 400;
  const cx = W / 2;
  const cy = H / 2;

  const positioned = useMemo(() => {
    if (!nodes.length) return [];
    const hub = nodes.find((n) => n.type === 'hub') || nodes[0];
    const others = nodes.filter((n) => n.id !== hub.id).slice(0, 18);
    const R = 140;
    return [
      { ...hub, x: cx, y: cy, size: 52 },
      ...others.map((n, i) => {
        const angle = (2 * Math.PI * i) / Math.max(others.length, 1) - Math.PI / 2;
        return {
          ...n,
          x: cx + R * Math.cos(angle),
          y: cy + R * Math.sin(angle),
          size: 40,
        };
      }),
    ];
  }, [nodes]);

  const byId = useMemo(() => Object.fromEntries(positioned.map((n) => [n.id, n])), [positioned]);

  const colorFor = (t) => {
    if (t === 'hub') return '#22d3ee';
    if (t === 'source') return '#818cf8';
    if (t === 'host') return '#34d399';
    return '#38bdf8';
  };

  return (
    <div className="relative h-full w-full overflow-hidden rounded-xl bg-[#0a1224]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(34,211,238,0.07)_0%,_transparent_65%)]" />
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full">
        <defs>
          <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.25" />
          </linearGradient>
        </defs>
        {edges.slice(0, 80).map((e, i) => {
          const a = byId[e.from];
          const b = byId[e.to];
          if (!a || !b) return null;
          return (
            <line
              key={i}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="url(#edgeGrad)"
              strokeWidth="1.25"
              opacity="0.75"
            />
          );
        })}
        {positioned.map((n) => (
          <g key={n.id} transform={`translate(${n.x},${n.y})`}>
            <circle r={n.size / 2 + 3} fill="none" stroke={colorFor(n.type)} strokeOpacity="0.25" />
            <circle
              r={n.size / 2}
              fill={colorFor(n.type)}
              opacity="0.9"
              style={{ filter: 'drop-shadow(0 0 10px rgba(34,211,238,0.35))' }}
            />
            <text
              y={n.size / 2 + 14}
              textAnchor="middle"
              fill="#e2e8f0"
              fontSize="9"
              fontWeight="500"
            >
              {(n.label || n.id).slice(0, 22)}
            </text>
            {n.sub && (
              <text y={n.size / 2 + 25} textAnchor="middle" fill="#64748b" fontSize="8">
                {n.sub}
              </text>
            )}
          </g>
        ))}
      </svg>
      <div className="absolute bottom-3 left-1/2 flex -translate-x-1/2 items-center gap-4 rounded-full border border-slate-700/60 bg-slate-900/80 px-4 py-1.5 text-[10px] text-slate-400 backdrop-blur">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-cyan-400" /> File
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-violet-400" /> Source
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-emerald-400" /> Host
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-slate-400" /> Connection
        </span>
      </div>
    </div>
  );
}

const FALLBACK_FILES = [
  { id: 'f1', name: 'image_001.jpg', type: 'Image', size: '2.4 MB', sha: 'a3f5e6e9d27e8a1...', sha_full: 'a3f5' },
  { id: 'f2', name: 'log_2025-06-14.txt', type: 'Text', size: '12 KB', sha: '6b1f9e2c4d8a713e...', sha_full: '6b1f' },
  { id: 'f3', name: 'system_dump.bin', type: 'Binary', size: '8.7 MB', sha: '9c7d4e6b2f1a8c3d...', sha_full: '9c7d' },
  { id: 'f4', name: 'email.eml', type: 'Email', size: '45 KB', sha: '2e6f9a1c3d5b7e8f...', sha_full: '2e6f' },
  { id: 'f5', name: 'report.pdf', type: 'PDF', size: '1.2 MB', sha: '7f3a6d9c2e1b4f8a...', sha_full: '7f3a' },
  { id: 'f6', name: 'video.mp4', type: 'Video', size: '15.6 MB', sha: '4c8e1f2a7b9d6c3e...', sha_full: '4c8e' },
  { id: 'f7', name: 'config.json', type: 'JSON', size: '6 KB', sha: '5d2f8a9c7e6b1d4f...', sha_full: '5d2f' },
  { id: 'f8', name: 'archive.zip', type: 'Archive', size: '3.1 MB', sha: '8e6c1f3a9d4b7c2e...', sha_full: '8e6c' },
];

const FALLBACK_TIMELINE = [
  { time: '10:24', label: 'File Collection' },
  { time: '10:32', label: 'System Access' },
  { time: '10:41', label: 'File Modification' },
  { time: '11:03', label: 'Correlation Analysis' },
  { time: '11:12', label: 'Integrity Verification' },
  { time: '11:18', label: 'Report Generated' },
];

const FALLBACK_CUSTODY = [
  { title: 'File Collected', detail: 'Evidence acquired from source', ts: '2025-06-14 10:24:32', icon: 'file' },
  { title: 'Hash Computed', detail: 'SHA-256 & SHA-512 generated', ts: '2025-06-14 10:25:18', icon: 'hash' },
  { title: 'Analyzed', detail: 'Correlation & analysis completed', ts: '2025-06-14 11:03:45', icon: 'activity' },
  { title: 'Verified', detail: 'Integrity check passed', ts: '2025-06-14 11:12:07', icon: 'shield' },
];

export default function App() {
  const [activeNav, setActiveNav] = useState('dashboard');
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState(null);
  const [graphFilter, setGraphFilter] = useState('All');
  const [cases, setCases] = useState([]);
  const [caseId, setCaseId] = useState('');
  const [files, setFiles] = useState(FALLBACK_FILES);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [timeline, setTimeline] = useState(FALLBACK_TIMELINE);
  const [custody, setCustody] = useState(FALLBACK_CUSTODY);
  const [integrity, setIntegrity] = useState({ total: 8, verified: 8, tampered: 0, status: 'VERIFIED' });
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);

  // AI panel state
  const [anomalies, setAnomalies] = useState([]);
  const [summary, setSummary] = useState(null);
  const [brief, setBrief] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [findingText, setFindingText] = useState(
    'Employee user_x stole Quarterly_Financials.xlsx via USB drive'
  );

  const loadDashboard = useCallback(async (id) => {
    if (!id) return;
    try {
      const [ev, gr, tl, cu] = await Promise.all([
        fetch(`/api/cases/${id}/evidence`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/cases/${id}/graph`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/cases/${id}/timeline?limit=12`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/cases/${id}/custody`).then((r) => (r.ok ? r.json() : null)),
      ]);
      if (ev) {
        setFiles(ev.files?.length ? ev.files : FALLBACK_FILES);
        setIntegrity({
          total: ev.total ?? 0,
          verified: ev.verified ?? 0,
          tampered: ev.tampered ?? 0,
          status: 'VERIFIED',
        });
        if (ev.files?.[0]) setSelectedId(ev.files[0].id);
      }
      if (gr) setGraph({ nodes: gr.nodes || [], edges: gr.edges || [] });
      if (tl?.events?.length) {
        setTimeline(
          tl.events.slice(0, 8).map((e) => ({
            time: e.time || '—',
            label: e.label || e.action || e.event_id,
          }))
        );
      }
      if (cu?.steps?.length) setCustody(cu.steps);
      setApiOnline(true);
      setError(null);
    } catch (e) {
      console.warn('Dashboard APIs unavailable, using demo data', e);
      setApiOnline(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const h = await fetch('/api/health').then((r) => (r.ok ? r.json() : null)).catch(() => null);
        if (!cancelled && h) {
          setHealth(h);
          setApiOnline(true);
        }
        const list = await fetch('/api/cases').then((r) => (r.ok ? r.json() : [])).catch(() => []);
        if (cancelled) return;
        setCases(list || []);
        const preferred =
          list?.find((c) => (c.case_id || '').includes('USB'))?.case_id ||
          list?.[0]?.case_id ||
          '';
        if (preferred) {
          setCaseId(preferred);
          await loadDashboard(preferred);
        } else {
          // offline demo graph
          setGraph({
            nodes: [
              { id: 'center', label: 'Case Hub', type: 'hub', sub: 'DEMO' },
              ...FALLBACK_FILES.map((f) => ({
                id: f.id,
                label: f.name,
                type: 'file',
                sub: f.type,
              })),
            ],
            edges: FALLBACK_FILES.map((f) => ({ from: 'center', to: f.id, kind: 'contains' })),
          });
        }
      } catch (e) {
        if (!cancelled) setError(String(e.message || e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loadDashboard]);

  useEffect(() => {
    if (caseId) loadDashboard(caseId);
  }, [caseId, loadDashboard]);

  const filteredFiles = useMemo(() => {
    if (!search.trim()) return files;
    const q = search.toLowerCase();
    return files.filter(
      (f) =>
        (f.name || '').toLowerCase().includes(q) ||
        (f.type || '').toLowerCase().includes(q) ||
        (f.sha || '').toLowerCase().includes(q)
    );
  }, [files, search]);

  const runAnomalies = async () => {
    if (!caseId) return;
    setAiLoading(true);
    try {
      const res = await fetch('/api/anomalies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      const data = await res.json();
      setAnomalies(Array.isArray(data) ? data : []);
    } catch (e) {
      setAnomalies([]);
    } finally {
      setAiLoading(false);
    }
  };

  const runSummary = async () => {
    if (!caseId) return;
    setAiLoading(true);
    try {
      const res = await fetch('/api/summarize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId, focus: 'USB data movement' }),
      });
      setSummary(await res.json());
    } catch (e) {
      setSummary(null);
    } finally {
      setAiLoading(false);
    }
  };

  const runCrossExamine = async () => {
    if (!caseId) return;
    setAiLoading(true);
    try {
      const res = await fetch('/api/cross-examine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          finding_text: findingText,
          citations: ['EVT-0043', 'EVT-0047'],
        }),
      });
      setBrief(await res.json());
    } catch (e) {
      setBrief(null);
    } finally {
      setAiLoading(false);
    }
  };

  const custodyIcon = (name) => {
    if (name === 'hash') return Hash;
    if (name === 'activity') return Activity;
    if (name === 'shield') return ShieldCheck;
    return FileText;
  };

  const showMainDashboard = activeNav !== 'ai';

  return (
    <div className="flex h-screen overflow-hidden bg-[#060b16] text-slate-100">
      {/* Sidebar */}
      <aside className="flex w-[220px] shrink-0 flex-col border-r border-slate-800/80 bg-[#080e1c]">
        <div className="flex items-center gap-2.5 border-b border-slate-800/80 px-4 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/25">
            <span className="text-sm font-bold text-white">D</span>
          </div>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-white">DigiPramaan</div>
            <div className="truncate text-[10px] text-slate-500">AI-Powered Digital Forensics</div>
          </div>
        </div>

        <nav className="flex-1 space-y-0.5 px-2 py-3">
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveNav(item.id)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-[13px] font-medium transition ${
                  active
                    ? 'bg-cyan-500/10 text-cyan-300 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.25)]'
                    : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                <Icon size={16} strokeWidth={active ? 2.2 : 1.8} />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="space-y-1 border-t border-slate-800/80 p-3 text-[10px] text-slate-600">
          <div className="flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${apiOnline ? 'bg-emerald-400' : 'bg-amber-400'}`}
            />
            {apiOnline ? 'API online' : 'Demo mode'}
            {health?.llm_provider && ` · ${health.llm_provider}`}
          </div>
          <div>Evidence Integrity · v1.0</div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-800/80 bg-[#080e1c]/70 px-5 backdrop-blur">
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-white">
              AI-Powered Digital Forensics & Evidence Integrity
            </h1>
            {loading && <Loader2 size={14} className="animate-spin text-cyan-400" />}
          </div>
          <div className="flex items-center gap-3">
            {cases.length > 0 && (
              <select
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                className="max-w-[220px] rounded-lg border border-slate-700/80 bg-slate-900/80 px-2 py-1.5 text-xs text-slate-200 focus:border-cyan-500/50 focus:outline-none"
              >
                {cases.map((c) => (
                  <option key={c.case_id} value={c.case_id}>
                    {c.case_id} ({c.event_count} events)
                  </option>
                ))}
              </select>
            )}
            <div className="relative hidden md:block">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search evidence, file name, hash..."
                className="w-56 rounded-lg border border-slate-700/80 bg-slate-900/80 py-1.5 pl-9 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/30"
              />
            </div>
            <button
              onClick={() => caseId && loadDashboard(caseId)}
              className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-slate-200"
              title="Refresh"
            >
              <RefreshCw size={16} />
            </button>
            <button className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-slate-200">
              <Bell size={16} />
            </button>
            <button className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-800 text-slate-300 ring-1 ring-slate-700">
              <User size={14} />
            </button>
          </div>
        </header>

        {error && (
          <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
            {error} — showing local demo data where needed.
          </div>
        )}

        {/* AI Reasoning panel */}
        {activeNav === 'ai' && (
          <div className="min-h-0 flex-1 overflow-y-auto p-5">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <button
                onClick={runAnomalies}
                disabled={aiLoading || !caseId}
                className="rounded-lg bg-cyan-600/90 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
              >
                Detect Anomalies
              </button>
              <button
                onClick={runSummary}
                disabled={aiLoading || !caseId}
                className="rounded-lg bg-indigo-600/90 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
              >
                AI Summary
              </button>
              <button
                onClick={runCrossExamine}
                disabled={aiLoading || !caseId}
                className="rounded-lg bg-violet-600/90 px-3 py-1.5 text-xs font-medium text-white hover:bg-violet-500 disabled:opacity-50"
              >
                Cross-Examine Finding
              </button>
              {aiLoading && <Loader2 size={16} className="animate-spin text-cyan-400" />}
            </div>

            <div className="mb-4">
              <label className="mb-1 block text-[11px] text-slate-400">Candidate finding</label>
              <input
                value={findingText}
                onChange={(e) => setFindingText(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <section className="rounded-xl border border-slate-800 bg-[#0a1224] p-4">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
                  <AlertTriangle size={14} className="text-amber-400" /> Anomalies
                </h3>
                <ul className="max-h-80 space-y-2 overflow-y-auto text-xs">
                  {anomalies.length === 0 && (
                    <li className="text-slate-500">Run detection to populate.</li>
                  )}
                  {anomalies.slice(0, 12).map((a, i) => (
                    <li key={a.anomaly_id || i} className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-2">
                      <div className="font-medium text-amber-300">
                        {(a.type || 'anomaly').toUpperCase()} · {Math.round((a.score || 0) * 100)}%
                      </div>
                      <div className="mt-1 text-slate-400">{a.explanation}</div>
                    </li>
                  ))}
                </ul>
              </section>

              <section className="rounded-xl border border-slate-800 bg-[#0a1224] p-4">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
                  <FileText size={14} className="text-cyan-400" /> Summary
                </h3>
                <ul className="max-h-80 space-y-2 overflow-y-auto text-xs">
                  {!summary && <li className="text-slate-500">Run AI summary to populate.</li>}
                  {(summary?.summary || []).map((c, i) => (
                    <li key={i} className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-2">
                      <div className="text-slate-200">{c.claim}</div>
                      <div className="mt-1 font-mono text-[10px] text-emerald-400/80">
                        {(c.citations || []).join(', ')}
                      </div>
                    </li>
                  ))}
                </ul>
              </section>

              <section className="rounded-xl border border-slate-800 bg-[#0a1224] p-4">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
                  <Scale size={14} className="text-violet-400" /> Rebuttal Brief
                </h3>
                {!brief && <p className="text-xs text-slate-500">Run cross-examination to populate.</p>}
                {brief && (
                  <div className="max-h-80 space-y-2 overflow-y-auto text-xs">
                    <div className="rounded-lg border border-violet-500/30 bg-violet-500/10 p-2">
                      Strength:{' '}
                      <span className="font-semibold text-violet-300">
                        {(brief.finding_strength || 'unknown').toUpperCase()}
                      </span>
                    </div>
                    {(brief.counter_hypotheses || []).map((h, i) => (
                      <div key={h.id || i} className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-2">
                        <div className="font-medium text-slate-200">
                          [{h.id}] {(h.status || '').toUpperCase()}
                        </div>
                        <div className="mt-1 text-slate-400">{h.hypothesis || h.rationale}</div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          </div>
        )}

        {/* Main dashboard grid */}
        {showMainDashboard && (
          <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[280px_1fr_260px]">
            {/* Evidence Files */}
            <section className="flex min-h-0 flex-col border-r border-slate-800/80 bg-[#070d1a]">
              <div className="flex items-center justify-between border-b border-slate-800/60 px-4 py-3">
                <div>
                  <h2 className="text-sm font-semibold text-white">Evidence Files</h2>
                  <p className="text-[11px] text-slate-500">{files.length} files</p>
                </div>
              </div>
              <div className="border-b border-slate-800/60 px-3 py-2">
                <div className="relative">
                  <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search files..."
                    className="w-full rounded-md border border-slate-700/70 bg-slate-900/60 py-1.5 pl-8 pr-8 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyan-500/40 focus:outline-none"
                  />
                  <Filter size={13} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                </div>
              </div>
              <ul className="flex-1 space-y-1 overflow-y-auto p-2">
                {filteredFiles.map((f) => {
                  const Icon = iconForName(f.name, f.type);
                  const selected = selectedId === f.id;
                  return (
                    <li key={f.id}>
                      <button
                        onClick={() => setSelectedId(f.id)}
                        className={`flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left transition ${
                          selected ? 'bg-cyan-500/10 ring-1 ring-cyan-500/30' : 'hover:bg-slate-800/50'
                        }`}
                      >
                        <div
                          className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${
                            selected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          <Icon size={15} />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-1">
                            <span className="truncate text-[12px] font-medium text-slate-100">
                              {f.name}
                            </span>
                            <CheckCircle2 size={13} className="shrink-0 text-emerald-400" />
                          </div>
                          <div className="mt-0.5 text-[10px] text-slate-500">
                            {f.type}
                            {f.event_count ? ` · ${f.event_count} events` : f.size ? ` · ${f.size}` : ''}
                          </div>
                          <div className="mt-0.5 truncate font-mono text-[9px] text-slate-600">
                            SHA-256: {f.sha || (f.sha_full || '').slice(0, 16)}
                          </div>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>

            {/* Center */}
            <section className="flex min-h-0 flex-col bg-[#060b16]">
              <div className="flex items-center justify-between border-b border-slate-800/60 px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <Share2 size={15} className="text-cyan-400" />
                  <h2 className="text-sm font-semibold text-white">Evidence Correlation Graph</h2>
                </div>
                <div className="flex items-center gap-1.5">
                  {['All', 'Files', 'Events', 'Hosts'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setGraphFilter(tab)}
                      className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                        graphFilter === tab
                          ? 'bg-cyan-500/15 text-cyan-300'
                          : 'text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                  <button
                    onClick={() => caseId && loadDashboard(caseId)}
                    className="ml-1 rounded-md p-1.5 text-slate-500 hover:bg-slate-800 hover:text-slate-300"
                  >
                    <RefreshCw size={13} />
                  </button>
                </div>
              </div>
              <div className="min-h-0 flex-1 p-3">
                <GraphCanvas
                  nodes={
                    graphFilter === 'All'
                      ? graph.nodes
                      : graph.nodes.filter((n) => {
                          if (graphFilter === 'Files') return n.type === 'file' || n.type === 'hub';
                          if (graphFilter === 'Hosts') return n.type === 'host' || n.type === 'hub';
                          if (graphFilter === 'Events') return n.type === 'source' || n.type === 'hub';
                          return true;
                        })
                  }
                  edges={graph.edges}
                />
              </div>

              <div className="border-t border-slate-800/60 bg-[#070d1a] px-4 py-3">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Clock size={14} className="text-cyan-400" />
                    <h3 className="text-sm font-semibold text-white">Forensic Event Timeline</h3>
                  </div>
                  <span className="text-[10px] text-slate-500">Case timeline</span>
                </div>
                <div className="relative flex items-start justify-between gap-1 overflow-x-auto px-1 pb-1">
                  <div className="absolute left-6 right-6 top-[14px] h-px bg-gradient-to-r from-cyan-500/40 via-indigo-500/40 to-emerald-500/40" />
                  {timeline.map((ev, i) => (
                    <div key={i} className="relative z-10 flex min-w-[72px] flex-col items-center text-center">
                      <div
                        className={`flex h-7 w-7 items-center justify-center rounded-full text-white shadow-lg ${
                          ['bg-cyan-500', 'bg-blue-500', 'bg-violet-500', 'bg-indigo-500', 'bg-emerald-500', 'bg-sky-500'][
                            i % 6
                          ]
                        }`}
                      >
                        <Activity size={12} />
                      </div>
                      <div className="mt-2 text-[11px] font-semibold text-slate-200">{ev.time}</div>
                      <div className="mt-0.5 max-w-[88px] text-[9px] leading-tight text-slate-500">
                        {ev.label}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            {/* Right rail */}
            <aside className="flex min-h-0 flex-col border-l border-slate-800/80 bg-[#070d1a]">
              <div className="border-b border-slate-800/60 p-4">
                <div className="mb-3 flex items-center gap-2">
                  <ShieldCheck size={15} className="text-emerald-400" />
                  <h2 className="text-sm font-semibold text-white">Evidence Integrity</h2>
                </div>
                <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4 text-center">
                  <div className="mx-auto mb-2 flex h-14 w-14 items-center justify-center rounded-full border-2 border-emerald-400/60 bg-emerald-500/10">
                    <CheckCircle2 size={28} className="text-emerald-400" />
                  </div>
                  <div className="text-sm font-bold tracking-wide text-emerald-300">
                    {integrity.status || 'VERIFIED'}
                  </div>
                  <p className="mt-1 text-[11px] leading-snug text-slate-400">
                    All selected evidence files are intact and unmodified.
                  </p>
                </div>
                <dl className="mt-4 space-y-2 text-[12px]">
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Total Files</dt>
                    <dd className="font-semibold text-slate-200">{integrity.total}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Verified</dt>
                    <dd className="font-semibold text-emerald-400">{integrity.verified}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Tampered</dt>
                    <dd className="font-semibold text-slate-200">{integrity.tampered}</dd>
                  </div>
                </dl>
              </div>

              <div className="flex min-h-0 flex-1 flex-col p-4">
                <div className="mb-3 flex items-center gap-2">
                  <Link2 size={15} className="text-cyan-400" />
                  <h2 className="text-sm font-semibold text-white">Chain of Custody</h2>
                </div>
                <ol className="relative flex-1 space-y-0 overflow-y-auto border-l border-slate-700/80 pl-4">
                  {custody.map((step, i) => {
                    const Icon = custodyIcon(step.icon);
                    const isLast = i === custody.length - 1;
                    return (
                      <li key={i} className="relative pb-5 last:pb-0">
                        <span
                          className={`absolute -left-[21px] flex h-6 w-6 items-center justify-center rounded-full border ${
                            isLast
                              ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-400'
                              : 'border-slate-600 bg-slate-900 text-cyan-400'
                          }`}
                        >
                          <Icon size={11} />
                        </span>
                        <div className="text-[12px] font-semibold text-slate-200">{step.title}</div>
                        <div className="text-[10px] text-slate-500">{step.detail}</div>
                        <div className="mt-0.5 font-mono text-[9px] text-slate-600">{step.ts}</div>
                      </li>
                    );
                  })}
                </ol>
              </div>
            </aside>
          </div>
        )}
      </div>
    </div>
  );
}
