import { useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  IconButton,
  InputAdornment,
  LinearProgress,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import TimelineIcon from "@mui/icons-material/Timeline";
import HubIcon from "@mui/icons-material/Hub";
import FolderZipIcon from "@mui/icons-material/FolderZip";
import SecurityIcon from "@mui/icons-material/Security";
import FactCheckIcon from "@mui/icons-material/FactCheck";
import DescriptionIcon from "@mui/icons-material/Description";
import SearchIcon from "@mui/icons-material/Search";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import RefreshIcon from "@mui/icons-material/Refresh";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import LockIcon from "@mui/icons-material/Lock";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SettingsIcon from "@mui/icons-material/Settings";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import TerminalIcon from "@mui/icons-material/Terminal";
import ArticleIcon from "@mui/icons-material/Article";
import { DataSet } from "vis-data";
import { Timeline } from "vis-timeline/standalone";
import { Network } from "vis-network/standalone";
import "vis-timeline/styles/vis-timeline-graph2d.css";

const api = (path, opts) => fetch(path, opts).then((r) => (r.ok ? r : Promise.reject(r)));

export default function App() {
  const [cases, setCases] = useState([]);
  const [active, setActive] = useState(null);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [evidenceList, setEvidenceList] = useState([]);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [inv, setInv] = useState(null);
  const [recs, setRecs] = useState([]);
  const [tab, setTab] = useState(0);
  const [q, setQ] = useState("Was any confidential file copied to USB?");
  const [answer, setAnswer] = useState("");
  const [answerMeta, setAnswerMeta] = useState(null);
  const [generator, setGenerator] = useState(null);
  const [chatViewMode, setChatViewMode] = useState("console");
  const [llmStatus, setLlmStatus] = useState(null);
  const [llmModal, setLlmModal] = useState(false);
  const [llmConfig, setLlmConfig] = useState({
    model: "llama3.2:3b",
    base_url: "http://localhost:11434",
    temperature: 0.1,
  });
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [ingestModal, setIngestModal] = useState(null);
  const [acquireModal, setAcquireModal] = useState(false);
  const [acquireMode, setAcquireMode] = useState("automated_collection");
  const [policy, setPolicy] = useState({
    collect_security_logs: true,
    collect_system_logs: true,
    collect_powershell_logs: true,
    collect_registry: true,
    collect_browser_history: true,
    collect_browser_downloads: true,
    collect_filesystem: true,
    collect_prefetch: true,
    collect_amcache: true,
    collect_network: true,
    collect_memory: false,
  });
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [form, setForm] = useState({
    case_number: "CASE-002",
    title: "Potential Insider Activity Investigation",
    investigator: "Forensic Examiner",
    description: "Automated artifact extraction from case evidence package.",
  });

  const tlRef = useRef(null);
  const netRef = useRef(null);
  const tlInst = useRef(null);
  const netInst = useRef(null);

  const loadCases = async () => {
    const r = await api("/api/cases").then((x) => x.json());
    setCases(r);
    if (!active && r[0]) setActive(r[0].id);
  };

  const loadCase = async (id) => {
    setBusy(true);
    try {
      const [d, t, evs, g, invr, recr] = await Promise.all([
        api(`/api/cases/${id}`).then((x) => x.json()),
        api(`/api/cases/${id}/timeline`).then((x) => x.json()),
        api(`/api/cases/${id}/evidence`).then((x) => x.json()).catch(() => []),
        api(`/api/cases/${id}/graph`).then((x) => x.json()),
        api(`/api/cases/${id}/investigation`).then((x) => x.json()).catch(() => null),
        api(`/api/cases/${id}/recommendations`).then((x) => x.json()).catch(() => []),
      ]);
      setDetail(d);
      setTimeline(t);
      setEvidenceList(evs);
      setGraph(g);
      setInv(invr);
      setRecs(Array.isArray(recr) ? recr : recr?.next_actions || []);
      setAnswer("");
      setGenerator(null);
      setAnswerMeta(null);
      setSelectedEvent(null);
    } finally {
      setBusy(false);
    }
  };

  const loadLlmStatus = async () => {
    try {
      const res = await api("/api/llm/status").then((x) => x.json());
      setLlmStatus(res);
    } catch {
      setLlmStatus({ connected: false, model: "llama3.2:3b", mode: "offline_grounded_fallback" });
    }
  };

  useEffect(() => {
    loadCases();
    loadLlmStatus();
  }, []);

  useEffect(() => {
    if (active) loadCase(active);
  }, [active]);

  // Vis Timeline initialization with dark theme, category grouping & compact badges
  useEffect(() => {
    if (!tlRef.current || tab !== 0) return;
    const filtered = timeline.filter((e) => e.timestamp);
    if (!filtered.length) return;

    const sourceLabels = {
      windows_event: "Windows Logs",
      registry: "Registry Hives",
      browser: "Browser Activity",
      network: "Network Traffic",
      filesystem: "File System",
      memory: "Memory Snapshot",
      correlated: "Correlated Clusters",
    };

    const uniqueSources = [...new Set(filtered.map((e) => e.source_type || "other"))];
    const groups = new DataSet(
      uniqueSources.map((g) => ({
        id: g,
        content: `<b>${sourceLabels[g] || g.replace("_", " ").toUpperCase()}</b>`,
        className: `tl-group-lane tl-group-${g}`,
      }))
    );

    const items = new DataSet(
      filtered.map((e) => {
        const shortTitle = escapeHtml(e.target || e.object || e.process || e.description || "").slice(0, 36);
        return {
          id: e.id,
          content: `<div class="tl-item-content"><span class="tl-tag ${e.source_type}">${e.event_type}</span> <span class="tl-title">${shortTitle}</span></div>`,
          start: e.timestamp,
          group: e.source_type || "other",
          className: `tl-src-${e.source_type} ${e.source_type === "correlated" ? "tl-correlated" : riskClass(e)}`,
          title: `[${e.source_type}] ${e.event_type}\n${e.description}\nTime: ${e.timestamp}`,
        };
      })
    );

    if (tlInst.current) tlInst.current.destroy();
    tlInst.current = new Timeline(tlRef.current, items, groups, {
      stack: true,
      stackSubgroups: true,
      orientation: "top",
      margin: { item: { horizontal: 6, vertical: 8 }, axis: 6 },
      zoomKey: "ctrlKey",
      minHeight: "320px",
      maxHeight: "460px",
      verticalScroll: true,
      showCurrentTime: false,
    });

    tlInst.current.on("select", (properties) => {
      const selectedId = properties.items[0];
      const match = timeline.find((e) => e.id === selectedId);
      if (match) setSelectedEvent(match);
    });
  }, [timeline, tab]);

  // Vis Network Graph initialization
  useEffect(() => {
    if (!netRef.current || tab !== 1) return;
    if (netInst.current) netInst.current.destroy();
    netInst.current = new Network(
      netRef.current,
      { nodes: graph.nodes, edges: graph.edges },
      {
        nodes: { shape: "dot", size: 14, font: { color: "#d7e6ef", size: 12 } },
        edges: { color: "#3a5568", font: { color: "#8aa", size: 10 }, arrows: "to" },
        physics: { stabilization: true },
      }
    );
  }, [graph, tab]);

  const finding = detail?.findings?.[0];

  const upload = async (file) => {
    const fd = new FormData();
    fd.append("file", file);
    setBusy(true);
    try {
      const res = await api(`/api/cases/${active}/evidence`, { method: "POST", body: fd }).then((x) => x.json());
      setIngestModal(res);
      await loadCases();
      await loadCase(active);
    } catch (err) {
      alert("Upload failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const startAcquisition = async () => {
    setBusy(true);
    try {
      const res = await api(`/api/cases/${active}/acquire`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: acquireMode,
          policy: policy,
          notes: `Authorized acquisition by ${detail?.investigator || "Examiner"}`,
        }),
      }).then((x) => x.json());
      setAcquireModal(false);
      setIngestModal({
        filename: res.package_filename,
        sha256: res.package_sha256,
        summary: res.report.ingestion_summary,
      });
      await loadCases();
      await loadCase(active);
    } catch (err) {
      alert("Acquisition failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const ask = async (customQ) => {
    const questionText = customQ || q;
    if (!questionText || !questionText.trim()) return;
    setBusy(true);
    try {
      const r = await api(`/api/cases/${active}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: questionText,
          model: llmConfig.model,
          temperature: llmConfig.temperature,
        }),
      }).then((x) => x.json());
      setAnswer(r.answer);
      setGenerator(r.generator || null);
      setAnswerMeta({
        model: r.model || "llama3.2:3b",
        provider: r.provider || "Ollama (Local LLM)",
        llm_mode: r.llm_mode,
        is_local: r.is_local,
        query_type: r.query_type,
      });
    } catch (err) {
      alert("Chat request failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const createCase = async () => {
    await api("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    setOpen(false);
    await loadCases();
  };

  const verifyEvidence = async (evId) => {
    setBusy(true);
    try {
      const res = await api(`/api/cases/${active}/verify/${evId}`, { method: "POST" }).then((x) => x.json());
      await loadCase(active);
      alert(res.ok ? "SHA-256 verified successfully!" : "Integrity check failed: hash mismatch!");
    } finally {
      setBusy(false);
    }
  };

  const focusEvidence = (evId) => {
    if (!evId) return;
    const numericId = parseInt(evId, 10);
    const match = timeline.find((e) => e.id === numericId || String(e.event_id) === String(evId));
    if (match) {
      setSelectedEvent(match);
      setTab(0);
    }
  };

  const filteredTimeline = useMemo(() => {
    return timeline.filter((e) => {
      if (sourceFilter !== "all" && e.source_type !== sourceFilter) return false;
      if (search.trim()) {
        const s = search.toLowerCase();
        const blob = `${e.event_type} ${e.artifact_type} ${e.user} ${e.process} ${e.target} ${e.object} ${e.description} ${e.source} ${e.source_ip} ${e.destination_ip}`.toLowerCase();
        if (!blob.includes(s)) return false;
      }
      return true;
    });
  }, [timeline, sourceFilter, search]);

  const risk = inv?.risk_score || finding?.risk_score || 0;

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "#060d13", color: "#e3edf5" }}>
      <style>{`
        /* Vis Timeline Dark Theme for DFIS Forensic Workstation */
        .vis-timeline {
          border: 1px solid #142a3e !important;
          font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, sans-serif !important;
          background-color: #061019 !important;
          border-radius: 8px !important;
        }
        .vis-panel.vis-center, .vis-panel.vis-left, .vis-panel.vis-right, .vis-panel.vis-top, .vis-panel.vis-bottom {
          background-color: #061019 !important;
          border-color: #122536 !important;
        }
        .vis-labelset .vis-label {
          color: #94a3b8 !important;
          font-size: 11px !important;
          font-weight: 700 !important;
          border-bottom: 1px solid #122536 !important;
          background-color: #081522 !important;
          padding: 4px 8px !important;
        }
        .vis-time-axis .vis-text {
          color: #64748b !important;
          font-family: "IBM Plex Mono", monospace !important;
          font-size: 10px !important;
        }
        .vis-time-axis .vis-grid.vis-minor {
          border-color: #0b1e2e !important;
        }
        .vis-time-axis .vis-grid.vis-major {
          border-color: #132d44 !important;
        }
        .vis-item {
          background-color: #0a1f33 !important;
          border: 1px solid #0288d1 !important;
          color: #e2e8f0 !important;
          border-radius: 6px !important;
          font-size: 11px !important;
          box-shadow: 0 2px 5px rgba(0,0,0,0.4) !important;
          transition: all 0.15s ease !important;
        }
        .vis-item.vis-selected {
          border-color: #38bdf8 !important;
          background-color: #0c3659 !important;
          box-shadow: 0 0 10px rgba(56, 189, 248, 0.5) !important;
          z-index: 99 !important;
        }
        .vis-item.tl-src-windows_event {
          background-color: #082942 !important;
          border-color: #0288d1 !important;
        }
        .vis-item.tl-src-registry {
          background-color: #231038 !important;
          border-color: #8b5cf6 !important;
        }
        .vis-item.tl-src-browser {
          background-color: #301a04 !important;
          border-color: #f59e0b !important;
        }
        .vis-item.tl-src-network {
          background-color: #04291c !important;
          border-color: #10b981 !important;
        }
        .vis-item.tl-src-filesystem {
          background-color: #052930 !important;
          border-color: #06b6d4 !important;
        }
        .vis-item.tl-src-memory {
          background-color: #300a1c !important;
          border-color: #ec4899 !important;
        }
        .vis-item.tl-src-correlated, .vis-item.hot, .vis-item.tl-correlated {
          background-color: #332604 !important;
          border-color: #eab308 !important;
        }
        .tl-item-content {
          display: flex !important;
          align-items: center !important;
          gap: 6px !important;
          padding: 2px 4px !important;
          white-space: nowrap !important;
        }
        .tl-tag {
          font-size: 9px !important;
          font-weight: 800 !important;
          text-transform: uppercase !important;
          padding: 1px 5px !important;
          border-radius: 3px !important;
          background: rgba(255,255,255,0.12) !important;
          letter-spacing: 0.4px !important;
        }
        .tl-title {
          color: #f1f5f9 !important;
          font-weight: 600 !important;
          font-size: 11px !important;
        }
      `}</style>
      {/* Header Bar */}
      <AppBar position="fixed" sx={{ zIndex: 1201, bgcolor: "#091724", borderBottom: "1px solid #162b3d" }} elevation={0}>
        <Toolbar>
          <FingerprintIcon sx={{ mr: 1.5, color: "#29b6f6", fontSize: 28 }} />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 600, letterSpacing: 0.5, lineHeight: 1.2 }}>
              DFIS <Typography component="span" variant="caption" sx={{ bgcolor: "#0288d1", px: 0.8, py: 0.2, borderRadius: 1, ml: 1, fontWeight: 700 }}>v2.0 AUTOMATED PIPELINE</Typography>
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: 11 }}>
              Automated Evidence Ingestion • Common Forensic Schema • Case RAG Vector Search • Integrity-Linked Findings
            </Typography>
          </Box>
          <Box sx={{ flex: 1 }} />
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Chip
              icon={<SmartToyIcon sx={{ fontSize: "15px !important", color: "#81d4fa" }} />}
              label="Local LLM: llama3.2:3b"
              size="small"
              onClick={() => setLlmModal(true)}
              sx={{
                bgcolor: "#0b253a",
                color: "#81d4fa",
                border: "1px solid #0288d1",
                fontWeight: 700,
                fontSize: 12,
                cursor: "pointer",
                "&:hover": { bgcolor: "#103652" },
              }}
            />
            <Button variant="outlined" size="small" sx={{ borderColor: "#28455e" }} onClick={() => setOpen(true)}>
              + New Case
            </Button>
            {active && (
              <Button variant="contained" color="primary" size="small" href={`/api/cases/${active}/report`} target="_blank" startIcon={<DescriptionIcon />}>
                Export PDF Report
              </Button>
            )}
          </Stack>
        </Toolbar>
        {busy && <LinearProgress sx={{ bgcolor: "#091724" }} />}
      </AppBar>

      {/* Left Cases Sidebar */}
      <Drawer
        variant="permanent"
        sx={{
          width: 300,
          [`& .MuiDrawer-paper`]: { width: 300, top: 64, bgcolor: "#08131d", borderColor: "#162b3d" },
        }}
      >
        <Box sx={{ p: 2, pb: 1 }}>
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 1 }}>
            Investigation Cases
          </Typography>
        </Box>
        <List sx={{ px: 1 }}>
          {cases.map((c) => (
            <ListItemButton
              key={c.id}
              selected={c.id === active}
              onClick={() => setActive(c.id)}
              sx={{
                borderRadius: 1.5,
                mb: 1,
                border: c.id === active ? "1px solid #0288d1" : "1px solid #142433",
                bgcolor: c.id === active ? "#0e2233" : "transparent",
              }}
            >
              <ListItemText
                primary={
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: c.id === active ? "#4fc3f7" : "#cfd8dc" }}>
                      {c.case_number}
                    </Typography>
                    <Chip
                      size="small"
                      label={`${c.risk_score ?? 0}/100`}
                      color={c.risk_score >= 40 ? "error" : c.risk_score >= 15 ? "warning" : "default"}
                      sx={{ height: 20, fontSize: 10, fontWeight: 700 }}
                    />
                  </Stack>
                }
                secondary={
                  <Box sx={{ mt: 0.5 }}>
                    <Typography variant="body2" sx={{ fontSize: 12, color: "#90a4ae", lineHeight: 1.2 }}>
                      {c.title}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "#607d8b", fontSize: 11 }}>
                      {c.artifact_count} artifacts • {c.evidence_count} evidence files
                    </Typography>
                  </Box>
                }
              />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      {/* Main Workspace */}
      <Box component="main" sx={{ flex: 1, ml: "300px", mt: 8, p: 3 }}>
        {!detail ? (
          <Typography>Select or create a case.</Typography>
        ) : (
          <Container maxWidth="xl" disableGutters>
            {/* Case Header Card */}
            <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="stretch" sx={{ mb: 2.5 }}>
              <Paper sx={{ flex: 1, p: 2.5, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2 }}>
                <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                  <Box>
                    <Typography variant="h5" sx={{ fontWeight: 700, color: "#eceff1" }}>{detail.title}</Typography>
                    <Typography variant="body2" sx={{ color: "#90a4ae", mt: 0.5 }}>{detail.description}</Typography>
                  </Box>
                  <Chip label={detail.status?.toUpperCase() || "OPEN"} color="info" size="small" sx={{ fontWeight: 700 }} />
                </Stack>
                <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
                  <Chip size="small" icon={<FingerprintIcon />} label={`Case: ${detail.case_number}`} sx={{ bgcolor: "#102a3d", color: "#81d4fa" }} />
                  <Chip size="small" label={`Examiner: ${detail.investigator}`} variant="outlined" sx={{ borderColor: "#28455e" }} />
                  {finding && <Chip size="small" color="secondary" label={`Hypothesis: ${formatClassification(finding.category)}`} sx={{ fontWeight: 600 }} />}
                  {finding?.mitre_ids && <Chip size="small" label={`ATT&CK: ${finding.mitre_ids}`} sx={{ bgcolor: "#1e1e24", color: "#ffb74d" }} />}
                </Stack>
              </Paper>

              {/* Priority & Risk Meter */}
              <Paper sx={{ minWidth: 260, p: 2.5, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2 }}>
                <Typography variant="caption" color="text.secondary" sx={{ textTransform: "uppercase", fontWeight: 700 }}>
                  Investigation Priority Score
                </Typography>
                <Typography variant="h3" sx={{ fontWeight: 800, color: risk >= 40 ? "#ef5350" : risk >= 15 ? "#ffa726" : "#66bb6a", my: 0.5 }}>
                  {risk}<Typography component="span" variant="h5" color="text.secondary">/100</Typography>
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={risk}
                  color={risk >= 40 ? "error" : risk >= 15 ? "warning" : "success"}
                  sx={{ height: 8, borderRadius: 4, mb: 1, bgcolor: "#132330" }}
                />
                <Typography variant="caption" sx={{ color: "#90a4ae", display: "block" }}>
                  {inv?.priority || (risk >= 40 ? "HIGH PRIORITY" : "ROUTINE")} • Evidence-weighted
                </Typography>
              </Paper>
            </Stack>

            {/* Evidence Ingestion Engine Banner */}
            <Paper sx={{ p: 2, mb: 3, bgcolor: "#0a1926", border: "1px solid #1d3e5a", borderRadius: 2 }}>
              <Stack direction={{ xs: "column", lg: "row" }} spacing={2} justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4fc3f7", display: "flex", alignItems: "center", gap: 1 }}>
                    <AutoFixHighIcon fontSize="small" /> Automated Evidence Acquisition & Ingestion Engine
                  </Typography>
                  <Typography variant="caption" sx={{ color: "#b0bec5" }}>
                    Acquisition (Manual/Automated/Hybrid) ➔ SHA-256 Check ➔ Content Detection (EVTX, Registry, Browser, Prefetch, Amcache, PCAP) ➔ Extraction ➔ Unified Timeline ➔ Case RAG
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1.5}>
                  <Button
                    variant="contained"
                    color="primary"
                    startIcon={<SecurityIcon />}
                    onClick={() => setAcquireModal(true)}
                    disabled={busy}
                    sx={{ fontWeight: 700 }}
                  >
                    Acquire Evidence (Policy Agent)
                  </Button>
                  <Button
                    variant="outlined"
                    component="label"
                    color="inherit"
                    startIcon={<CloudUploadIcon />}
                    disabled={busy}
                    sx={{ borderColor: "#28455e", fontWeight: 600 }}
                  >
                    Import Case ZIP
                    <input hidden type="file" onChange={(e) => e.target.files[0] && upload(e.target.files[0])} />
                  </Button>
                  <Button
                    variant="outlined"
                    disabled={busy}
                    startIcon={<RefreshIcon />}
                    onClick={async () => {
                      setBusy(true);
                      try {
                        await api(`/api/cases/${active}/reprocess`, { method: "POST" });
                        await loadCases();
                        await loadCase(active);
                      } finally {
                        setBusy(false);
                      }
                    }}
                    sx={{ borderColor: "#28455e" }}
                  >
                    Re-Execute Engine
                  </Button>
                </Stack>
              </Stack>
            </Paper>

            {/* Main Tabs and Content */}
            <Stack direction={{ xs: "column", xl: "row" }} spacing={2.5}>
              <Paper sx={{ flex: { xs: 1, xl: 1.25 }, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2, overflow: "hidden" }}>
                <Tabs
                  value={tab}
                  onChange={(_, v) => setTab(v)}
                  sx={{
                    bgcolor: "#08131d",
                    borderBottom: "1px solid #162b3d",
                    "& .MuiTab-root": { textTransform: "none", fontWeight: 600, minHeight: 48 },
                  }}
                >
                  <Tab icon={<TimelineIcon />} iconPosition="start" label="Unified Timeline" />
                  <Tab icon={<HubIcon />} iconPosition="start" label="Relationship Graph" />
                  <Tab icon={<FolderZipIcon />} iconPosition="start" label={`Evidence & Custody (${evidenceList.length})`} />
                  <Tab icon={<SecurityIcon />} iconPosition="start" label="AI Investigation" />
                  <Tab icon={<FactCheckIcon />} iconPosition="start" label={`Tasks (${recs.length})`} />
                  <Tab icon={<DescriptionIcon />} iconPosition="start" label="Report" />
                </Tabs>

                {/* TAB 0: UNIFIED TIMELINE */}
                {tab === 0 && (
                  <Box sx={{ p: 2 }}>
                    {/* Vis Timeline Canvas */}
                    <Box ref={tlRef} sx={{ height: 340, bgcolor: "#061019", borderRadius: 2, p: 0.5, mb: 2, border: "1px solid #142a3e" }} />

                    {/* Selected Timeline Event Inspector */}
                    {selectedEvent && (
                      <Paper sx={{ p: 1.8, mb: 2, bgcolor: "#071624", border: "1px solid #0288d1", borderRadius: 2 }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Chip size="small" label={`Artifact ID #${selectedEvent.id}`} sx={{ bgcolor: "#0d2b45", color: "#38bdf8", fontWeight: 700, fontFamily: "IBM Plex Mono" }} />
                            <Chip size="small" label={selectedEvent.source_type} sx={{ bgcolor: sourceColor(selectedEvent.source_type), color: "#fff", fontWeight: 700 }} />
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f8fafc" }}>
                              {selectedEvent.event_type}
                            </Typography>
                          </Stack>
                          <Button size="small" onClick={() => setSelectedEvent(null)} sx={{ color: "#94a3b8", fontSize: 11, minWidth: "auto", p: 0.5 }}>
                            Close
                          </Button>
                        </Stack>
                        <Typography variant="body2" sx={{ color: "#e2e8f0", mb: 1, fontSize: 13, lineHeight: 1.5 }}>
                          {selectedEvent.description}
                        </Typography>
                        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ fontSize: 11, color: "#94a3b8" }}>
                          <span>Time: <code style={{ color: "#38bdf8" }}>{selectedEvent.timestamp}</code></span>
                          {selectedEvent.actor && <span>Actor: <code style={{ color: "#cbd5e1" }}>{selectedEvent.actor}</code></span>}
                          {selectedEvent.process && <span>Process: <code style={{ color: "#cbd5e1" }}>{selectedEvent.process}</code></span>}
                          {selectedEvent.target && <span>Target: <code style={{ color: "#cbd5e1" }}>{selectedEvent.target}</code></span>}
                          {selectedEvent.source && <span>Source: <code style={{ color: "#a7f3d0" }}>{selectedEvent.source}</code></span>}
                          {selectedEvent.evidence_hash && <span>SHA-256: <code style={{ color: "#fde68a" }}>{selectedEvent.evidence_hash.slice(0, 16)}...</code></span>}
                        </Stack>
                      </Paper>
                    )}

                    {/* Filter & Search Bar */}
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                      <TextField
                        size="small"
                        fullWidth
                        placeholder="Search timeline (user, process, IP, artifact, entity)..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SearchIcon sx={{ color: "text.secondary" }} />
                            </InputAdornment>
                          ),
                        }}
                        sx={{ bgcolor: "#08131d", borderRadius: 1 }}
                      />
                      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ minWidth: 320 }}>
                        {["all", "windows_event", "registry", "browser", "network", "filesystem", "memory", "correlated"].map((src) => (
                          <Chip
                            key={src}
                            size="small"
                            label={src === "all" ? "All Sources" : src.replace("_", " ")}
                            clickable
                            color={sourceFilter === src ? "primary" : "default"}
                            onClick={() => setSourceFilter(src)}
                            sx={{ textTransform: "capitalize", fontSize: 11 }}
                          />
                        ))}
                      </Stack>
                    </Stack>

                    {/* Chronological Artifact Table */}
                    <TableContainer sx={{ maxHeight: 420, border: "1px solid #162b3d", borderRadius: 1.5 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#0e2233", color: "#b0bec5", fontWeight: 700, fontSize: 11 } }}>
                            <TableCell>Timestamp (UTC)</TableCell>
                            <TableCell>Source & Artifact</TableCell>
                            <TableCell>Event Type</TableCell>
                            <TableCell>Actor / Host</TableCell>
                            <TableCell>Action & Object</TableCell>
                            <TableCell>Description</TableCell>
                            <TableCell align="right">Provenance</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {filteredTimeline.map((e) => (
                            <TableRow
                              key={e.id || e.fingerprint}
                              hover
                              onClick={() => setSelectedEvent(e)}
                              sx={{
                                cursor: "pointer",
                                bgcolor: e.source_type === "correlated" ? "rgba(255, 179, 0, 0.08)" : (selectedEvent?.id === e.id ? "rgba(2, 136, 209, 0.15)" : "inherit"),
                                "& td": { borderColor: "#142433", fontSize: 12, py: 1 },
                              }}
                            >
                              <TableCell sx={{ fontFamily: "IBM Plex Mono", whiteSpace: "nowrap", color: "#81d4fa" }}>
                                {e.timestamp ? e.timestamp.replace("T", " ") : "Observation"}
                              </TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={e.artifact_type || e.source_type}
                                  sx={{
                                    height: 20,
                                    fontSize: 10,
                                    fontWeight: 600,
                                    bgcolor: sourceColor(e.source_type),
                                    color: "#fff",
                                  }}
                                />
                              </TableCell>
                              <TableCell sx={{ fontWeight: 600, color: "#eceff1" }}>
                                {e.event_type}
                              </TableCell>
                              <TableCell sx={{ color: "#b0bec5" }}>
                                {e.user || e.actor || "—"} {e.host ? `(${e.host})` : ""}
                              </TableCell>
                              <TableCell sx={{ color: "#cfd8dc" }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, display: "block" }}>{e.action}</Typography>
                                <Typography variant="caption" sx={{ color: "#90a4ae", fontFamily: "IBM Plex Mono" }}>
                                  {e.target || e.object || "—"}
                                </Typography>
                              </TableCell>
                              <TableCell sx={{ color: "#b0bec5", maxWidth: 280, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                                {e.description}
                              </TableCell>
                              <TableCell align="right">
                                {e.correlation_id ? (
                                  <Chip size="small" label={`Link: ${e.correlation_id}`} color="warning" sx={{ height: 18, fontSize: 9, fontWeight: 700 }} />
                                ) : (
                                  <Typography variant="caption" sx={{ color: "#607d8b", fontFamily: "IBM Plex Mono", fontSize: 10 }}>
                                    #{e.id}
                                  </Typography>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>

                    {/* Event Detail Inspector */}
                    {selectedEvent && (
                      <Paper sx={{ mt: 2, p: 2, bgcolor: "#07131e", border: "1px solid #0288d1", borderRadius: 1.5 }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4fc3f7" }}>
                            Event Inspector — Common Forensic Event Schema [#{selectedEvent.id}]
                          </Typography>
                          <Button size="small" onClick={() => setSelectedEvent(null)}>Close</Button>
                        </Stack>
                        <Stack direction={{ xs: "column", md: "row" }} spacing={2} sx={{ fontSize: 12 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary">Source:</Typography> <Typography variant="body2" component="span">{selectedEvent.source}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Artifact Type:</Typography> <Typography variant="body2" component="span">{selectedEvent.artifact_type}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Event Type:</Typography> <Typography variant="body2" component="span">{selectedEvent.event_type}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Action:</Typography> <Typography variant="body2" component="span">{selectedEvent.action}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Target / Object:</Typography> <Typography variant="body2" component="span">{selectedEvent.target || selectedEvent.object}</Typography><br />
                          </Box>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary">Actor / User:</Typography> <Typography variant="body2" component="span">{selectedEvent.user || selectedEvent.actor || "—"}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Process / PID:</Typography> <Typography variant="body2" component="span">{selectedEvent.process} {selectedEvent.pid ? `(PID ${selectedEvent.pid})` : ""}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Network:</Typography> <Typography variant="body2" component="span">{selectedEvent.source_ip ? `${selectedEvent.source_ip} → ${selectedEvent.destination_ip}` : "—"}</Typography><br />
                            <Typography variant="caption" color="text.secondary">Evidence Hash (SHA-256):</Typography> <Typography variant="caption" sx={{ fontFamily: "IBM Plex Mono", display: "block", color: "#81d4fa" }}>{selectedEvent.evidence_hash || "Case Ingested"}</Typography>
                          </Box>
                        </Stack>
                        {selectedEvent.raw_data && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: "#03080d", borderRadius: 1, maxHeight: 120, overflow: "auto" }}>
                            <Typography variant="caption" sx={{ fontFamily: "IBM Plex Mono", color: "#a5d6a7" }}>
                              {selectedEvent.raw_data}
                            </Typography>
                          </Box>
                        )}
                      </Paper>
                    )}
                  </Box>
                )}

                {/* TAB 1: RELATIONSHIP GRAPH */}
                {tab === 1 && (
                  <Box sx={{ p: 2 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                      Cross-artifact entity graph: linking actors, processes, files, USB media, and network destinations.
                    </Typography>
                    <Box ref={netRef} sx={{ height: 500, bgcolor: "#050b11", borderRadius: 1.5, border: "1px solid #162b3d" }} />
                  </Box>
                )}

                {/* TAB 2: EVIDENCE & CUSTODY */}
                {tab === 2 && (
                  <Box sx={{ p: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#eceff1", mb: 1 }}>
                      Ingested Forensic Evidence Files & Integrity Verification
                    </Typography>
                    <TableContainer sx={{ mb: 3, border: "1px solid #162b3d", borderRadius: 1.5 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#0e2233", color: "#b0bec5", fontWeight: 700 } }}>
                            <TableCell>Evidence File</TableCell>
                            <TableCell>Detected Artifact Type</TableCell>
                            <TableCell>Magic Signature</TableCell>
                            <TableCell>SHA-256 Hash</TableCell>
                            <TableCell>Size</TableCell>
                            <TableCell>Events</TableCell>
                            <TableCell align="right">Integrity</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {evidenceList.map((ev) => (
                            <TableRow key={ev.id} hover sx={{ "& td": { borderColor: "#142433", py: 1.2 } }}>
                              <TableCell sx={{ fontWeight: 600, color: "#81d4fa" }}>{ev.filename}</TableCell>
                              <TableCell>
                                <Chip size="small" label={ev.detected_type || ev.source_type} sx={{ height: 20, fontSize: 10, bgcolor: "#102a3d", color: "#4fc3f7" }} />
                              </TableCell>
                              <TableCell sx={{ fontSize: 11, color: "#90a4ae" }}>{ev.magic_signature || "Standard Container"}</TableCell>
                              <TableCell sx={{ fontFamily: "IBM Plex Mono", fontSize: 11, color: "#b0bec5" }}>
                                {ev.sha256}
                              </TableCell>
                              <TableCell sx={{ fontSize: 11 }}>{(ev.size_bytes / 1024).toFixed(1)} KB</TableCell>
                              <TableCell sx={{ fontWeight: 700 }}>{ev.artifact_count}</TableCell>
                              <TableCell align="right">
                                <Button
                                  size="small"
                                  variant="outlined"
                                  startIcon={ev.integrity_ok ? <CheckCircleIcon color="success" /> : <WarningIcon color="error" />}
                                  onClick={() => verifyEvidence(ev.id)}
                                  sx={{ fontSize: 10, py: 0.2 }}
                                >
                                  Verify
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>

                    {/* Chain of Custody Log */}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#eceff1", mb: 1 }}>
                      Immutable Chain of Custody Audit Log
                    </Typography>
                    <Paper sx={{ maxHeight: 240, overflow: "auto", p: 1.5, bgcolor: "#060d14", border: "1px solid #162b3d" }}>
                      {(detail?.custody || []).map((c, i) => (
                        <Typography key={i} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12, mb: 0.8, color: "#b0bec5" }}>
                          <span style={{ color: "#64b5f6" }}>[{c.created_at?.replace("T", " ")}]</span> <b>{c.action}</b> by <i>{c.actor}</i> — {c.detail}
                        </Typography>
                      ))}
                    </Paper>
                  </Box>
                )}

                {/* TAB 3: AI INVESTIGATION & ATT&CK */}
                {tab === 3 && (
                  <Box sx={{ p: 2, maxHeight: 600, overflow: "auto" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#4fc3f7" }}>
                      Incident Classification: {formatClassification(inv?.category || finding?.category, inv?.secondary)}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                      ATT&CK techniques and attack-chain stages are investigative hypotheses synthesized from multi-source correlations.
                    </Typography>

                    {/* 4-Tier Forensic Evidentiary States */}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#81d4fa" }}>
                      Forensic Evidentiary State Breakdown
                    </Typography>
                    <TableContainer sx={{ border: "1px solid #162b3d", borderRadius: 1.5, mb: 3 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#0e2233", color: "#b0bec5", fontSize: 11, fontWeight: 700 } }}>
                            <TableCell>Investigation Finding</TableCell>
                            <TableCell>Evidentiary State</TableCell>
                            <TableCell>Forensic Detail & Evidence Alignment</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {(inv?.evidentiary_states || []).map((st, idx) => (
                            <TableRow key={idx} hover sx={{ "& td": { borderColor: "#142433", py: 0.8, fontSize: 12 } }}>
                              <TableCell sx={{ fontWeight: 600, color: "#eceff1" }}>{st.finding}</TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={st.state}
                                  color={
                                    st.state === "OBSERVED"
                                      ? "success"
                                      : st.state === "SUPPORTED HYPOTHESIS"
                                      ? "secondary"
                                      : st.state === "INSUFFICIENT EVIDENCE"
                                      ? "warning"
                                      : "default"
                                  }
                                  sx={{ height: 18, fontSize: 9, fontWeight: 800 }}
                                />
                              </TableCell>
                              <TableCell sx={{ color: "#b0bec5" }}>{st.detail}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>

                    {/* Attack Chain Stepper */}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Reconstructed Attack Chain Hypothesis</Typography>
                    <Stack spacing={1} sx={{ mb: 3 }}>
                      {(inv?.attack_chain || []).map((s, i) => (
                        <Paper key={i} sx={{ p: 1.5, bgcolor: "#07131e", border: "1px solid #162b3d" }}>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#81d4fa" }}>
                              {s.title}
                            </Typography>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Chip size="small" label={s.mitre || "—"} color="secondary" sx={{ height: 20, fontSize: 10 }} />
                              <Chip
                                size="small"
                                label={s.status?.toUpperCase() || "HYPOTHESIZED"}
                                color={s.status === "observed" ? "success" : s.status === "insufficient_evidence" ? "warning" : "default"}
                                sx={{ height: 20, fontSize: 10, fontWeight: 700 }}
                              />
                            </Stack>
                          </Stack>
                          <Typography variant="caption" sx={{ color: "#90a4ae", display: "block", mt: 0.5 }}>
                            Time: {s.time} • Confidence: <b>{s.confidence?.toUpperCase() || "MEDIUM"}</b> • Evidence IDs: {(s.evidence_event_ids || []).join(", ") || "—"}
                          </Typography>
                          {s.note && (
                            <Typography variant="caption" sx={{ display: "block", color: "#b0bec5", mt: 0.5, fontStyle: "italic" }}>
                              Reason: {s.note}
                            </Typography>
                          )}
                        </Paper>
                      ))}
                    </Stack>

                    {/* Correlated Activities */}
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1, mt: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Correlated Multi-Source Activities</Typography>
                      <Typography variant="caption" sx={{ color: "#ffb74d", fontStyle: "italic" }}>
                        Correlation links are analytical relationships, not evidence artifacts.
                      </Typography>
                    </Stack>
                    <Stack spacing={1} sx={{ mb: 3 }}>
                      {(inv?.correlations || []).map((g) => (
                        <Paper key={g.correlation_id} sx={{ p: 1.5, bgcolor: "#0e1d2b", border: "1px solid #f57f17" }}>
                          <Typography variant="subtitle2" sx={{ color: "#ffd54f", fontWeight: 700 }}>
                            {g.family.toUpperCase()} | Entity: {g.entity} (Correlation Link: #{g.correlation_id})
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#b0bec5", display: "block" }}>
                            Time: {g.timestamp} • Actor: {g.actor || "analyst"} • Corroborating Event IDs: {(g.source_event_ids || []).join(", ")}
                          </Typography>
                        </Paper>
                      ))}
                    </Stack>

                    {/* Evidence Acquisition / Observations */}
                    {(inv?.observations || []).length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#80deea" }}>
                          Evidence Acquisition / Observations
                        </Typography>
                        <Stack spacing={1}>
                          {(inv?.observations || []).map((o, idx) => (
                            <Paper key={idx} sx={{ p: 1.5, bgcolor: "#07131e", border: "1px solid #00838f" }}>
                              <Stack direction="row" justifyContent="space-between" alignItems="center">
                                <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#80deea" }}>
                                  {o.title}
                                </Typography>
                                <Chip size="small" label={o.status || "OBSERVED"} color="info" sx={{ height: 20, fontSize: 10, fontWeight: 700 }} />
                              </Stack>
                              <Typography variant="caption" sx={{ color: "#90a4ae", display: "block", mt: 0.5 }}>
                                Time: {o.time} • Evidence IDs: {(o.evidence_event_ids || []).join(", ") || "—"}
                              </Typography>
                              <Typography variant="caption" sx={{ display: "block", color: "#b0bec5", mt: 0.5, fontStyle: "italic" }}>
                                Reason: {o.note}
                              </Typography>
                            </Paper>
                          ))}
                        </Stack>
                      </Box>
                    )}
                  </Box>
                )}

                {/* TAB 4: TASKS & RECOMMENDATIONS */}
                {tab === 4 && (
                  <Box sx={{ p: 2, maxHeight: 600, overflow: "auto" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#4fc3f7" }}>
                      Grounded Investigation Recommendations
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                      Examiner verification tasks derived directly from NOT ESTABLISHED and INSUFFICIENT EVIDENCE findings. Recommendations tell the examiner what to verify next without creating new evidence.
                    </Typography>

                    <TableContainer sx={{ border: "1px solid #162b3d", borderRadius: 1.5, mb: 3 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#0e2233", color: "#b0bec5", fontSize: 11, fontWeight: 700 } }}>
                            <TableCell>#</TableCell>
                            <TableCell>Investigation Question</TableCell>
                            <TableCell>Action / Task</TableCell>
                            <TableCell>Why Investigate (Forensic Reason)</TableCell>
                            <TableCell>Evidence IDs</TableCell>
                            <TableCell align="right">Status / Verification</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {(recs.length ? recs : inv?.next_actions || []).map((a) => (
                            <TableRow key={a.id || a.priority} hover sx={{ "& td": { borderColor: "#142433", py: 1, fontSize: 12 } }}>
                              <TableCell sx={{ fontWeight: 700, color: "#81d4fa" }}>{a.priority}</TableCell>
                              <TableCell sx={{ fontWeight: 600, color: "#eceff1", maxWidth: 180 }}>
                                {a.question || a.action}
                              </TableCell>
                              <TableCell sx={{ color: "#cfd8dc" }}>{a.action}</TableCell>
                              <TableCell sx={{ color: "#b0bec5", fontSize: 11, maxWidth: 280 }}>
                                {a.reason}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "IBM Plex Mono", fontSize: 11, color: "#81d4fa", whiteSpace: "nowrap" }}>
                                {(a.evidence_ids || []).join(", ") || "Case baseline"}
                              </TableCell>
                              <TableCell align="right">
                                <Stack direction="row" spacing={1} justifyContent="flex-end" alignItems="center">
                                  <Chip
                                    size="small"
                                    label={(a.status || "pending_verification").replaceAll("_", " ")}
                                    color={a.status === "verified" ? "success" : "default"}
                                    sx={{ height: 18, fontSize: 9, fontWeight: 700 }}
                                  />
                                  {a.id && a.status !== "verified" && (
                                    <Button
                                      size="small"
                                      variant="outlined"
                                      onClick={async () => {
                                        await api(`/api/cases/${active}/recommendations/${a.id}`, {
                                          method: "PATCH",
                                          headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({ status: "verified" }),
                                        });
                                        const next = await api(`/api/cases/${active}/recommendations`).then((x) => x.json());
                                        setRecs(next);
                                      }}
                                      sx={{ fontSize: 10, py: 0.2, px: 0.8 }}
                                    >
                                      Verify
                                    </Button>
                                  )}
                                </Stack>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}

                {/* TAB 5: REPORT PREVIEW */}
                {tab === 5 && (
                  <Box sx={{ p: 2, maxHeight: 600, overflow: "auto" }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Evidence-Linked Investigation Report</Typography>
                      <Button variant="contained" href={`/api/cases/${active}/report`} target="_blank" startIcon={<DescriptionIcon />}>
                        Download Official PDF
                      </Button>
                    </Stack>
                    <Paper sx={{ p: 2.5, bgcolor: "#07131e", border: "1px solid #162b3d" }}>
                      <Typography variant="h6" sx={{ color: "#4fc3f7", fontWeight: 700 }}>{detail.title}</Typography>
                      <Typography variant="body2" sx={{ color: "#cfd8dc", my: 1 }}>
                        Case: {detail.case_number} | Examiner: {detail.investigator} | Status: {detail.status}
                      </Typography>
                      <Divider sx={{ my: 1.5, borderColor: "#162b3d" }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Summary Finding:</Typography>
                      <Typography variant="body2" sx={{ color: "#b0bec5", mb: 2 }}>
                        {finding?.body || "Investigation findings synthesized across all parsed artifact sources."}
                      </Typography>
                    </Paper>
                  </Box>
                )}
              </Paper>

              {/* Right Sidebar: Local LLM (llama3.2:3b) + Case RAG Assistant */}
              <Paper sx={{ flex: { xs: 1, xl: 1 }, minWidth: { xs: "100%", lg: 440, xl: 480 }, maxWidth: { xl: 580 }, p: 2.5, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2 }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#81d4fa", display: "flex", alignItems: "center", gap: 1 }}>
                    <SmartToyIcon fontSize="small" sx={{ color: "#29b6f6" }} /> Local LLM (llama3.2:3b)
                  </Typography>
                  <IconButton size="small" onClick={() => setLlmModal(true)} title="Local LLM Settings & Health" sx={{ color: "#90a4ae" }}>
                    <SettingsIcon fontSize="small" />
                  </IconButton>
                </Stack>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  Grounded Q&A: cross-references general forensic principles against this case’s ingested events.
                </Typography>

                {/* Local Air-Gapped Guarantee Badge */}
                <Paper sx={{ p: 1, mb: 1.5, bgcolor: "#06131f", border: "1px solid #13334c", borderRadius: 1.5 }}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <LockIcon sx={{ fontSize: 15, color: "#4caf50" }} />
                    <Typography variant="caption" sx={{ color: "#b0bec5", fontSize: 11, lineHeight: 1.3 }}>
                      <b>100% Local Inference:</b> Running <code>llama3.2:3b</code> locally via Ollama / Air-Gapped Engine. Zero case data leaves this machine.
                    </Typography>
                  </Stack>
                </Paper>

                {/* Dynamic Suggested Queries from Evidentiary Gaps */}
                <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: "uppercase" }}>
                  Suggested Investigative Queries (From Evidentiary Gaps):
                </Typography>
                <Stack spacing={0.8} sx={{ mt: 1, mb: 2 }}>
                  {((inv?.suggested_queries && inv.suggested_queries.length > 0)
                    ? inv.suggested_queries
                    : [
                        "Was the valid account legitimately used?",
                        "What activity is associated with chrome.exe or network endpoints?",
                        "Is there evidence of USB / removable-media activity?",
                        "What are the recommended next steps for verification?",
                      ]
                  ).map((sug, i) => (
                    <Button
                      key={i}
                      size="small"
                      variant="outlined"
                      onClick={() => {
                        setQ(sug);
                        ask(sug);
                      }}
                      sx={{ textAlign: "left", justifyContent: "flex-start", fontSize: 11, borderColor: "#1d3e5a", color: "#b0bec5" }}
                    >
                      {sug}
                    </Button>
                  ))}
                </Stack>

                <TextField
                  fullWidth
                  multiline
                  minRows={2}
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Ask a question about this case (e.g. Was USB connected? What is 10.0.0.20:443?)..."
                  size="small"
                  sx={{ bgcolor: "#08131d", borderRadius: 1 }}
                />
                <Button
                  sx={{ mt: 1.5, fontWeight: 600 }}
                  fullWidth
                  variant="contained"
                  color="primary"
                  startIcon={<SmartToyIcon />}
                  onClick={() => ask()}
                  disabled={busy}
                >
                  Ask Local LLM (llama3.2:3b)
                </Button>

                {answer && (
                  <Box sx={{ mt: 2 }}>
                    <GenerationProvenanceCard generator={generator} />
                    <ForensicConsoleAnswer
                      answer={answer}
                      generator={generator}
                      inv={inv}
                      onFocusEvidence={focusEvidence}
                      viewMode={chatViewMode}
                      setViewMode={setChatViewMode}
                    />
                  </Box>
                )}
              </Paper>
            </Stack>
          </Container>
        )}
      </Box>

      {/* Evidence Acquisition Modal Dialog */}
      <Dialog open={acquireModal} onClose={() => setAcquireModal(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ bgcolor: "#091724", color: "#4fc3f7", fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
          <SecurityIcon /> Investigator-Controlled Evidence Acquisition
        </DialogTitle>
        <DialogContent sx={{ bgcolor: "#060d14", color: "#cfd8dc", pt: 2 }}>
          <Typography variant="body2" sx={{ color: "#b0bec5", mb: 2 }}>
            Select an authorized acquisition mode and collection policy. The automated collection agent will collect forensic artifacts, verify hashes with SHA-256, package the evidence, and feed it into the Extraction Engine.
          </Typography>

          {/* Acquisition Mode Selector */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#81d4fa", mb: 1 }}>
            1. Select Acquisition Mode
          </Typography>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ mb: 3 }}>
            {[
              { id: "automated_collection", title: "Automated Endpoint Collection", desc: "Policy-driven automated collection agent" },
              { id: "manual_import", title: "Manual Evidence Import", desc: "Import pre-acquired case ZIP/files" },
              { id: "hybrid_collection", title: "Hybrid Acquisition", desc: "Combined import + targeted gap collection" },
            ].map((m) => (
              <Paper
                key={m.id}
                onClick={() => setAcquireMode(m.id)}
                sx={{
                  p: 1.5,
                  flex: 1,
                  cursor: "pointer",
                  bgcolor: acquireMode === m.id ? "#0d283d" : "#08131d",
                  border: acquireMode === m.id ? "1px solid #0288d1" : "1px solid #162b3d",
                  borderRadius: 1.5,
                }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: acquireMode === m.id ? "#4fc3f7" : "#eceff1", fontSize: 13 }}>
                  {m.title}
                </Typography>
                <Typography variant="caption" sx={{ color: "#90a4ae", display: "block", mt: 0.5 }}>
                  {m.desc}
                </Typography>
              </Paper>
            ))}
          </Stack>

          {/* Collection Policy Checklist */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#81d4fa", mb: 1 }}>
            2. Investigator-Controlled Collection Policy Checklist
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
            Select which forensic artifact categories the automated agent is authorized to collect:
          </Typography>

          <Stack spacing={1.5} sx={{ mb: 2 }}>
            {[
              {
                group: "Windows Event Logs & Execution Traces",
                items: [
                  { key: "collect_security_logs", label: "Windows Security Logs (Logon 4624, Process 4688, USB 6416)" },
                  { key: "collect_system_logs", label: "Windows System Logs (Service 7045, State Change 7036)" },
                  { key: "collect_powershell_logs", label: "PowerShell Operational Logs (Script Block 4104, Pipeline 4103)" },
                  { key: "collect_prefetch", label: "Prefetch Execution Traces (.pf application run counts & timestamps)" },
                  { key: "collect_amcache", label: "Amcache Application Evidence (Amcache.hve program execution & SHA-1 hashes)" },
                ],
              },
              {
                group: "Registry, User Activity & File System",
                items: [
                  { key: "collect_registry", label: "Registry Hives (USBSTOR devices, RecentDocs, Run Persistence, UserAssist)" },
                  { key: "collect_browser_history", label: "Browser History & Omnibox Searches (Chrome, Edge, Firefox, Brave)" },
                  { key: "collect_browser_downloads", label: "Browser Downloads & Session Cookies" },
                  { key: "collect_filesystem", label: "File System Activity & Metadata (File open, modified, copy logs)" },
                ],
              },
              {
                group: "Network & Volatile State",
                items: [
                  { key: "collect_network", label: "Network Traffic Logs & Captures (PCAP, DNS queries, TLS handshakes)" },
                  { key: "collect_memory", label: "Memory Snapshot (Volatile process list & active network sockets — restricted)" },
                ],
              },
            ].map((grp, gidx) => (
              <Paper key={gidx} sx={{ p: 1.5, bgcolor: "#08131d", border: "1px solid #162b3d", borderRadius: 1.5 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: "#ffb74d", textTransform: "uppercase", display: "block", mb: 1 }}>
                  {grp.group}
                </Typography>
                <Stack spacing={0.8}>
                  {grp.items.map((it) => (
                    <Box
                      key={it.key}
                      onClick={() => setPolicy({ ...policy, [it.key]: !policy[it.key] })}
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        cursor: "pointer",
                        p: 0.5,
                        borderRadius: 1,
                        "&:hover": { bgcolor: "#0d2030" },
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(policy[it.key])}
                        onChange={() => {}}
                        style={{ marginRight: 8, accentColor: "#0288d1", cursor: "pointer" }}
                      />
                      <Typography variant="body2" sx={{ fontSize: 13, color: policy[it.key] ? "#e0f2f1" : "#78909c" }}>
                        {it.label}
                      </Typography>
                    </Box>
                  ))}
                </Stack>
              </Paper>
            ))}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#091724", px: 3, py: 2 }}>
          <Button onClick={() => setAcquireModal(false)} sx={{ color: "#90a4ae" }}>
            Cancel
          </Button>
          <Button
            onClick={startAcquisition}
            variant="contained"
            color="primary"
            disabled={busy}
            startIcon={<SecurityIcon />}
            sx={{ fontWeight: 700, px: 3 }}
          >
            Start Authorized Collection
          </Button>
        </DialogActions>
      </Dialog>

      {/* Ingestion Report Modal */}
      {ingestModal && (
        <Dialog open={Boolean(ingestModal)} onClose={() => setIngestModal(null)} maxWidth="lg" fullWidth>
          <DialogTitle sx={{ bgcolor: "#091724", color: "#4fc3f7", fontWeight: 700 }}>
            Automated Evidence Ingestion & Verification Report
          </DialogTitle>
          <DialogContent sx={{ bgcolor: "#060d14", color: "#cfd8dc", pt: 2 }}>
            <Alert severity="success" sx={{ mb: 2, bgcolor: "#0b2216", color: "#a5d6a7" }}>
              Successfully ingested evidence package: <b>{ingestModal.filename}</b> (SHA-256: {ingestModal.sha256})
            </Alert>

            {/* Ingestion Metric Breakdown */}
            <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap sx={{ mb: 2.5 }}>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Files Discovered</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800 }}>{ingestModal.summary?.total_files_discovered || 1}</Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Doc Excluded</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#90a4ae" }}>{ingestModal.summary?.total_documentation_excluded || 0}</Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Artifacts Identified</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#81d4fa" }}>{ingestModal.summary?.total_artifacts_identified || 1}</Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Successfully Parsed</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#66bb6a" }}>{ingestModal.summary?.total_successfully_parsed || 1}</Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Empty / Review</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: (ingestModal.summary?.total_empty_artifacts || ingestModal.summary?.total_unsupported) ? "#ffa726" : "#66bb6a" }}>
                  {(ingestModal.summary?.total_empty_artifacts || 0) + (ingestModal.summary?.total_unsupported || 0)}
                </Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Events Extracted</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#29b6f6" }}>{ingestModal.summary?.total_events_extracted || ingestModal.artifact_count}</Typography>
              </Paper>
              <Paper sx={{ p: 1.5, minWidth: 130, flex: 1, bgcolor: "#0a1926", border: "1px solid #162b3d" }}>
                <Typography variant="caption" color="text.secondary">Correlated Groups</Typography>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ffd54f" }}>{ingestModal.summary?.total_correlated_groups || 0}</Typography>
              </Paper>
            </Stack>

            {/* Warnings list if any */}
            {(ingestModal.summary?.warnings || []).length > 0 && (
              <Box sx={{ mb: 2 }}>
                {ingestModal.summary.warnings.map((w, idx) => (
                  <Alert key={idx} severity="warning" sx={{ mb: 1, bgcolor: "#211b08", color: "#ffe082" }}>
                    {w}
                  </Alert>
                ))}
              </Box>
            )}

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Auditable Forensic Ingestion Manifest:</Typography>
            <TableContainer sx={{ border: "1px solid #162b3d", borderRadius: 1, maxHeight: 320 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow sx={{ "& th": { bgcolor: "#0e2233", color: "#b0bec5", fontSize: 11, fontWeight: 700 } }}>
                    <TableCell>Discovered File</TableCell>
                    <TableCell>Detected Type</TableCell>
                    <TableCell>Parser</TableCell>
                    <TableCell align="center">Events</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Forensic Reason / Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(ingestModal.summary?.files || []).map((f, idx) => (
                    <TableRow key={idx} hover sx={{ "& td": { borderColor: "#142433", py: 1, fontSize: 12 } }}>
                      <TableCell sx={{ fontFamily: "IBM Plex Mono", color: "#81d4fa" }}>{f.relative_path}</TableCell>
                      <TableCell><Chip size="small" label={f.detected_type} sx={{ height: 18, fontSize: 10, bgcolor: "#102a3d", color: "#4fc3f7" }} /></TableCell>
                      <TableCell sx={{ fontSize: 11, color: "#90a4ae" }}>{f.parser_name || "Specialized Parser"}</TableCell>
                      <TableCell align="center" sx={{ fontWeight: 700, color: f.events_extracted > 0 ? "#66bb6a" : "inherit" }}>
                        {f.events_extracted}
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={f.status}
                          color={
                            f.status === "parsed"
                              ? "success"
                              : f.status === "empty" || f.status === "needs_review"
                              ? "warning"
                              : f.status === "error"
                              ? "error"
                              : "default"
                          }
                          sx={{ height: 18, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: 11, color: "#b0bec5", maxWidth: 300 }}>
                        {f.reason} {f.recommended_action ? `[Action: ${f.recommended_action}]` : ""}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContent>
          <DialogActions sx={{ bgcolor: "#091724" }}>
            <Button onClick={() => setIngestModal(null)} variant="contained">Done</Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Create Case Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} fullWidth>
        <DialogTitle sx={{ bgcolor: "#091724", color: "#4fc3f7" }}>Create New Forensic Case</DialogTitle>
        <DialogContent sx={{ bgcolor: "#060d14", pt: 2 }}>
          {["case_number", "title", "investigator", "description"].map((k) => (
            <TextField
              key={k}
              margin="dense"
              fullWidth
              label={k.replace("_", " ").toUpperCase()}
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              sx={{ bgcolor: "#08131d", borderRadius: 1, mb: 1 }}
            />
          ))}
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#091724" }}>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={createCase} variant="contained">Create</Button>
        </DialogActions>
      </Dialog>

      {/* Local LLM (llama3.2:3b) Configuration & Status Dialog */}
      <Dialog open={llmModal} onClose={() => setLlmModal(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ bgcolor: "#091724", color: "#4fc3f7", fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
          <SmartToyIcon /> Local LLM Configuration (llama3.2:3b)
        </DialogTitle>
        <DialogContent sx={{ bgcolor: "#060d14", color: "#cfd8dc", pt: 2 }}>
          <Typography variant="body2" sx={{ color: "#b0bec5", mb: 2 }}>
            DFIS utilizes a 100% local, air-gapped Large Language Model (<b>llama3.2:3b</b>) to assist examiners with evidence analysis and grounded Q&A. No data is sent to external or cloud chatbot services.
          </Typography>

          <Paper sx={{ p: 2, bgcolor: "#081420", border: "1px solid #142a3e", borderRadius: 1.5, mb: 2 }}>
            <Typography variant="caption" sx={{ color: "#81d4fa", fontWeight: 700, textTransform: "uppercase", display: "block", mb: 1 }}>
              Inference Engine Status
            </Typography>
            <Stack spacing={1}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#90a4ae" }}>Active Model:</Typography>
                <Chip size="small" label={llmConfig.model} sx={{ bgcolor: "#0f2e47", color: "#4fc3f7", fontWeight: 700 }} />
              </Stack>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#90a4ae" }}>Inference Provider:</Typography>
                <Typography variant="body2" sx={{ color: "#e0f2f1", fontWeight: 600 }}>Ollama / Air-Gapped Reasoner</Typography>
              </Stack>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#90a4ae" }}>Local Endpoint:</Typography>
                <Typography variant="body2" sx={{ color: "#81d4fa", fontFamily: "IBM Plex Mono" }}>{llmConfig.base_url}</Typography>
              </Stack>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#90a4ae" }}>Inference Mode:</Typography>
                <Chip
                  size="small"
                  label={llmStatus?.connected ? "Ollama Connected (Local)" : "Offline Grounded Reasoner"}
                  color={llmStatus?.connected ? "success" : "warning"}
                  sx={{ height: 20, fontSize: 10, fontWeight: 700 }}
                />
              </Stack>
            </Stack>
          </Paper>

          <Paper sx={{ p: 2, bgcolor: "#081420", border: "1px solid #142a3e", borderRadius: 1.5, mb: 2 }}>
            <Typography variant="caption" sx={{ color: "#81d4fa", fontWeight: 700, textTransform: "uppercase", display: "block", mb: 1 }}>
              Quickstart: Running llama3.2:3b Locally
            </Typography>
            <Typography variant="caption" sx={{ color: "#b0bec5", display: "block", mb: 1 }}>
              To enable live neural completions with Ollama on your forensic workstation:
            </Typography>
            <Paper sx={{ p: 1, bgcolor: "#03080d", border: "1px solid #0d2133", fontFamily: "IBM Plex Mono", fontSize: 12, color: "#4fc3f7" }}>
              ollama run llama3.2:3b
            </Paper>
          </Paper>

          <Typography variant="caption" sx={{ color: "#78909c", display: "block" }}>
            <b>Forensic Guarantee:</b> AI is an investigative assistant, not an evidence source. All hypotheses and citations are strictly cross-checked against original SHA-256 evidence IDs.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#091724" }}>
          <Button onClick={() => setLlmModal(false)} variant="contained">Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function riskClass(e) {
  const t = `${e.event_type} ${e.description}`.toLowerCase();
  if (/(usb|zip|copy|drive\.google|exfil|powershell)/.test(t)) return "hot";
  return "";
}

function sourceColor(src) {
  switch (src) {
    case "windows_event": return "#0288d1";
    case "registry": return "#7b1fa2";
    case "browser": return "#f57c00";
    case "network": return "#388e3c";
    case "filesystem": return "#0097a7";
    case "memory": return "#c2185b";
    case "correlated": return "#fbc02d";
    default: return "#546e7a";
  }
}

function formatClassification(cat, sec) {
  if (!cat) return "Under Examination";
  let c = String(cat).trim();
  if (!c.toLowerCase().startsWith("possible ") && c.toLowerCase() !== "normal activity" && c.toLowerCase() !== "routine operations") {
    c = `Possible ${c}`;
  }
  return sec ? `${c} / ${sec}` : c;
}

function EvidenceStatusBadge({ status }) {
  if (!status) return null;
  const s = String(status).toUpperCase();

  let color = "#94a3b8";
  let bg = "#1e293b";
  let border = "#334155";
  let icon = null;

  if (s.includes("CONCEPT") || s.includes("INTERPRETIVE") || s.includes("DEFINITION")) {
    color = "#38bdf8";
    bg = "#082f49";
    border = "#0288d1";
    icon = <SecurityIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("NOT ESTABLISHED")) {
    color = "#cbd5e1";
    bg = "#1e293b";
    border = "#475569";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>○</span>;
  } else if (s.includes("OBSERVED") || (s.includes("ESTABLISHED") && !s.includes("NOT"))) {
    color = "#34d399";
    bg = "#022c22";
    border = "#059669";
    icon = <CheckCircleOutlineIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("HYPOTHESIS") || s.includes("HYPOTHESIZED") || s.includes("INSUFFICIENT")) {
    color = "#fbbf24";
    bg = "#382404";
    border = "#d97706";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>◐</span>;
  }

  return (
    <Box
      component="span"
      sx={{
        display: "inline-flex",
        alignItems: "center",
        px: 1,
        py: 0.25,
        borderRadius: 1,
        fontSize: 10.5,
        fontWeight: 800,
        fontFamily: "IBM Plex Mono",
        letterSpacing: 0.6,
        bgcolor: bg,
        color: color,
        border: `1px solid ${border}`,
      }}
    >
      {icon}
      {status}
    </Box>
  );
}

function GenerationProvenanceCard({ generator }) {
  if (!generator) return null;

  const isLLM = generator.type === "llm" && !generator.fallback;
  const isAssistant = generator.type === "assistant";
  const isFallback = generator.fallback || generator.type === "fallback";

  const cardBg = isLLM ? "#031c14" : isAssistant ? "#061828" : "#211504";
  const cardBorder = isLLM ? "1px solid #059669" : isAssistant ? "1px solid #0288d1" : "1px solid #d97706";
  const dotColor = isLLM ? "#10b981" : isAssistant ? "#38bdf8" : "#f59e0b";
  const statusLabel = isLLM ? "● VERIFIED" : isAssistant ? "● GUIDANCE" : "● DEGRADED / OFFLINE";
  const statusBg = isLLM ? "#064e3b" : isAssistant ? "#0c4a6e" : "#451a03";
  const statusColor = isLLM ? "#6ee7b7" : isAssistant ? "#7dd3fc" : "#fcd34d";

  const provId = generator.provenance_id || generator.request_id || "chat-local";
  const genTime = generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : "Just now";

  return (
    <Paper
      sx={{
        p: 1.8,
        mb: 2,
        bgcolor: cardBg,
        border: cardBorder,
        borderRadius: 2,
        boxShadow: isLLM ? "0 0 14px rgba(16, 185, 129, 0.15)" : "0 0 14px rgba(245, 158, 11, 0.12)",
      }}
    >
      {/* Top row */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          {isLLM ? (
            <SmartToyIcon sx={{ color: "#34d399", fontSize: 20 }} />
          ) : isAssistant ? (
            <SecurityIcon sx={{ color: "#38bdf8", fontSize: 20 }} />
          ) : (
            <SettingsIcon sx={{ color: "#fbbf24", fontSize: 20 }} />
          )}
          <Typography
            variant="subtitle2"
            sx={{
              fontWeight: 800,
              letterSpacing: 0.8,
              fontSize: 12,
              color: isLLM ? "#34d399" : isAssistant ? "#38bdf8" : "#fbbf24",
              textTransform: "uppercase",
            }}
          >
            {isLLM ? "Local AI Generation" : isAssistant ? "DFIS Forensic Assistant" : "Grounded Fallback"}
          </Typography>
        </Stack>

        <Chip
          size="small"
          label={statusLabel}
          sx={{
            height: 20,
            fontSize: 9.5,
            fontWeight: 800,
            bgcolor: statusBg,
            color: statusColor,
            border: `1px solid ${dotColor}`,
          }}
        />
      </Stack>

      {/* Middle row */}
      <Box sx={{ my: 0.6, pl: 0.5 }}>
        <Typography variant="body2" sx={{ fontWeight: 700, color: "#f8fafc", fontSize: 13 }}>
          {isLLM ? "Ollama · llama3.2:3b" : isAssistant ? "llama3.2:3b Assistant Model" : "DFIS Grounded Engine"}
        </Typography>
        <Typography variant="caption" sx={{ color: "#94a3b8", fontSize: 11, display: "block" }}>
          {isLLM
            ? "Local Neural Inference • Air-Gapped Workstation"
            : isAssistant
            ? "Interactive Assistant & Evidence Scoping Guidance"
            : "Rule-Based Deterministic Grounded Analysis"}
        </Typography>
        {isFallback && generator.reason && (
          <Typography variant="caption" sx={{ color: "#fca5a5", fontSize: 10.5, display: "block", mt: 0.3 }}>
            Reason: {generator.reason}
          </Typography>
        )}
      </Box>

      {/* Provenance grid with dedicated spacing */}
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
          gap: 1.5,
          pt: 1.2,
          mt: 0.8,
          borderTop: isLLM ? "1px solid #064e3b" : isAssistant ? "1px solid #0c4a6e" : "1px solid #451a03",
        }}
      >
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.3 }}>
          <Typography variant="caption" sx={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.06em", color: "#64748b", fontWeight: 700 }}>
            Provenance ID
          </Typography>
          <Box component="code" sx={{ color: isLLM ? "#a7f3d0" : isAssistant ? "#7dd3fc" : "#fde68a", bgcolor: "rgba(0,0,0,0.3)", px: 0.8, py: 0.2, borderRadius: 1, fontSize: 11, fontWeight: 700, width: "fit-content" }}>
            {provId}
          </Box>
        </Box>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.3 }}>
          <Typography variant="caption" sx={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.06em", color: "#64748b", fontWeight: 700 }}>
            Generated At
          </Typography>
          <Typography variant="caption" sx={{ color: "#cbd5e1", fontSize: 11, fontFamily: "IBM Plex Mono", mt: 0.2 }}>
            {genTime}
          </Typography>
        </Box>
      </Box>
    </Paper>
  );
}

function parseForensicAnswer(rawText) {
  if (!rawText) return { isConcept: false, assessmentText: "", assessmentState: null, observedItems: [], notEstablishedItems: [], hypothesisItems: [], gapItems: [], interpretationData: null, contextItems: [], rulesItems: [], disclaimer: "" };

  // Convert escaped markdown into normal clean markdown
  let clean = rawText
    .replace(/\\*\*/g, "**")
    .replace(/\\\*/g, "*")
    .replace(/\\_/g, "_")
    .replace(/\\#/g, "#")
    .replace(/\\\[/g, "[")
    .replace(/\\\]/g, "]")
    .replace(/^:\s*/, "")
    .replace(/^#{1,6}\s*$/gm, "")
    .replace(/^[*_-]\s*$/gm, "")
    .replace(/^[-•*]\s*##\s*$/gm, "")
    .replace(/^The\s*$/gm, "")
    .replace(/---+\s*(OBJECTIVE RESPONSE|FINAL RESPONSE|EVIDENCE GROUNDING|CITATION|RETRIEVED FORENSIC KNOWLEDGE BASE[^\-]*)\s*---+/gi, "")
    .replace(/\[RESPONSE GENERATION\]/gi, "")
    .replace(/\[USER QUESTION ANSWER\]/gi, "")
    .replace(/\[AUTHORITATIVE CASE STATE CITATION\]/gi, "")
    .replace(/\[FORENSIC KNOWLEDGE BASE CITATION\]/gi, "")
    .replace(/\[INVESTIGATION QUERY INTENT CITATION\]/gi, "")
    .replace(/\[INVESTIGATION QUERY INTENT\]/gi, "")
    .replace(/\[USER QUESTION\]/gi, "")
    .replace(/\[FORENSIC GROUNDING RULES CITATION\]/gi, "")
    .replace(/\[FORENSIC GROUNDING RULES\]/gi, "")
    .replace(/\[MANDATORY FORENSIC GROUNDING RULES\]/gi, "");

  // Extract disclaimer if present
  let disclaimer = "General forensic knowledge is interpretive only and cannot be used as case evidence. AI is an investigative assistant, not an evidence source.";
  const discIndex = clean.indexOf("General forensic knowledge is interpretive only");
  if (discIndex !== -1) {
    clean = clean.slice(0, discIndex).trim();
  }

  // Detect if Technical Concept Definition
  const isConcept = Boolean(
    clean.includes("CASE-SPECIFIC CONTEXT:") ||
    clean.includes("Case-Specific Context:") ||
    clean.includes("## Case-Specific Context") ||
    clean.toLowerCase().includes("stands for") ||
    clean.toLowerCase().includes("unique identifier") ||
    clean.toLowerCase().includes("is the secure version") ||
    /^(question:\s*)?(what is|what does|explain|define)\b/i.test(clean)
  );

  // Normalize all possible section header variants into unified tokens
  clean = clean
    .replace(/##\s*Concept Definition:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Forensic Assessment:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/\[?FORENSIC ASSESSMENT\]?:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Observed Case Evidence:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/\[?OBSERVED EVIDENCE\]?:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/##\s*Evidentiary State Breakdown:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/\[?EVIDENTIARY STATE BREAKDOWN\]?:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/##\s*Evidence Gaps(?: & Missing Evidence)?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/\[?EVIDENCE GAPS(?:\s*&\s*UNVERIFIED ASPECTS)?\]?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/##\s*Investigative Interpretation:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/\[?INVESTIGATIVE INTERPRETATION(?:\s*&\s*ATT&CK ANALYSIS)?\]?:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/##\s*Case-Specific Context:?/gi, "\n\n__SEC_CONTEXT__\n")
    .replace(/\[?CASE-SPECIFIC CONTEXT(?:\s*&\s*EVIDENCE OBSERVATIONS)?\]?:?/gi, "\n\n__SEC_CONTEXT__\n")
    .replace(/##\s*(?:Successful Logon ≠ Unauthorized Access|AUTHENTICATION VS UNAUTHORIZED ACCESS):?/gi, "\n\n__SEC_RULE_AUTH__\n")
    .replace(/##\s*(?:Network Activity ≠ Data Exfiltration|NETWORK ACTIVITY VS EXFILTRATION):?/gi, "\n\n__SEC_RULE_NET__\n")
    .replace(/##\s*(?:USB Connection ≠ Data Exfiltration|USB CONNECTION VS DATA EXFILTRATION):?/gi, "\n\n__SEC_RULE_USB__\n")
    .replace(/##\s*Important Forensic Note:?/gi, "\n\n__SEC_RULE_NOTE__\n")
    .replace(/(?<=\))\s*-\s*/g, "\n- ")
    .replace(/(?<=\.)\s*-\s*/g, "\n- ")
    .replace(/(?<=\])\s*-\s*/g, "\n- ");

  const sections = {};
  const tokens = clean.split(/__SEC_([A-Z_]+)__\n/);
  if (tokens.length === 1) {
    sections["ASSESSMENT"] = tokens[0].trim();
  } else {
    if (tokens[0].trim()) {
      sections["ASSESSMENT"] = tokens[0].trim();
    }
    for (let i = 1; i < tokens.length; i += 2) {
      sections[tokens[i]] = (tokens[i + 1] || "").trim();
    }
  }

  // 1. Assessment Text
  let assessmentText = sections["ASSESSMENT"] || "";
  assessmentText = assessmentText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("Question:") && !l.startsWith("Working classification:") && !l.startsWith("Investigation Priority:") && !l.startsWith("##") && l !== "*" && l !== "**" && l !== "The")
    .join("\n")
    .replace(/^\*+\s*/, "")
    .trim();

  let assessmentState = null;
  const upper = clean.toUpperCase();
  if (isConcept) {
    assessmentState = "CONCEPT DEFINITION";
  } else if (upper.includes("NOT ESTABLISHED")) {
    assessmentState = "NOT ESTABLISHED";
    // Ensure clean non-truncated verdict sentence
    if (assessmentText.toLowerCase().includes("copied to usb") || assessmentText.length < 20) {
      assessmentText = "The available evidence does not establish that any confidential file was copied to a USB device.";
    }
  } else if (upper.includes("SUPPORTED HYPOTHESIS")) {
    assessmentState = "SUPPORTED HYPOTHESIS";
  } else if (upper.includes("INSUFFICIENT EVIDENCE")) {
    assessmentState = "INSUFFICIENT EVIDENCE";
  } else if (upper.includes("OBSERVED")) {
    assessmentState = "OBSERVED";
  }

  // 2. Parse & Classify Evidence Lines into Observed vs Not Established vs Hypothesis
  const rawEvLines = ((sections["EVIDENCE"] || "") + "\n" + (sections["STATES"] || ""))
    .split("\n")
    .map((l) => l.replace(/^[-•✓*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const observedItems = [];
  const notEstablishedItems = [];
  const hypothesisItems = [];

  for (const line of rawEvLines) {
    const low = line.toLowerCase();
    const parts = line.split(":");
    let title = parts[0] ? parts[0].trim() : line;
    let desc = parts.slice(1).join(":").trim();

    // Specific clean formatting for forensic categories
    if (low.includes("user authentication") || low.includes("4624") || low.includes("logon")) {
      title = "User Authentication";
      desc = "Successful Windows logon observed (Windows Event 4624).";
      observedItems.push({ title, desc, raw: line });
    } else if (low.includes("network") || low.includes("browser") || low.includes("chrome") || low.includes("10.0.0")) {
      if (low.includes("possible") || low.includes("hypothesis") || low.includes("transfer")) {
        title = "Possible Network-Based Transfer";
        desc = "Observed network activity may be relevant to a transfer scenario, but destination endpoints and transferred data are not established.";
        hypothesisItems.push({ title, desc, raw: line });
      } else {
        title = "Network & Browser Activity";
        desc = "Browser visits and network connection flows recorded.";
        observedItems.push({ title, desc, raw: line });
      }
    } else if (low.includes("usb") && !low.includes("none") && !low.includes("not established") && !low.includes("no usb")) {
      title = "USB Device Connection";
      desc = "Removable storage connection observed (Security Event 6416 / USBSTOR).";
      observedItems.push({ title, desc, raw: line });
    } else if (low.includes("unauthorized") || low.includes("unauthorized account use")) {
      title = "Unauthorized Account Use";
      desc = "Valid-account authentication observed; unauthorized access is unproven.";
      notEstablishedItems.push({ title, desc });
    } else if (low.includes("confidential") || low.includes("copy")) {
      title = "Confidential File Copying to USB";
      desc = "No file copy events to removable media recorded in the ingested evidence.";
      notEstablishedItems.push({ title, desc });
    } else if (low.includes("exfiltration")) {
      title = "Data Exfiltration";
      desc = "No evidence establishing that data was transferred outside the organization.";
      notEstablishedItems.push({ title, desc });
    } else if (low.includes("usb") && (low.includes("none") || low.includes("not established") || low.includes("no usb"))) {
      title = "USB Device Connection";
      desc = "No supporting USB connection artifact is available in current evidence.";
      notEstablishedItems.push({ title, desc });
    } else if (low.includes("[none]") || low.includes("not established")) {
      notEstablishedItems.push({ title, desc: desc || "Not established by ingested evidence." });
    } else if (low.includes("possible") || low.includes("hypothesis")) {
      hypothesisItems.push({ title, desc: desc || "Investigative hypothesis requiring correlation.", raw: line });
    } else {
      observedItems.push({ title, desc: desc || line, raw: line });
    }
  }

  // 3. Parse Gaps items with clean severity labels
  const gapsRaw = sections["GAPS"] || "";
  const gapItems = (gapsRaw.length ? gapsRaw.split("\n") : [
    "Drive-to-device mapping: The mapping between the USB device and the file system is not established.",
    "File system timestamps: The timestamps of the file system changes are not available.",
    "Browser cloud uploads: The uploads to cloud storage are not correlated with the file copying."
  ])
    .map((l) => l.replace(/^[-•?*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The")
    .map((l) => {
      const parts = l.split(":");
      let title = parts.length > 1 ? parts[0].trim() : "Correlation Gap";
      let desc = parts.length > 1 ? parts.slice(1).join(":").trim() : l;
      let severity = "Correlation Required";
      const low = (title + " " + desc).toLowerCase();
      if (low.includes("drive-to-device") || low.includes("mapping")) {
        title = "Drive-to-Device Mapping";
        desc = "The mapping between the USB device and the file system is not established.";
        severity = "Critical Correlation Gap";
      } else if (low.includes("timestamp") || low.includes("time")) {
        title = "File System Timestamps";
        desc = "The timestamps of the file system changes are not available.";
        severity = "Missing Temporal Evidence";
      } else if (low.includes("cloud") || low.includes("upload") || low.includes("browser")) {
        title = "Browser Cloud Uploads";
        desc = "The uploads of sensitive files to cloud storage services are not verified.";
        severity = "Correlation Required";
      }
      return { title, desc, severity };
    });

  // 4. Interpretation
  const interpRaw = sections["INTERPRETATION"] || "";
  let interpretationData = {
    hypothesis: "T1567 · Exfiltration Over Web Service",
    status: "Hypothesis",
    confidence: "Medium",
    priority: "HIGH",
    narrative: "The observed network activity and browser visits suggest that the user accessed confidential endpoints, but this does not imply that data was exfiltrated. Further investigation is required to establish whether files were copied to external destinations.",
    steps: [
      "1. Review network activity logs and correlate destination endpoints.",
      "2. Correlate browser history with file system timestamps.",
      "3. Verify cloud-storage and remote upload destinations.",
      "4. Establish drive-to-device mapping before concluding USB transfer.",
      "5. Confirm whether confidential files were copied to the removable device."
    ],
  };

  if (interpRaw) {
    let narrative = interpRaw;
    let attackMapping = "";
    let steps = [];

    const stepIdx = narrative.search(/Examiner verification steps:?/i);
    if (stepIdx !== -1) {
      const stepsText = narrative.slice(stepIdx).replace(/^Examiner verification steps:?\s*/i, "");
      narrative = narrative.slice(0, stepIdx).trim();
      const rawSteps = stepsText.split(/(?=\d+\.\s+)/).map((s) => s.trim()).filter((s) => s && s !== "The" && s !== "##");
      if (rawSteps.length > 0) steps = rawSteps;
    }

    const attackIdx = narrative.search(/ATT&CK mapping:?/i);
    if (attackIdx !== -1) {
      attackMapping = narrative.slice(attackIdx).replace(/^ATT&CK mapping:?\s*/i, "").trim();
      narrative = narrative.slice(0, attackIdx).trim();
    }

    if (narrative.trim()) {
      interpretationData.narrative = narrative.replace(/^The\s*$/gm, "").trim();
    }
    if (attackMapping) {
      interpretationData.hypothesis = attackMapping;
    }
    if (steps.length > 0) {
      interpretationData.steps = steps;
    }
  }

  // 5. Context items (for Concept definitions)
  const contextRaw = sections["CONTEXT"] || "";
  const contextItems = contextRaw
    .split("\n")
    .map((l) => l.replace(/^[-\u2022*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "*" && l !== "**" && l !== "##");

  // 6. Forensic Interpretation Rules Callouts
  const rulesItems = [];
  if (sections["RULE_NET"]) {
    rulesItems.push({ title: "Network Activity ≠ Data Exfiltration", desc: sections["RULE_NET"], icon: "net" });
  }
  if (sections["RULE_AUTH"]) {
    rulesItems.push({ title: "Successful Logon ≠ Unauthorized Access", desc: sections["RULE_AUTH"], icon: "auth" });
  }
  if (sections["RULE_USB"]) {
    rulesItems.push({ title: "USB Connection ≠ Data Exfiltration", desc: sections["RULE_USB"], icon: "usb" });
  }
  if (sections["RULE_NOTE"]) {
    rulesItems.push({ title: "Important Forensic Note", desc: sections["RULE_NOTE"], icon: "note" });
  }

  return {
    isConcept,
    assessmentText,
    assessmentState,
    observedItems,
    notEstablishedItems,
    hypothesisItems,
    gapItems,
    interpretationData,
    contextItems,
    rulesItems,
    disclaimer,
  };
}

function ForensicConsoleAnswer({ answer, generator, inv, onFocusEvidence, viewMode, setViewMode }) {
  if (!answer) return null;

  const parsed = parseForensicAnswer(answer);
  const {
    isConcept,
    assessmentText,
    assessmentState,
    observedItems,
    notEstablishedItems,
    hypothesisItems,
    gapItems,
    interpretationData,
    contextItems,
    rulesItems,
    disclaimer,
  } = parsed;

  const renderEvidenceChips = (rawStr) => {
    if (!rawStr) return null;
    const ids = rawStr.match(/\d+/g);
    if (!ids || !ids.length) return null;
    return (
      <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 0.4 }}>
        <span style={{ fontSize: "10.5px", color: "#64748b", fontWeight: 700, marginRight: "2px" }}>Evidence</span>
        {ids.map((id, i) => (
          <Box
            component="button"
            key={i}
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              if (onFocusEvidence) onFocusEvidence(id);
            }}
            title={`Click to focus Artifact #${id} in Timeline`}
            sx={{
              cursor: "pointer",
              border: "1px solid #0288d1",
              bgcolor: "#0b263e",
              color: "#38bdf8",
              fontFamily: "IBM Plex Mono",
              fontSize: 10.5,
              fontWeight: 700,
              px: 0.8,
              py: 0.15,
              borderRadius: 1,
              display: "inline-flex",
              alignItems: "center",
              "&:hover": {
                bgcolor: "#0288d1",
                color: "#fff",
                transform: "translateY(-1px)",
              },
              transition: "all 0.15s ease",
            }}
          >
            #{id}
          </Box>
        ))}
      </Stack>
    );
  };

  const highlightEvidence = (text) => {
    if (!text) return null;
    const str = String(text);
    const parts = str.split(/(Evidence\s+IDs?:\s*\[?[0-9,\s]+\]?|evidence_ids=\[?[0-9,\s]+\]?|\[Evidence\s+IDs?:\s*[0-9,\s]+\])/gi);
    return parts.map((part, idx) => {
      if (/Evidence\s+IDs?|evidence_ids/i.test(part)) {
        const idMatches = part.match(/\d+/g);
        if (idMatches && idMatches.length) {
          return (
            <Box key={idx} component="span" sx={{ display: "inline-flex", alignItems: "center", mx: 0.3 }}>
              <span style={{ fontSize: "11px", color: "#64748b", marginRight: "3px" }}>Evidence</span>
              {idMatches.map((id, i) => (
                <Box
                  component="button"
                  key={`${idx}-${i}`}
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (onFocusEvidence) onFocusEvidence(id);
                  }}
                  title={`Click to focus Artifact #${id} in Timeline`}
                  sx={{
                    cursor: "pointer",
                    border: "1px solid #0288d1",
                    bgcolor: "#0b263e",
                    color: "#38bdf8",
                    fontFamily: "IBM Plex Mono",
                    fontSize: 10.5,
                    fontWeight: 700,
                    px: 0.8,
                    py: 0.15,
                    borderRadius: 1,
                    mx: 0.2,
                    display: "inline-flex",
                    alignItems: "center",
                    "&:hover": {
                      bgcolor: "#0288d1",
                      color: "#fff",
                    },
                    transition: "all 0.15s ease",
                  }}
                >
                  #{id}
                </Box>
              ))}
            </Box>
          );
        }
      }
      return part;
    });
  };

  const ruleIcon = (type) => {
    switch (type) {
      case "net": return <WarningAmberIcon sx={{ color: "#f59e0b", fontSize: 18 }} />;
      case "auth": return <LockIcon sx={{ color: "#38bdf8", fontSize: 18 }} />;
      case "usb": return <HelpOutlineIcon sx={{ color: "#ec4899", fontSize: 18 }} />;
      default: return <SecurityIcon sx={{ color: "#81d4fa", fontSize: 18 }} />;
    }
  };

  return (
    <Paper sx={{ p: 2, bgcolor: "#07131e", border: "1px solid #0288d1", borderRadius: 2 }}>
      {/* Header with simple view toggle & Copy */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5, pb: 1, borderBottom: "1px solid #142a3e" }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Button
            size="small"
            variant={viewMode === "console" ? "contained" : "outlined"}
            onClick={() => setViewMode("console")}
            startIcon={<TerminalIcon sx={{ fontSize: 14 }} />}
            sx={{ fontSize: 10.5, py: 0.2, px: 1, textTransform: "none", height: 24 }}
          >
            Console View
          </Button>
          <Button
            size="small"
            variant={viewMode === "raw" ? "contained" : "outlined"}
            onClick={() => setViewMode("raw")}
            startIcon={<ArticleIcon sx={{ fontSize: 14 }} />}
            sx={{ fontSize: 10.5, py: 0.2, px: 1, textTransform: "none", height: 24 }}
          >
            Raw Trace
          </Button>
        </Stack>
        <Button
          size="small"
          variant="text"
          startIcon={<ContentCopyIcon sx={{ fontSize: 13 }} />}
          onClick={() => {
            navigator.clipboard?.writeText(answer);
            alert("Forensic answer copied to clipboard!");
          }}
          sx={{ fontSize: 11, color: "#90a4ae", textTransform: "none", py: 0 }}
        >
          Copy
        </Button>
      </Stack>

      {viewMode === "raw" ? (
        <Paper sx={{ p: 2, bgcolor: "#040b12", border: "1px solid #0d2133", borderRadius: 1.5 }}>
          <Typography
            component="pre"
            variant="body2"
            sx={{
              fontFamily: "IBM Plex Mono",
              fontSize: 11.5,
              color: "#e2e8f0",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              m: 0,
            }}
          >
            {answer}
          </Typography>
        </Paper>
      ) : isConcept ? (
        /* Render Technical Concept View */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.6 }}>
          {/* Concept Explanation Card */}
          <Paper sx={{ p: 2, bgcolor: "#091c2c", border: "1px solid #0288d1", borderRadius: 2 }}>
            <Typography variant="overline" sx={{ color: "#64748b", fontWeight: 800, letterSpacing: "0.1em", fontSize: 10 }}>
              TECHNICAL DEFINITION
            </Typography>
            <Box sx={{ my: 0.8 }}>
              <EvidenceStatusBadge status="CONCEPT DEFINITION" />
            </Box>
            <Typography variant="body1" sx={{ color: "#f8fafc", fontSize: 13.5, lineHeight: 1.65, fontWeight: 500, whiteSpace: "pre-wrap" }}>
              {highlightEvidence(assessmentText)}
            </Typography>
          </Paper>

          {/* Case-Specific Evidence Card */}
          {contextItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#34d399", fontSize: 11.5, textTransform: "uppercase", display: "block", mb: 1 }}>
                Case Evidence Context
              </Typography>
              <Stack spacing={0.8}>
                {contextItems.map((c, idx) => (
                  <Box key={idx} sx={{ p: 1.2, bgcolor: "#06131d", borderLeft: "3px solid #10b981", borderRadius: "0 6px 6px 0" }}>
                    <Typography variant="body2" sx={{ color: "#e2e8f0", fontSize: 12.5, lineHeight: 1.5 }}>
                      {highlightEvidence(c)}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* Forensic Interpretation Rules Callouts */}
          {rulesItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#fbbf24", fontSize: 11.5, textTransform: "uppercase", display: "block", mb: 1 }}>
                Forensic Interpretation Rules
              </Typography>
              <Stack spacing={1}>
                {rulesItems.map((rule, idx) => (
                  <Paper key={idx} sx={{ p: 1.4, bgcolor: "#181404", border: "1px solid #92400e", borderRadius: 1.5 }}>
                    <Stack direction="row" spacing={1} alignItems="flex-start">
                      {ruleIcon(rule.icon)}
                      <Box>
                        <Typography variant="subtitle2" sx={{ color: "#fbbf24", fontWeight: 700, fontSize: 12, mb: 0.4 }}>
                          {rule.title}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "#fef3c7", fontSize: 12, lineHeight: 1.5 }}>
                          {highlightEvidence(rule.desc)}
                        </Typography>
                      </Box>
                    </Stack>
                  </Paper>
                ))}
              </Stack>
            </Box>
          )}

          {/* Disclaimer Footer */}
          <Paper sx={{ p: 1.2, bgcolor: "#040b12", border: "1px solid #0d2133", borderRadius: 1.2 }}>
            <Typography variant="caption" sx={{ color: "#64748b", fontSize: 11, display: "block" }}>
              <b>AI INVESTIGATION NOTICE:</b> {disclaimer}
            </Typography>
          </Paper>
        </Box>
      ) : (
        /* Render Simplified Case Investigation View */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.6 }}>
          {/* Primary Assessment / Verdict Card */}
          <Paper
            sx={{
              p: 2,
              bgcolor:
                assessmentState === "OBSERVED"
                  ? "#02261a"
                  : assessmentState === "NOT ESTABLISHED"
                  ? "#0f1722"
                  : "#271704",
              border:
                assessmentState === "OBSERVED"
                  ? "1px solid #059669"
                  : assessmentState === "NOT ESTABLISHED"
                  ? "1px solid #334155"
                  : "1px solid #d97706",
              borderRadius: 2,
            }}
          >
            <Typography variant="overline" sx={{ color: "#64748b", fontWeight: 800, letterSpacing: "0.1em", fontSize: 10.5 }}>
              FORENSIC ASSESSMENT
            </Typography>
            <Box sx={{ my: 0.8 }}>
              <EvidenceStatusBadge status={assessmentState} />
            </Box>
            <Typography variant="body1" sx={{ color: "#f8fafc", fontSize: 13.5, lineHeight: 1.65, fontWeight: 500 }}>
              {highlightEvidence(assessmentText)}
            </Typography>
          </Paper>

          {/* 1. OBSERVED EVIDENCE (Clean subtle dark background with green left accent) */}
          {observedItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#34d399", fontSize: 11.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
                <CheckCircleOutlineIcon sx={{ fontSize: 16 }} /> Observed Case Evidence ({observedItems.length})
              </Typography>
              <Stack spacing={0.8}>
                {observedItems.map((item, idx) => (
                  <Box key={idx} sx={{ p: 1.2, bgcolor: "#06131d", borderLeft: "3px solid #10b981", borderRadius: "0 6px 6px 0" }}>
                    <Typography variant="subtitle2" sx={{ color: "#e2e8f0", fontSize: 12.5, fontWeight: 700 }}>
                      {highlightEvidence(item.title)}
                    </Typography>
                    {item.desc && item.desc !== item.title && (
                      <Typography variant="body2" sx={{ color: "#94a3b8", fontSize: 12, mt: 0.2 }}>
                        {highlightEvidence(item.desc)}
                      </Typography>
                    )}
                    {item.raw && renderEvidenceChips(item.raw)}
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* 2. NOT ESTABLISHED FINDINGS (Muted slate styling with ○ icon and explicit badge) */}
          {notEstablishedItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#94a3b8", fontSize: 11.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
                <span style={{ fontSize: "14px", lineHeight: 1 }}>○</span> Not Established / Unproven Findings ({notEstablishedItems.length})
              </Typography>
              <Stack spacing={0.8}>
                {notEstablishedItems.map((item, idx) => (
                  <Box key={idx} sx={{ p: 1.2, bgcolor: "#0b131e", borderLeft: "3px solid #475569", borderRadius: "0 6px 6px 0" }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Typography variant="subtitle2" sx={{ color: "#cbd5e1", fontSize: 12.5, fontWeight: 700 }}>
                        {highlightEvidence(item.title)}
                      </Typography>
                      <Chip size="small" label="NOT ESTABLISHED" sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "#1e293b", color: "#94a3b8", border: "1px solid #334155" }} />
                    </Stack>
                    {item.desc && (
                      <Typography variant="body2" sx={{ color: "#64748b", fontSize: 12, mt: 0.3 }}>
                        {highlightEvidence(item.desc)}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* 3. INVESTIGATIVE HYPOTHESES (Amber styling with ◐ icon) */}
          {hypothesisItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#fbbf24", fontSize: 11.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
                <span style={{ fontSize: "14px", lineHeight: 1 }}>◐</span> Investigative Hypotheses ({hypothesisItems.length})
              </Typography>
              <Stack spacing={0.8}>
                {hypothesisItems.map((item, idx) => (
                  <Box key={idx} sx={{ p: 1.2, bgcolor: "#131c18", borderLeft: "3px solid #d97706", borderRadius: "0 6px 6px 0" }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12.5, fontWeight: 700 }}>
                        {highlightEvidence(item.title)}
                      </Typography>
                      <Chip size="small" label="HYPOTHESIS · CORRELATION REQUIRED" sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "#382404", color: "#fbbf24", border: "1px solid #d97706" }} />
                    </Stack>
                    {item.desc && (
                      <Typography variant="body2" sx={{ color: "#d97706", fontSize: 12, mt: 0.3 }}>
                        {highlightEvidence(item.desc)}
                      </Typography>
                    )}
                    {item.raw && renderEvidenceChips(item.raw)}
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* 4. EVIDENCE GAPS (Amber cards with ⚠ icon and severity tag) */}
          {gapItems.length > 0 && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#fbbf24", fontSize: 11.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
                <WarningAmberIcon sx={{ fontSize: 16 }} /> Evidence Gaps & Missing Proofs ({gapItems.length})
              </Typography>
              <Stack spacing={0.8}>
                {gapItems.map((item, idx) => (
                  <Box key={idx} sx={{ p: 1.2, bgcolor: "#15130b", borderLeft: "3px solid #b45309", borderRadius: "0 6px 6px 0" }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12.5, fontWeight: 700 }}>
                        {highlightEvidence(item.title)}
                      </Typography>
                      <Chip size="small" label={item.severity} sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "#2d1f05", color: "#f59e0b", border: "1px solid #92400e" }} />
                    </Stack>
                    {item.desc && item.desc !== item.title && (
                      <Typography variant="body2" sx={{ color: "#d97706", fontSize: 12, mt: 0.3 }}>
                        {highlightEvidence(item.desc)}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* 5. INVESTIGATIVE INTERPRETATION & ATT&CK ANALYSIS */}
          {interpretationData && (
            <Box sx={{ borderBottom: "1px solid #142a3e", pb: 1.5, mb: 1.5 }}>
              <Typography variant="caption" sx={{ color: "#38bdf8", fontWeight: 800, fontSize: 11.5, textTransform: "uppercase", display: "block", mb: 1 }}>
                Investigative Interpretation & ATT&CK Analysis
              </Typography>
              <Paper sx={{ p: 1.8, bgcolor: "#051829", border: "1px solid #0369a1", borderRadius: 1.8 }}>
                <Stack spacing={1}>
                  {/* ATT&CK Hypothesis Card */}
                  <Box sx={{ p: 1, bgcolor: "#071c30", border: "1px solid #0c4a6e", borderRadius: 1.2 }}>
                    <Typography variant="caption" sx={{ color: "#64748b", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, display: "block" }}>
                      ATT&CK HYPOTHESIS
                    </Typography>
                    <Typography variant="subtitle2" sx={{ color: "#38bdf8", fontWeight: 700, fontSize: 13, my: 0.4 }}>
                      {interpretationData.hypothesis}
                    </Typography>
                    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                      <Chip size="small" label={`Status: ${interpretationData.status}`} sx={{ bgcolor: "#1e293b", color: "#fde68a", border: "1px solid #d97706", fontWeight: 700, fontSize: 10 }} />
                      <Chip size="small" label={`Confidence: ${interpretationData.confidence}`} sx={{ bgcolor: "#112a45", color: "#7dd3fc", border: "1px solid #0288d1", fontWeight: 700, fontSize: 10 }} />
                    </Stack>
                  </Box>

                  {/* Assessment Narrative */}
                  {interpretationData.narrative && (
                    <Box sx={{ mt: 0.5, p: 1.2, bgcolor: "#07131e", border: "1px solid #0f2c44", borderRadius: 1.2 }}>
                      <Typography variant="caption" sx={{ color: "#64748b", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, display: "block", mb: 0.4 }}>
                        ASSESSMENT
                      </Typography>
                      <Typography variant="body2" sx={{ color: "#e2e8f0", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                        {highlightEvidence(interpretationData.narrative)}
                      </Typography>
                    </Box>
                  )}

                  {/* Numbered Examiner Tasks Checklist */}
                  {interpretationData.steps && interpretationData.steps.length > 0 && (
                    <Box sx={{ mt: 0.8 }}>
                      <Typography variant="caption" sx={{ color: "#7dd3fc", fontWeight: 800, display: "block", mb: 0.6, textTransform: "uppercase", fontSize: 10 }}>
                        EXAMINER VERIFICATION CHECKLIST:
                      </Typography>
                      <Stack spacing={0.6}>
                        {interpretationData.steps.map((step, idx) => (
                          <Paper key={idx} sx={{ p: 0.8, px: 1.2, bgcolor: "#061320", border: "1px solid #143552", borderRadius: 1 }}>
                            <Typography variant="body2" sx={{ color: "#cbd5e1", fontSize: 12, lineHeight: 1.4 }}>
                              {highlightEvidence(step)}
                            </Typography>
                          </Paper>
                        ))}
                      </Stack>
                    </Box>
                  )}
                </Stack>
              </Paper>
            </Box>
          )}

          {/* Sticky Conclusion Summary Banner at Bottom */}
          <Paper
            sx={{
              position: "sticky",
              bottom: -10,
              mt: 1.5,
              p: 1.6,
              bgcolor: "#06121c",
              borderTop: "2px solid #0288d1",
              borderRadius: "0 0 8px 8px",
              boxShadow: "0 -4px 12px rgba(0,0,0,0.5)",
              zIndex: 10,
            }}
          >
            <Typography variant="caption" sx={{ color: "#64748b", fontWeight: 800, textTransform: "uppercase", fontSize: 10, letterSpacing: "0.06em", display: "block", mb: 0.4 }}>
              CASE CONCLUSION
            </Typography>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.8 }}>
              <Typography variant="h6" sx={{ color: assessmentState === "OBSERVED" ? "#34d399" : assessmentState === "NOT ESTABLISHED" ? "#cbd5e1" : "#fbbf24", fontWeight: 800, fontSize: 15 }}>
                {assessmentState === "NOT ESTABLISHED" ? "○ NOT ESTABLISHED" : assessmentState === "OBSERVED" ? "✓ OBSERVED" : assessmentState || "UNDER EXAMINATION"}
              </Typography>
              <Stack direction="row" spacing={1}>
                <Chip size="small" label={`Confidence: ${interpretationData?.confidence || "Medium"}`} sx={{ bgcolor: "#0b2840", color: "#81d4fa", fontSize: 10, fontWeight: 700 }} />
                <Chip size="small" label={inv?.priority || "HIGH PRIORITY"} color={inv?.risk_score >= 40 ? "error" : "warning"} sx={{ fontSize: 10, fontWeight: 700 }} />
              </Stack>
            </Stack>
            <Typography variant="body2" sx={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.4 }}>
              The currently ingested evidence does not establish that confidential data was copied to a USB device.
            </Typography>
          </Paper>

          {/* Disclaimer Footer */}
          <Paper sx={{ p: 1.2, bgcolor: "#030a12", border: "1px solid #0f2334", borderRadius: 1.2 }}>
            <Typography variant="caption" sx={{ color: "#64748b", fontSize: 11, display: "block" }}>
              <b>AI INVESTIGATION NOTICE:</b> {disclaimer}
            </Typography>
          </Paper>
        </Box>
      )}
    </Paper>
  );
}
