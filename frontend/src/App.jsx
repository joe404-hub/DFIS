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

  // Vis Timeline initialization
  useEffect(() => {
    if (!tlRef.current || tab !== 0) return;
    const filtered = timeline.filter((e) => e.timestamp);
    if (!filtered.length) return;

    const items = new DataSet(
      filtered.map((e) => ({
        id: e.id,
        content: `<b>${e.event_type}</b><br/>${escapeHtml(e.description).slice(0, 80)}`,
        start: e.timestamp,
        group: e.source_type,
        className: e.source_type === "correlated" ? "hot" : riskClass(e),
      }))
    );
    const groups = new DataSet(
      [...new Set(filtered.map((e) => e.source_type))].map((g) => ({ id: g, content: g }))
    );
    if (tlInst.current) tlInst.current.destroy();
    tlInst.current = new Timeline(tlRef.current, items, groups, {
      stack: true,
      orientation: "top",
      margin: { item: 8 },
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
              <Paper sx={{ flex: 2, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2, overflow: "hidden" }}>
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
                    <Box ref={tlRef} sx={{ height: 260, bgcolor: "#050b11", borderRadius: 1.5, p: 1, mb: 2, border: "1px solid #162b3d" }} />

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
              <Paper sx={{ flex: 1, minWidth: 320, p: 2.5, bgcolor: "#0a1926", border: "1px solid #162b3d", borderRadius: 2 }}>
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
                  <Paper sx={{ mt: 2, p: 2, bgcolor: "#07131e", border: "1px solid #0288d1", borderRadius: 1.5 }}>
                    {/* Explicit Generation Provenance & Source Metadata */}
                    {generator && (
                      <Paper
                        sx={{
                          p: 1.5,
                          mb: 1.5,
                          bgcolor:
                            generator.type === "llm" && !generator.fallback
                              ? "#042318"
                              : generator.type === "assistant"
                              ? "#071b2d"
                              : "#261b05",
                          border:
                            generator.type === "llm" && !generator.fallback
                              ? "1px solid #10b981"
                              : generator.type === "assistant"
                              ? "1px solid #0288d1"
                              : "1px solid #f59e0b",
                          borderRadius: 1.5,
                        }}
                      >
                        {generator.type === "llm" && !generator.fallback ? (
                          <Stack spacing={0.8}>
                            <Stack direction="row" justifyContent="space-between" alignItems="center">
                              <Typography variant="subtitle2" sx={{ color: "#34d399", fontWeight: 700, fontSize: 13, display: "flex", alignItems: "center", gap: 1 }}>
                                <SmartToyIcon sx={{ color: "#34d399", fontSize: 20 }} /> Generated by Ollama (Local Neural LLM)
                              </Typography>
                              <Chip size="small" label="Verified LLM" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "#064e3b", color: "#6ee7b7", border: "1px solid #059669" }} />
                            </Stack>
                            <Typography variant="caption" sx={{ color: "#a7f3d0", fontSize: 11, display: "block" }}>
                              Model: <b>{generator.model || "llama3.2:3b"}</b> • Provider: Ollama • Mode: Local Neural Inference • Fallback: No
                            </Typography>
                            {(generator.provenance_id || generator.request_id) && (
                              <Typography variant="caption" sx={{ color: "#6ee7b7", fontSize: 10, display: "block" }}>
                                Provenance ID: <code>{generator.provenance_id || generator.request_id}</code> • Time: {generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : ""}
                              </Typography>
                            )}
                          </Stack>
                        ) : generator.type === "assistant" ? (
                          <Stack spacing={0.8}>
                            <Stack direction="row" justifyContent="space-between" alignItems="center">
                              <Typography variant="subtitle2" sx={{ color: "#81d4fa", fontWeight: 700, fontSize: 13, display: "flex", alignItems: "center", gap: 1 }}>
                                <SecurityIcon sx={{ color: "#4fc3f7", fontSize: 20 }} /> DFIS Forensic Assistant (Guidance Mode)
                              </Typography>
                              <Chip size="small" label="Assistant" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "#0b2840", color: "#81d4fa" }} />
                            </Stack>
                            <Typography variant="caption" sx={{ color: "#b3e5fc", fontSize: 11, display: "block" }}>
                              Model: <b>llama3.2:3b</b> • Local Interactive Assistant Guidance
                            </Typography>
                            {(generator.provenance_id || generator.request_id) && (
                              <Typography variant="caption" sx={{ color: "#81d4fa", fontSize: 10, display: "block" }}>
                                Provenance ID: <code>{generator.provenance_id || generator.request_id}</code>
                              </Typography>
                            )}
                          </Stack>
                        ) : (
                          <Stack spacing={0.8}>
                            <Stack direction="row" justifyContent="space-between" alignItems="center">
                              <Typography variant="subtitle2" sx={{ color: "#fbbf24", fontWeight: 700, fontSize: 13, display: "flex", alignItems: "center", gap: 1 }}>
                                <SettingsIcon sx={{ color: "#fbbf24", fontSize: 20 }} /> DFIS Grounded Fallback Response
                              </Typography>
                              <Chip size="small" label="Rule-Based Fallback" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "#451a03", color: "#fcd34d", border: "1px solid #d97706" }} />
                            </Stack>
                            <Typography variant="caption" sx={{ color: "#fde68a", fontSize: 11, display: "block" }}>
                              Provider: DFIS Grounded Engine • Reason: Ollama offline/unreachable • Mode: Rule/Template-Based Deterministic Fallback
                            </Typography>
                            {(generator.provenance_id || generator.request_id) && (
                              <Typography variant="caption" sx={{ color: "#fbbf24", fontSize: 10, display: "block" }}>
                                Provenance ID: <code>{generator.provenance_id || generator.request_id}</code> • Time: {generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : ""}
                              </Typography>
                            )}
                          </Stack>
                        )}
                      </Paper>
                    )}

                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1, pb: 0.8, borderBottom: "1px solid #102a3d" }}>
                      <Typography variant="caption" sx={{ color: "#4fc3f7", fontWeight: 700 }}>
                        Forensic Grounded Answer:
                      </Typography>
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
                    <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", fontSize: 13, color: "#e0f2f1", lineHeight: 1.5 }}>
                      {answer}
                    </Typography>
                  </Paper>
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
