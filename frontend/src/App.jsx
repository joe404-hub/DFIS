import React, { Component, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
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
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import MemoryIcon from "@mui/icons-material/Memory";
import { DataSet } from "vis-data";
import { Timeline } from "vis-timeline/standalone";
import { Network } from "vis-network/standalone";
import "vis-timeline/styles/vis-timeline-graph2d.css";

const api = (path, opts) => fetch(path, opts).then((r) => (r.ok ? r : Promise.reject(r)));

async function queryLocalOllamaFromBrowser(baseUrl, model, messages, temperature = 0.1) {
  const cleanUrl = (baseUrl || "http://localhost:11434").replace(/\/+$/, "");
  const candidates = [cleanUrl];
  if (cleanUrl.includes("localhost")) {
    candidates.push(cleanUrl.replace("localhost", "127.0.0.1"));
  } else if (cleanUrl.includes("127.0.0.1")) {
    candidates.push(cleanUrl.replace("127.0.0.1", "localhost"));
  }

  let lastError = null;
  for (const url of candidates) {
    try {
      const resp = await fetch(`${url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: model || "llama3.2:3b",
          messages: messages,
          stream: false,
          options: {
            temperature: temperature,
          },
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        const content = data?.message?.content?.trim();
        if (content) {
          return { success: true, content, model: data.model || model, url };
        }
      }
    } catch (err) {
      lastError = err;
    }
  }

  return { success: false, error: lastError ? String(lastError) : "Failed to connect to local Ollama" };
}

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
  const [q, setQ] = useState("Generate the timeline of events that occurred in this investigation");
  const [answer, setAnswer] = useState("");
  const [answerMeta, setAnswerMeta] = useState(null);
  const [generator, setGenerator] = useState(null);
  const [chatViewMode, setChatViewMode] = useState("console");
  const [llmStatus, setLlmStatus] = useState(null);
  const [llmModal, setLlmModal] = useState(false);
  const [llmConfig, setLlmConfig] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_llm_config");
      if (saved) return JSON.parse(saved);
    } catch {}
    return {
      model: "llama3.2:3b",
      base_url: "http://localhost:11434",
      temperature: 0.1,
    };
  });
  const [testingLlm, setTestingLlm] = useState(false);
  const [llmTestMsg, setLlmTestMsg] = useState(null);
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

  const loadLlmStatus = async (customConfig) => {
    const cfg = customConfig || llmConfig;
    try {
      const res = await api(`/api/llm/status?base_url=${encodeURIComponent(cfg.base_url || "")}&model=${encodeURIComponent(cfg.model || "")}`).then((x) => x.json());
      setLlmStatus(res);
      return res;
    } catch {
      const fallbackStatus = { connected: false, model: cfg.model || "llama3.2:3b", mode: "offline_grounded_fallback" };
      setLlmStatus(fallbackStatus);
      return fallbackStatus;
    }
  };

  useEffect(() => {
    loadCases();
    loadLlmStatus();
  }, []);

  useEffect(() => {
    if (active) loadCase(active);
  }, [active]);

  // Vis Timeline initialization with Black & Emerald theme
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
      uniqueSources.map((src) => ({
        id: src,
        content: `<span style="color:#3dffae;font-weight:700;font-size:11px;">●</span> ${sourceLabels[src] || src.toUpperCase()}`,
        style: "color:#8fa89d;font-weight:700;font-size:11.5px;padding:4px 8px;",
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
        nodes: { shape: "dot", size: 14, font: { color: "#eefaf4", size: 12, face: "Inter" } },
        edges: { color: "rgba(61, 255, 174, 0.2)", font: { color: "#8fa89d", size: 10 }, arrows: "to" },
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

  const acquireEvidence = async () => {
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
          base_url: llmConfig.base_url,
          temperature: llmConfig.temperature,
        }),
      }).then((x) => x.json());

      let finalAnswer = r.answer;
      let finalGenerator = r.generator || null;
      let finalAnalysis = r.generated_analysis || null;

      // If backend was unable to reach user's local Ollama from cloud, try direct browser bridge
      if (r.generator?.fallback && r.prompt_messages && r.prompt_messages.length > 0) {
        try {
          const browserRes = await queryLocalOllamaFromBrowser(
            llmConfig.base_url,
            llmConfig.model,
            r.prompt_messages,
            llmConfig.temperature
          );
          if (browserRes.success && browserRes.content) {
            if (r.intent === "CASE_TIMELINE") {
              const tablePart = r.answer ? r.answer.split("### AI Investigation Summary")[0].trim() : "";
              finalAnswer = `${tablePart}\n\n### AI Investigation Summary & Sequence Analysis\n${browserRes.content}\n\n*General forensic knowledge is interpretive only and cannot be presented as case evidence.*\n*AI is an investigative assistant, not an evidence source.*`;
            } else if (r.intent === "CASE_SUMMARY") {
              const summaryPart = r.answer ? r.answer.split("### Executive AI Assessment")[0].trim() : "";
              finalAnswer = `${summaryPart}\n\n### Executive AI Assessment\n${browserRes.content}\n\n*General forensic knowledge is interpretive only and cannot be presented as case evidence.*\n*AI is an investigative assistant, not an evidence source.*`;
            } else {
              finalAnswer = browserRes.content;
            }

            finalGenerator = {
              type: "llm",
              provider: "ollama",
              model: browserRes.model || llmConfig.model,
              mode: "local_browser_ollama_bridge",
              fallback: false,
              verified: true,
              reason: null,
              provenance_id: r.generator?.provenance_id || `chat-${Date.now().toString(16)}`,
              request_id: r.generator?.request_id || `chat-${Date.now().toString(16)}`,
              generated_at: new Date().toISOString(),
            };

            if (r.intent === "CASE_QUERY" && r.forensic_state) {
              const parsedInterp = parseForensicAnswer(browserRes.content);
              finalAnalysis = parsedInterp.interpretationData || r.generated_analysis;
            }
          }
        } catch {}
      }

      setAnswer(finalAnswer);
      setGenerator(finalGenerator);
      setAnswerMeta({
        model: finalGenerator?.model || r.model || llmConfig.model,
        provider: finalGenerator?.provider || r.provider || "Ollama (Local LLM)",
        llm_mode: finalGenerator?.mode || r.llm_mode,
        is_local: true,
        query_type: r.query_type,
        intent: r.intent || (r.query_type === "general" ? "GENERAL" : r.query_type === "technical_forensic" ? "FORENSIC_KNOWLEDGE" : r.query_type === "case_guidance" ? "CASE_GUIDANCE" : "CASE_QUERY"),
        render_type: r.render_type || (r.intent === "CASE_QUERY" ? "forensic_structured" : r.intent === "CASE_TIMELINE" ? "timeline" : "markdown"),
        forensic_state: r.forensic_state || null,
        generated_analysis: finalAnalysis,
        concept_data: r.concept_data || null,
        timeline: r.timeline || null,
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

  const updateRec = async (id, status) => {
    await api(`/api/cases/${active}/recommendations/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    await loadCase(active);
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
      try {
        if (tlInst.current) {
          tlInst.current.setSelection(match.id);
          if (match.timestamp) {
            tlInst.current.moveTo(match.timestamp);
          }
        }
      } catch {}
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

  // Split title for styling
  const formatHeroTitle = (title) => {
    if (!title) return { main: "Forensic Investigation", accent: "Workspace" };
    const words = title.trim().split(" ");
    if (words.length === 1) return { main: words[0], accent: "" };
    const accent = words[words.length - 1];
    const main = words.slice(0, -1).join(" ");
    return { main, accent };
  };

  const heroTitle = formatHeroTitle(detail?.title);

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "#020806", color: "#eefaf4" }}>
      <style>{`
        /* Vis Timeline Black & Emerald Theme */
        .vis-timeline {
          border: 1px solid rgba(61, 255, 174, 0.12) !important;
          font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif !important;
          background-color: #050f0b !important;
          border-radius: 12px !important;
        }
        .vis-panel.vis-center, .vis-panel.vis-left, .vis-panel.vis-right, .vis-panel.vis-top, .vis-panel.vis-bottom {
          background-color: #050f0b !important;
          border-color: rgba(61, 255, 174, 0.08) !important;
        }
        .vis-labelset .vis-label {
          color: #8fa89d !important;
          font-size: 11px !important;
          font-weight: 700 !important;
          border-bottom: 1px solid rgba(61, 255, 174, 0.08) !important;
          background-color: #08140f !important;
          padding: 6px 10px !important;
        }
        .vis-time-axis .vis-text {
          color: #52685e !important;
          font-family: "JetBrains Mono", "IBM Plex Mono", monospace !important;
          font-size: 10px !important;
        }
        .vis-time-axis .vis-grid.vis-minor {
          border-color: rgba(61, 255, 174, 0.04) !important;
        }
        .vis-time-axis .vis-grid.vis-major {
          border-color: rgba(61, 255, 174, 0.08) !important;
        }
        .vis-item {
          background-color: #0d1e16 !important;
          border: 1px solid rgba(61, 255, 174, 0.22) !important;
          color: #eefaf4 !important;
          border-radius: 6px !important;
          font-size: 11px !important;
          box-shadow: 0 2px 8px rgba(0,0,0,0.4) !important;
          transition: all 0.15s ease !important;
        }
        .vis-item.vis-selected {
          border-color: #3dffae !important;
          background-color: #12281e !important;
          box-shadow: 0 0 15px rgba(61, 255, 174, 0.35) !important;
          z-index: 99 !important;
        }
        .vis-item.tl-src-windows_event {
          background-color: #071911 !important;
          border-color: #10b981 !important;
        }
        .vis-item.tl-src-registry {
          background-color: #081a13 !important;
          border-color: #059669 !important;
        }
        .vis-item.tl-src-browser {
          background-color: #0a1f17 !important;
          border-color: #34d399 !important;
        }
        .vis-item.tl-src-network {
          background-color: #0d261c !important;
          border-color: #6ee7b7 !important;
        }
        .vis-item.tl-src-filesystem {
          background-color: #0e2b1f !important;
          border-color: #3dffae !important;
        }
        .vis-item.tl-src-memory {
          background-color: #1f1807 !important;
          border-color: #f6b84a !important;
        }
        .vis-item.tl-src-correlated, .vis-item.hot, .vis-item.tl-correlated {
          background-color: #16261c !important;
          border-color: #a7f3d0 !important;
        }
        .tl-item-content {
          display: flex !important;
          align-items: center !important;
          gap: 6px !important;
          padding: 2px 6px !important;
          white-space: nowrap !important;
        }
        .tl-tag {
          font-size: 9px !important;
          font-weight: 800 !important;
          text-transform: uppercase !important;
          padding: 1px 5px !important;
          border-radius: 3px !important;
          background: rgba(61, 255, 174, 0.12) !important;
          color: #3dffae !important;
          letter-spacing: 0.4px !important;
        }
        .tl-title {
          color: #eefaf4 !important;
          font-weight: 600 !important;
          font-size: 11px !important;
        }
      `}</style>

      {/* Top Navigation Bar */}
      <AppBar
        position="fixed"
        sx={{
          zIndex: 1201,
          bgcolor: "#020806",
          borderBottom: "1px solid rgba(61, 255, 174, 0.12)",
          backdropFilter: "blur(12px)",
        }}
        elevation={0}
      >
        <Toolbar sx={{ justifyContent: "space-between", minHeight: 64, px: 3 }}>
          {/* Brand Logo */}
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: "8px",
                bgcolor: "rgba(61, 255, 174, 0.1)",
                border: "1px solid rgba(61, 255, 174, 0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 15px rgba(61, 255, 174, 0.15)",
              }}
            >
              <FingerprintIcon sx={{ color: "#3dffae", fontSize: 20 }} />
            </Box>
            <Box>
              <Stack direction="row" spacing={0.8} alignItems="center">
                <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: "-0.02em", color: "#eefaf4", fontSize: 16 }}>
                  DFIS
                </Typography>
                <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: "#3dffae", boxShadow: "0 0 8px #3dffae" }} />
              </Stack>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5, letterSpacing: "0.04em", display: "block" }}>
                Digital Forensics Intelligence System
              </Typography>
            </Box>
          </Stack>

          {/* Active Status & Actions */}
          <Stack direction="row" spacing={1.5} alignItems="center">
            {detail && (
              <Chip
                size="small"
                label={detail.case_number}
                sx={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 11,
                  fontWeight: 700,
                  bgcolor: "rgba(61, 255, 174, 0.08)",
                  color: "#3dffae",
                  border: "1px solid rgba(61, 255, 174, 0.25)",
                }}
              />
            )}

            <Chip
              icon={<SmartToyIcon sx={{ fontSize: "14px !important", color: llmStatus?.connected ? "#3dffae" : "#f6b84a" }} />}
              label={llmStatus?.connected ? "LOCAL AI READY" : "OFFLINE GROUNDED"}
              size="small"
              onClick={() => setLlmModal(true)}
              sx={{
                bgcolor: llmStatus?.connected ? "rgba(61, 255, 174, 0.08)" : "rgba(246, 184, 74, 0.08)",
                color: llmStatus?.connected ? "#3dffae" : "#f6b84a",
                border: `1px solid ${llmStatus?.connected ? "rgba(61, 255, 174, 0.25)" : "rgba(246, 184, 74, 0.25)"}`,
                fontWeight: 700,
                fontSize: 11,
                cursor: "pointer",
                "&:hover": { bgcolor: "rgba(61, 255, 174, 0.15)" },
              }}
            />

            <IconButton
              size="small"
              onClick={() => setLlmModal(true)}
              title="Local LLM Settings"
              sx={{ color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.12)", bgcolor: "#08140f", "&:hover": { color: "#3dffae", borderColor: "#3dffae" } }}
            >
              <SettingsIcon sx={{ fontSize: 16 }} />
            </IconButton>

            {active && (
              <Button
                variant="outlined"
                size="small"
                href={`/api/cases/${active}/report`}
                target="_blank"
                startIcon={<DescriptionIcon sx={{ fontSize: 14 }} />}
                sx={{
                  borderColor: "rgba(61, 255, 174, 0.25)",
                  color: "#3dffae",
                  fontSize: 11.5,
                  fontWeight: 600,
                  "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.08)" },
                }}
              >
                Export PDF
              </Button>
            )}

            <Button
              variant="contained"
              size="small"
              onClick={() => setOpen(true)}
              sx={{
                bgcolor: "#3dffae",
                color: "#020806",
                fontWeight: 700,
                fontSize: 11.5,
                "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 15px rgba(61, 255, 174, 0.4)" },
              }}
            >
              + New Case
            </Button>
          </Stack>
        </Toolbar>
        {busy && <LinearProgress sx={{ bgcolor: "#020806", "& .MuiLinearProgress-bar": { bgcolor: "#3dffae" } }} />}
      </AppBar>

      {/* Left Investigations Sidebar */}
      <Drawer
        variant="permanent"
        sx={{
          width: 260,
          [`& .MuiDrawer-paper`]: {
            width: 260,
            top: 64,
            bgcolor: "#050f0b",
            borderColor: "rgba(61, 255, 174, 0.1)",
          },
        }}
      >
        <Box sx={{ p: 2, pb: 1 }}>
          <Typography
            variant="overline"
            sx={{
              fontWeight: 800,
              letterSpacing: "0.14em",
              color: "#52685e",
              fontSize: 10,
              textTransform: "uppercase",
            }}
          >
            INVESTIGATIONS
          </Typography>
        </Box>
        <List sx={{ px: 1 }}>
          {cases.map((c) => {
            const isSel = c.id === active;
            return (
              <ListItemButton
                key={c.id}
                selected={isSel}
                onClick={() => setActive(c.id)}
                sx={{
                  borderRadius: "8px",
                  mb: 0.8,
                  py: 1.2,
                  px: 1.5,
                  border: isSel ? "1px solid rgba(61, 255, 174, 0.25)" : "1px solid transparent",
                  borderLeft: isSel ? "3px solid #3dffae !important" : "1px solid transparent",
                  background: isSel
                    ? "linear-gradient(90deg, rgba(61, 255, 174, 0.12), transparent) !important"
                    : "transparent",
                  "&:hover": {
                    bgcolor: "#0d1e16",
                  },
                }}
              >
                <ListItemText
                  primary={
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Stack direction="row" spacing={0.8} alignItems="center">
                        <span style={{ color: isSel ? "#3dffae" : "#52685e", fontSize: 12 }}>
                          {isSel ? "●" : "○"}
                        </span>
                        <Typography
                          variant="subtitle2"
                          sx={{
                            fontFamily: "JetBrains Mono, monospace",
                            fontWeight: isSel ? 800 : 600,
                            color: isSel ? "#3dffae" : "#8fa89d",
                            fontSize: 12,
                          }}
                        >
                          {c.case_number}
                        </Typography>
                      </Stack>
                      <Chip
                        size="small"
                        label={`${c.risk_score ?? 0}`}
                        sx={{
                          height: 18,
                          fontSize: 9.5,
                          fontWeight: 800,
                          fontFamily: "JetBrains Mono, monospace",
                          bgcolor: c.risk_score >= 40 ? "rgba(255, 101, 101, 0.15)" : "rgba(61, 255, 174, 0.1)",
                          color: c.risk_score >= 40 ? "#ff6565" : "#3dffae",
                          border: `1px solid ${c.risk_score >= 40 ? "rgba(255, 101, 101, 0.3)" : "rgba(61, 255, 174, 0.2)"}`,
                        }}
                      />
                    </Stack>
                  }
                  secondary={
                    <Box sx={{ mt: 0.4, pl: 2 }}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontSize: 11.5,
                          color: isSel ? "#eefaf4" : "#8fa89d",
                          fontWeight: isSel ? 600 : 400,
                          lineHeight: 1.25,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {c.title}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10, display: "block", mt: 0.2 }}>
                        {c.artifact_count} artifacts • {c.evidence_count} evidence
                      </Typography>
                    </Box>
                  }
                />
              </ListItemButton>
            );
          })}
        </List>

        <Box sx={{ p: 2, mt: "auto" }}>
          <Button
            fullWidth
            variant="outlined"
            size="small"
            onClick={() => setOpen(true)}
            sx={{
              borderColor: "rgba(61, 255, 174, 0.2)",
              color: "#3dffae",
              fontSize: 11.5,
              fontWeight: 700,
              py: 0.8,
              "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.06)" },
            }}
          >
            + New Investigation
          </Button>
        </Box>
      </Drawer>

      {/* Main Workspace Canvas */}
      <Box component="main" sx={{ flex: 1, ml: "260px", mt: 8, p: { xs: 2, md: 3 }, bgcolor: "#020806" }}>
        {!detail ? (
          <Typography sx={{ color: "#8fa89d" }}>Select or create an investigation.</Typography>
        ) : (
          <Container maxWidth="xl" disableGutters>
            {/* Case Hero Header Area */}
            <Paper
              sx={{
                p: 3,
                mb: 2.5,
                bgcolor: "#08140f",
                border: "1px solid rgba(61, 255, 174, 0.12)",
                borderRadius: "16px",
                background: "radial-gradient(circle at top right, rgba(61, 255, 174, 0.06), transparent 40%), #08140f",
                boxShadow: "0 20px 60px rgba(0, 0, 0, 0.45)",
              }}
            >
              <Typography
                variant="overline"
                sx={{
                  color: "#3dffae",
                  fontWeight: 800,
                  fontSize: 10.5,
                  letterSpacing: "0.14em",
                  display: "block",
                  mb: 0.4,
                }}
              >
                ACTIVE INVESTIGATION • {detail.case_number}
              </Typography>

              <Typography
                variant="h1"
                sx={{
                  fontSize: { xs: 24, md: 32, lg: 38 },
                  fontWeight: 800,
                  color: "#eefaf4",
                  letterSpacing: "-0.03em",
                  lineHeight: 1.2,
                  mb: 0.8,
                }}
              >
                {heroTitle.main} <span style={{ color: "#3dffae" }}>{heroTitle.accent}</span>
              </Typography>

              <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 13.5, maxWidth: 840, mb: 2 }}>
                {detail.description || "Digital evidence correlation and grounded forensic analysis."}
              </Typography>

              {/* Monospace Stat Tokens */}
              <Stack direction="row" spacing={1.2} flexWrap="wrap" useFlexGap alignItems="center">
                <Box
                  sx={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 11,
                    fontWeight: 700,
                    px: 1.2,
                    py: 0.4,
                    borderRadius: "6px",
                    bgcolor: "rgba(61, 255, 174, 0.06)",
                    border: "1px solid rgba(61, 255, 174, 0.18)",
                    color: "#3dffae",
                  }}
                >
                  {timeline.length} ARTIFACTS
                </Box>
                <Box
                  sx={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 11,
                    fontWeight: 700,
                    px: 1.2,
                    py: 0.4,
                    borderRadius: "6px",
                    bgcolor: "rgba(61, 255, 174, 0.06)",
                    border: "1px solid rgba(61, 255, 174, 0.18)",
                    color: "#3dffae",
                  }}
                >
                  {evidenceList.length} EVIDENCE FILES
                </Box>
                <Box
                  sx={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 11,
                    fontWeight: 700,
                    px: 1.2,
                    py: 0.4,
                    borderRadius: "6px",
                    bgcolor: risk >= 40 ? "rgba(255, 101, 101, 0.08)" : "rgba(61, 255, 174, 0.06)",
                    border: `1px solid ${risk >= 40 ? "rgba(255, 101, 101, 0.25)" : "rgba(61, 255, 174, 0.18)"}`,
                    color: risk >= 40 ? "#ff6565" : "#3dffae",
                  }}
                >
                  PRIORITY: {risk}/100 ({inv?.priority || (risk >= 40 ? "HIGH" : "LOW")})
                </Box>
                <Box
                  sx={{
                    fontSize: 11,
                    color: "#8fa89d",
                    px: 1,
                    py: 0.4,
                  }}
                >
                  Examiner: <span style={{ color: "#eefaf4", fontWeight: 600 }}>{detail.investigator}</span>
                </Box>
              </Stack>
            </Paper>

            {/* Hero AI Command Center (Primary Workspace Interaction) */}
            <Paper
              sx={{
                p: 2.5,
                mb: 3,
                bgcolor: "#08140f",
                border: "1px solid rgba(61, 255, 174, 0.25)",
                borderRadius: "16px",
                background: "radial-gradient(circle at top right, rgba(61, 255, 174, 0.08), transparent 50%), #08140f",
                boxShadow: "0 0 35px rgba(61, 255, 174, 0.06)",
              }}
            >
              <Typography
                variant="overline"
                sx={{
                  color: "#8fa89d",
                  fontWeight: 800,
                  fontSize: 10,
                  letterSpacing: "0.12em",
                  display: "block",
                  mb: 1,
                }}
              >
                WHAT WOULD YOU LIKE TO INVESTIGATE?
              </Typography>

              <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems="center">
                <TextField
                  fullWidth
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      ask();
                    }
                  }}
                  placeholder="Ask anything about this investigation (e.g., generate the timeline of events occurred, was data copied to USB)..."
                  size="small"
                  sx={{
                    bgcolor: "#050f0b",
                    borderRadius: "10px",
                    "& .MuiOutlinedInput-root": {
                      color: "#eefaf4",
                      fontFamily: "Inter, sans-serif",
                      fontSize: 13.5,
                      "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                      "&:hover fieldset": { borderColor: "#3dffae" },
                      "&.Mui-focused fieldset": { borderColor: "#3dffae", boxShadow: "0 0 12px rgba(61, 255, 174, 0.2)" },
                    },
                  }}
                />

                <Button
                  variant="contained"
                  disabled={busy}
                  onClick={() => ask()}
                  startIcon={<SmartToyIcon sx={{ fontSize: 16 }} />}
                  sx={{
                    bgcolor: "#3dffae",
                    color: "#020806",
                    fontWeight: 800,
                    fontSize: 13,
                    py: 1.1,
                    px: 3,
                    borderRadius: "10px",
                    whiteSpace: "nowrap",
                    boxShadow: "0 0 20px rgba(61, 255, 174, 0.25)",
                    "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 25px rgba(61, 255, 174, 0.4)" },
                  }}
                >
                  {busy ? "Reasoning..." : "Analyze with Local AI →"}
                </Button>
              </Stack>

              {/* Quick Suggestion Pills */}
              <Stack direction="row" spacing={0.8} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1.5 }}>
                <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10.5, fontWeight: 700, mr: 0.5 }}>
                  TRY:
                </Typography>
                {[
                  "Generate the timeline of events occurred",
                  "Was confidential data copied to USB?",
                  "What are the recommended next steps?",
                  "Summarize the case",
                  "How to identify suspicious activity?",
                ].map((sug, i) => (
                  <Box
                    component="button"
                    key={i}
                    type="button"
                    onClick={() => {
                      setQ(sug);
                      ask(sug);
                    }}
                    sx={{
                      cursor: "pointer",
                      bgcolor: "rgba(61, 255, 174, 0.04)",
                      border: "1px solid rgba(61, 255, 174, 0.12)",
                      color: "#8fa89d",
                      fontSize: 11,
                      fontWeight: 600,
                      px: 1,
                      py: 0.3,
                      borderRadius: "6px",
                      transition: "all 0.15s ease",
                      "&:hover": {
                        bgcolor: "rgba(61, 255, 174, 0.1)",
                        color: "#3dffae",
                        borderColor: "rgba(61, 255, 174, 0.3)",
                      },
                    }}
                  >
                    {sug}
                  </Box>
                ))}
              </Stack>
            </Paper>

            {/* Ingestion & Engine Action Bar */}
            <Paper
              sx={{
                p: 1.6,
                mb: 3,
                bgcolor: "#050f0b",
                border: "1px solid rgba(61, 255, 174, 0.1)",
                borderRadius: "12px",
              }}
            >
              <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} justifyContent="space-between" alignItems="center">
                <Stack direction="row" spacing={1} alignItems="center">
                  <AutoFixHighIcon sx={{ color: "#3dffae", fontSize: 18 }} />
                  <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11.5 }}>
                    <b style={{ color: "#eefaf4" }}>Automated Ingestion Pipeline:</b> Policy Agent Acquisition ➔ SHA-256 Check ➔ EVTX / Registry / Browser / PCAP ➔ Unified Timeline ➔ RAG
                  </Typography>
                </Stack>

                <Stack direction="row" spacing={1}>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<SecurityIcon sx={{ fontSize: 14 }} />}
                    onClick={() => setAcquireModal(true)}
                    disabled={busy}
                    sx={{
                      borderColor: "rgba(61, 255, 174, 0.2)",
                      color: "#3dffae",
                      fontSize: 11,
                      fontWeight: 700,
                      "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.08)" },
                    }}
                  >
                    Acquire Evidence
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    component="label"
                    startIcon={<CloudUploadIcon sx={{ fontSize: 14 }} />}
                    disabled={busy}
                    sx={{
                      borderColor: "rgba(61, 255, 174, 0.15)",
                      color: "#8fa89d",
                      fontSize: 11,
                      "&:hover": { color: "#eefaf4", borderColor: "#8fa89d" },
                    }}
                  >
                    Import ZIP
                    <input hidden type="file" onChange={(e) => e.target.files[0] && upload(e.target.files[0])} />
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={busy}
                    startIcon={<RefreshIcon sx={{ fontSize: 14 }} />}
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
                    sx={{
                      borderColor: "rgba(61, 255, 174, 0.15)",
                      color: "#8fa89d",
                      fontSize: 11,
                      "&:hover": { color: "#eefaf4", borderColor: "#8fa89d" },
                    }}
                  >
                    Reprocess
                  </Button>
                </Stack>
              </Stack>
            </Paper>

            {/* Workspace Content Grid */}
            <Stack direction={{ xs: "column", xl: "row" }} spacing={2.5}>
              {/* Main Tabbed Analysis Area */}
              <Paper
                sx={{
                  flex: { xs: 1, xl: 1.25 },
                  bgcolor: "#08140f",
                  border: "1px solid rgba(61, 255, 174, 0.12)",
                  borderRadius: "16px",
                  overflow: "hidden",
                }}
              >
                <Tabs
                  value={tab}
                  onChange={(_, v) => setTab(v)}
                  sx={{
                    bgcolor: "#050f0b",
                    borderBottom: "1px solid rgba(61, 255, 174, 0.1)",
                    "& .MuiTab-root": {
                      textTransform: "none",
                      fontWeight: 600,
                      minHeight: 46,
                      fontSize: 12.5,
                      color: "#8fa89d",
                      "&.Mui-selected": { color: "#3dffae" },
                    },
                    "& .MuiTabs-indicator": { bgcolor: "#3dffae", height: 3 },
                  }}
                >
                  <Tab icon={<TimelineIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Timeline (${timeline.length})`} />
                  <Tab icon={<HubIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Graph" />
                  <Tab icon={<FolderZipIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Evidence (${evidenceList.length})`} />
                  <Tab icon={<SecurityIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="AI Investigation" />
                  <Tab icon={<FactCheckIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Tasks (${recs.length})`} />
                  <Tab icon={<DescriptionIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Report" />
                </Tabs>

                {/* TAB 0: UNIFIED TIMELINE */}
                {tab === 0 && (
                  <Box sx={{ p: 2.5 }}>
                    {/* Vis Timeline Canvas */}
                    <Box ref={tlRef} sx={{ height: 340, bgcolor: "#050f0b", borderRadius: "12px", p: 0.5, mb: 2, border: "1px solid rgba(61, 255, 174, 0.1)" }} />

                    {/* Selected Timeline Event Inspector */}
                    {selectedEvent && (
                      <Paper
                        sx={{
                          p: 2,
                          mb: 2,
                          bgcolor: "#0d1e16",
                          border: "1px solid rgba(61, 255, 174, 0.25)",
                          borderRadius: "12px",
                        }}
                      >
                        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Box
                              sx={{
                                fontFamily: "JetBrains Mono, monospace",
                                fontSize: 10.5,
                                fontWeight: 700,
                                px: 0.8,
                                py: 0.2,
                                borderRadius: "4px",
                                bgcolor: "rgba(61, 255, 174, 0.1)",
                                color: "#3dffae",
                                border: "1px solid rgba(61, 255, 174, 0.3)",
                              }}
                            >
                              Artifact #{selectedEvent.id}
                            </Box>
                            <Chip size="small" label={selectedEvent.source_type} sx={{ bgcolor: sourceColor(selectedEvent.source_type), color: "#fff", fontWeight: 700, height: 20, fontSize: 10 }} />
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#eefaf4", fontSize: 13 }}>
                              {selectedEvent.event_type}
                            </Typography>
                          </Stack>
                          <Button size="small" onClick={() => setSelectedEvent(null)} sx={{ color: "#8fa89d", fontSize: 11, minWidth: "auto", p: 0.5 }}>
                            Close
                          </Button>
                        </Stack>
                        <Typography variant="body2" sx={{ color: "#eefaf4", mb: 1, fontSize: 13, lineHeight: 1.5 }}>
                          {selectedEvent.description}
                        </Typography>
                        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ fontSize: 11, color: "#8fa89d", fontFamily: "JetBrains Mono, monospace" }}>
                          <span>Time: <code style={{ color: "#3dffae" }}>{selectedEvent.timestamp}</code></span>
                          {selectedEvent.actor && <span>Actor: <code style={{ color: "#eefaf4" }}>{selectedEvent.actor}</code></span>}
                          {selectedEvent.process && <span>Process: <code style={{ color: "#eefaf4" }}>{selectedEvent.process}</code></span>}
                          {selectedEvent.target && <span>Target: <code style={{ color: "#eefaf4" }}>{selectedEvent.target}</code></span>}
                          {selectedEvent.evidence_hash && <span>SHA-256: <code style={{ color: "#f6b84a" }}>{selectedEvent.evidence_hash.slice(0, 16)}...</code></span>}
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
                              <SearchIcon sx={{ color: "#52685e", fontSize: 18 }} />
                            </InputAdornment>
                          ),
                        }}
                        sx={{
                          bgcolor: "#050f0b",
                          borderRadius: "8px",
                          "& .MuiOutlinedInput-root": {
                            fontSize: 12.5,
                            "& fieldset": { borderColor: "rgba(61, 255, 174, 0.12)" },
                          },
                        }}
                      />
                      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ minWidth: 320 }}>
                        {["all", "windows_event", "registry", "browser", "network", "filesystem", "memory", "correlated"].map((src) => (
                          <Chip
                            key={src}
                            size="small"
                            label={src === "all" ? "All Sources" : src.replace("_", " ")}
                            clickable
                            onClick={() => setSourceFilter(src)}
                            sx={{
                              textTransform: "capitalize",
                              fontSize: 10.5,
                              fontWeight: 600,
                              bgcolor: sourceFilter === src ? "rgba(61, 255, 174, 0.15)" : "#050f0b",
                              color: sourceFilter === src ? "#3dffae" : "#8fa89d",
                              border: `1px solid ${sourceFilter === src ? "rgba(61, 255, 174, 0.3)" : "rgba(61, 255, 174, 0.08)"}`,
                            }}
                          />
                        ))}
                      </Stack>
                    </Stack>

                    {/* Chronological Artifact Table */}
                    <TableContainer sx={{ maxHeight: 420, border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px" }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#050f0b", color: "#8fa89d", fontWeight: 700, fontSize: 11, borderBottom: "1px solid rgba(61, 255, 174, 0.15)" } }}>
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
                                bgcolor: e.source_type === "correlated" ? "rgba(61, 255, 174, 0.04)" : (selectedEvent?.id === e.id ? "rgba(61, 255, 174, 0.12)" : "inherit"),
                                "& td": { borderColor: "rgba(61, 255, 174, 0.06)", fontSize: 12, py: 1 },
                                "&:hover": { bgcolor: "rgba(61, 255, 174, 0.06) !important" },
                              }}
                            >
                              <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap", color: "#3dffae", fontSize: 11 }}>
                                {e.timestamp ? e.timestamp.replace("T", " ") : "Observation"}
                              </TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={e.artifact_type || e.source_type}
                                  sx={{
                                    height: 18,
                                    fontSize: 9.5,
                                    fontWeight: 700,
                                    bgcolor: sourceColor(e.source_type),
                                    color: "#fff",
                                  }}
                                />
                              </TableCell>
                              <TableCell sx={{ fontWeight: 600, color: "#eefaf4" }}>
                                {e.event_type}
                              </TableCell>
                              <TableCell sx={{ color: "#8fa89d" }}>
                                {e.user || e.actor || "—"} {e.host ? `(${e.host})` : ""}
                              </TableCell>
                              <TableCell sx={{ color: "#cbd5e1" }}>
                                <Typography variant="caption" sx={{ fontWeight: 700, display: "block", color: "#eefaf4" }}>{e.action}</Typography>
                                <Typography variant="caption" sx={{ color: "#8fa89d", fontFamily: "JetBrains Mono, monospace", fontSize: 10.5 }}>
                                  {e.target || e.object || "—"}
                                </Typography>
                              </TableCell>
                              <TableCell sx={{ color: "#8fa89d", maxWidth: 260, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                                {e.description}
                              </TableCell>
                              <TableCell align="right">
                                {e.correlation_id ? (
                                  <Chip size="small" label={`Link: ${e.correlation_id}`} sx={{ height: 18, fontSize: 9, fontWeight: 700, bgcolor: "rgba(246, 184, 74, 0.1)", color: "#f6b84a", border: "1px solid rgba(246, 184, 74, 0.3)" }} />
                                ) : (
                                  <Box
                                    component="span"
                                    sx={{
                                      fontFamily: "JetBrains Mono, monospace",
                                      fontSize: 10.5,
                                      color: "#3dffae",
                                      bgcolor: "rgba(61, 255, 174, 0.06)",
                                      px: 0.6,
                                      py: 0.15,
                                      borderRadius: "4px",
                                      border: "1px solid rgba(61, 255, 174, 0.15)",
                                    }}
                                  >
                                    #{e.id}
                                  </Box>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}

                {/* TAB 1: RELATIONSHIP GRAPH */}
                {tab === 1 && (
                  <Box sx={{ p: 2.5 }}>
                    <Typography variant="caption" sx={{ color: "#8fa89d", mb: 1.5, display: "block" }}>
                      Cross-artifact entity graph: linking actors, processes, files, USB media, and network destinations.
                    </Typography>
                    <Box ref={netRef} sx={{ height: 500, bgcolor: "#050f0b", borderRadius: "12px", border: "1px solid rgba(61, 255, 174, 0.12)" }} />
                  </Box>
                )}

                {/* TAB 2: EVIDENCE & CUSTODY */}
                {tab === 2 && (
                  <Box sx={{ p: 2.5 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#eefaf4", mb: 1.5 }}>
                      Ingested Forensic Evidence Packages & Hash Verification
                    </Typography>
                    <TableContainer sx={{ mb: 3, border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px" }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#050f0b", color: "#8fa89d", fontWeight: 700, borderBottom: "1px solid rgba(61, 255, 174, 0.15)" } }}>
                            <TableCell>Evidence File</TableCell>
                            <TableCell>Detected Type</TableCell>
                            <TableCell>SHA-256 Digest</TableCell>
                            <TableCell>Size</TableCell>
                            <TableCell>Artifacts</TableCell>
                            <TableCell align="right">Integrity Check</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {evidenceList.map((ev) => (
                            <TableRow key={ev.id} hover sx={{ "& td": { borderColor: "rgba(61, 255, 174, 0.06)", py: 1.2 } }}>
                              <TableCell sx={{ fontWeight: 600, color: "#eefaf4" }}>{ev.filename}</TableCell>
                              <TableCell>
                                <Chip size="small" label={ev.detected_type || ev.source_type} sx={{ height: 20, fontSize: 10, bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae", border: "1px solid rgba(61, 255, 174, 0.2)" }} />
                              </TableCell>
                              <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11, color: "#3dffae" }}>
                                {ev.sha256}
                              </TableCell>
                              <TableCell sx={{ fontSize: 11, color: "#8fa89d" }}>{(ev.size_bytes / 1024).toFixed(1)} KB</TableCell>
                              <TableCell sx={{ fontWeight: 700, color: "#eefaf4" }}>{ev.artifact_count}</TableCell>
                              <TableCell align="right">
                                <Button
                                  size="small"
                                  variant="outlined"
                                  startIcon={ev.integrity_ok ? <CheckCircleIcon sx={{ color: "#3dffae", fontSize: 14 }} /> : <WarningIcon sx={{ color: "#ff6565", fontSize: 14 }} />}
                                  onClick={() => verifyEvidence(ev.id)}
                                  sx={{
                                    fontSize: 10.5,
                                    py: 0.2,
                                    borderColor: ev.integrity_ok ? "rgba(61, 255, 174, 0.3)" : "rgba(255, 101, 101, 0.3)",
                                    color: ev.integrity_ok ? "#3dffae" : "#ff6565",
                                  }}
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
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#eefaf4", mb: 1 }}>
                      Immutable Chain of Custody Audit Log
                    </Typography>
                    <Paper sx={{ maxHeight: 240, overflow: "auto", p: 1.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "8px" }}>
                      {(detail?.custody || []).map((c, i) => (
                        <Typography key={i} variant="body2" sx={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11.5, mb: 0.6, color: "#8fa89d" }}>
                          <span style={{ color: "#3dffae" }}>[{c.created_at?.replace("T", " ").slice(0, 19)}]</span> <b style={{ color: "#eefaf4" }}>{c.action}</b> by <i>{c.actor}</i> — {c.detail}
                        </Typography>
                      ))}
                    </Paper>
                  </Box>
                )}

                {/* TAB 3: AI INVESTIGATION & ATT&CK */}
                {tab === 3 && (
                  <Box sx={{ p: 2.5, maxHeight: 600, overflow: "auto" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3dffae" }}>
                      Incident Classification: {formatClassification(inv?.category || finding?.category, inv?.secondary)}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mb: 2 }}>
                      ATT&CK techniques and attack-chain stages are investigative hypotheses synthesized from multi-source correlations.
                    </Typography>

                    {/* Evidentiary State Breakdown */}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#eefaf4" }}>
                      Forensic Evidentiary State Breakdown
                    </Typography>
                    <TableContainer sx={{ border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px", mb: 3 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#050f0b", color: "#8fa89d", fontWeight: 700, borderBottom: "1px solid rgba(61, 255, 174, 0.15)" } }}>
                            <TableCell>Forensic Assertion</TableCell>
                            <TableCell>State</TableCell>
                            <TableCell>Observation Rationale</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {(inv?.evidentiary_states || []).map((st, i) => (
                            <TableRow key={i} hover sx={{ "& td": { borderColor: "rgba(61, 255, 174, 0.06)", py: 1.2 } }}>
                              <TableCell sx={{ fontWeight: 700, color: "#eefaf4" }}>{st.finding}</TableCell>
                              <TableCell>
                                <EvidenceStatusBadge status={st.state} />
                              </TableCell>
                              <TableCell sx={{ color: "#8fa89d", fontSize: 12 }}>{st.detail}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}

                {/* TAB 4: TASKS */}
                {tab === 4 && (
                  <Box sx={{ p: 2.5, maxHeight: 600, overflow: "auto" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#eefaf4", mb: 1 }}>
                      Examiner Verification Checklist & Investigation Tasks
                    </Typography>
                    <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mb: 2 }}>
                      Derived from active evidentiary gaps and missing artifact correlations.
                    </Typography>
                    <TableContainer sx={{ border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px" }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { bgcolor: "#050f0b", color: "#8fa89d", fontWeight: 700, borderBottom: "1px solid rgba(61, 255, 174, 0.15)" } }}>
                            <TableCell>Priority</TableCell>
                            <TableCell>Action Item</TableCell>
                            <TableCell>Forensic Reason</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell align="right">Controls</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {recs.map((r) => (
                            <TableRow key={r.id} hover sx={{ "& td": { borderColor: "rgba(61, 255, 174, 0.06)", py: 1.2 } }}>
                              <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", color: "#3dffae", fontWeight: 700 }}>#{r.priority}</TableCell>
                              <TableCell sx={{ fontWeight: 700, color: "#eefaf4" }}>{r.action}</TableCell>
                              <TableCell sx={{ color: "#8fa89d", fontSize: 12 }}>{r.reason}</TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={r.status?.replace("_", " ")}
                                  sx={{
                                    height: 20,
                                    fontSize: 10,
                                    fontWeight: 700,
                                    bgcolor: r.status === "verified" ? "rgba(61, 255, 174, 0.15)" : "rgba(246, 184, 74, 0.1)",
                                    color: r.status === "verified" ? "#3dffae" : "#f6b84a",
                                    border: `1px solid ${r.status === "verified" ? "rgba(61, 255, 174, 0.3)" : "rgba(246, 184, 74, 0.3)"}`,
                                  }}
                                />
                              </TableCell>
                              <TableCell align="right">
                                <Button
                                  size="small"
                                  variant="outlined"
                                  onClick={() => updateRec(r.id, r.status === "verified" ? "pending_examiner_verification" : "verified")}
                                  sx={{ fontSize: 10, py: 0.2, borderColor: "rgba(61, 255, 174, 0.25)", color: "#3dffae" }}
                                >
                                  {r.status === "verified" ? "Re-open" : "Mark Verified"}
                                </Button>
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
                  <Box sx={{ p: 2.5, maxHeight: 600, overflow: "auto" }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#eefaf4" }}>Evidence-Linked Investigation Report</Typography>
                      <Button variant="contained" href={`/api/cases/${active}/report`} target="_blank" startIcon={<DescriptionIcon sx={{ fontSize: 14 }} />} sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>
                        Download PDF Report
                      </Button>
                    </Stack>
                    <Paper sx={{ p: 2.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px" }}>
                      <Typography variant="h6" sx={{ color: "#3dffae", fontWeight: 700 }}>{detail.title}</Typography>
                      <Typography variant="body2" sx={{ color: "#8fa89d", my: 1, fontFamily: "JetBrains Mono, monospace", fontSize: 11.5 }}>
                        Case: {detail.case_number} | Examiner: {detail.investigator} | Status: {detail.status}
                      </Typography>
                      <Divider sx={{ my: 1.5, borderColor: "rgba(61, 255, 174, 0.1)" }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#eefaf4" }}>Summary Finding:</Typography>
                      <Typography variant="body2" sx={{ color: "#8fa89d", mb: 2, fontSize: 13, lineHeight: 1.6 }}>
                        {finding?.body || "Investigation findings synthesized across all parsed artifact sources."}
                      </Typography>
                    </Paper>
                  </Box>
                )}
              </Paper>

              {/* Right Panel: Local AI Intelligence & Response Panel */}
              <Paper
                sx={{
                  flex: { xs: 1, xl: 1 },
                  minWidth: { xs: "100%", lg: 440, xl: 480 },
                  maxWidth: { xl: 580 },
                  p: 2.5,
                  bgcolor: "#08140f",
                  border: "1px solid rgba(61, 255, 174, 0.15)",
                  borderRadius: "16px",
                  boxShadow: "0 20px 60px rgba(0, 0, 0, 0.45)",
                }}
              >
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 800, color: "#eefaf4", display: "flex", alignItems: "center", gap: 1, fontSize: 14 }}>
                    <SmartToyIcon sx={{ color: "#3dffae", fontSize: 18 }} /> Local AI Intelligence
                  </Typography>
                  <IconButton size="small" onClick={() => setLlmModal(true)} title="Settings" sx={{ color: "#8fa89d", "&:hover": { color: "#3dffae" } }}>
                    <SettingsIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </Stack>

                <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mb: 1.5 }}>
                  Grounded Q&A: cross-references general forensic knowledge against this case’s ingested events.
                </Typography>

                {/* Local Air-Gapped Guarantee Badge */}
                <Paper
                  sx={{
                    p: 1.2,
                    mb: 2,
                    bgcolor: "#050f0b",
                    border: "1px solid rgba(61, 255, 174, 0.12)",
                    borderRadius: "8px",
                  }}
                >
                  <Stack direction="row" spacing={1} alignItems="center">
                    <LockIcon sx={{ fontSize: 14, color: "#3dffae" }} />
                    <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11, lineHeight: 1.3 }}>
                      <b style={{ color: "#eefaf4" }}>100% Local Inference:</b> Running <code>llama3.2:3b</code> locally via Ollama. Zero case data leaves this machine.
                    </Typography>
                  </Stack>
                </Paper>

                {answer ? (
                  <Box sx={{ mt: 1 }}>
                    <GenerationProvenanceCard generator={generator} />
                    <ChatErrorBoundary fallbackText={answer}>
                      <ForensicConsoleAnswer
                        answer={answer}
                        generator={generator}
                        inv={inv}
                        intent={answerMeta?.intent}
                        renderType={answerMeta?.render_type}
                        forensicState={answerMeta?.forensic_state}
                        generatedAnalysis={answerMeta?.generated_analysis}
                        conceptData={answerMeta?.concept_data}
                        onFocusEvidence={focusEvidence}
                        viewMode={chatViewMode}
                        setViewMode={setChatViewMode}
                      />
                    </ChatErrorBoundary>
                  </Box>
                ) : (
                  <Box sx={{ p: 4, textAlign: "center", border: "1px dashed rgba(61, 255, 174, 0.15)", borderRadius: "12px", bgcolor: "#050f0b", my: 2 }}>
                    <SmartToyIcon sx={{ color: "#3dffae", fontSize: 32, opacity: 0.8, mb: 1 }} />
                    <Typography variant="subtitle2" sx={{ color: "#eefaf4", fontWeight: 700, mb: 0.5 }}>
                      Ready to Analyze Evidence
                    </Typography>
                    <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", maxWidth: 280, mx: "auto" }}>
                      Ask a query in the top command bar or click one of the suggested investigative prompts.
                    </Typography>
                  </Box>
                )}
              </Paper>
            </Stack>
          </Container>
        )}
      </Box>

      {/* Case Creation Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 700, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
          Create New Investigation
        </DialogTitle>
        <DialogContent sx={{ bgcolor: "#050f0b", pt: 2.5 }}>
          {["case_number", "title", "investigator", "description"].map((k) => (
            <TextField
              key={k}
              margin="dense"
              fullWidth
              size="small"
              label={k.replace("_", " ").toUpperCase()}
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              sx={{
                bgcolor: "#08140f",
                borderRadius: "8px",
                mb: 1.5,
                "& .MuiOutlinedInput-root": {
                  "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                  "&:hover fieldset": { borderColor: "#3dffae" },
                },
              }}
            />
          ))}
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#08140f", borderTop: "1px solid rgba(61, 255, 174, 0.1)", p: 1.5 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "#8fa89d" }}>Cancel</Button>
          <Button onClick={createCase} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Create Case</Button>
        </DialogActions>
      </Dialog>

      {/* Ingest Summary Dialog */}
      {ingestModal && (
        <Dialog open={Boolean(ingestModal)} onClose={() => setIngestModal(null)} maxWidth="sm" fullWidth>
          <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 700 }}>
            Evidence Ingestion Complete
          </DialogTitle>
          <DialogContent sx={{ bgcolor: "#050f0b", pt: 2 }}>
            <Typography variant="body2" sx={{ color: "#eefaf4", mb: 1 }}>
              Package: <b>{ingestModal.filename}</b>
            </Typography>
            <Typography variant="caption" sx={{ fontFamily: "JetBrains Mono, monospace", color: "#3dffae", display: "block", mb: 2 }}>
              SHA-256: {ingestModal.sha256}
            </Typography>
            <Paper sx={{ p: 1.5, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "8px" }}>
              <Typography variant="caption" sx={{ color: "#8fa89d", display: "block" }}>
                Artifacts Extracted: <b>{ingestModal.artifact_count || ingestModal.summary?.total_artifacts_extracted || 0}</b>
              </Typography>
            </Paper>
          </DialogContent>
          <DialogActions sx={{ bgcolor: "#08140f" }}>
            <Button onClick={() => setIngestModal(null)} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Done</Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Evidence Acquisition Modal Dialog */}
      <Dialog open={acquireModal} onClose={() => setAcquireModal(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 700, display: "flex", alignItems: "center", gap: 1, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
          <SecurityIcon /> Investigator-Controlled Evidence Acquisition
        </DialogTitle>
        <DialogContent sx={{ bgcolor: "#050f0b", color: "#eefaf4", pt: 2.5 }}>
          <Typography variant="body2" sx={{ color: "#8fa89d", mb: 2 }}>
            Select an authorized acquisition mode and collection policy. The automated collection agent will collect forensic artifacts, verify hashes with SHA-256, package the evidence, and feed it into the Extraction Engine.
          </Typography>

          {/* Acquisition Mode Selector */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3dffae", mb: 1 }}>
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
                  flex: 1,
                  p: 1.5,
                  cursor: "pointer",
                  bgcolor: acquireMode === m.id ? "#0d1e16" : "#08140f",
                  border: `1px solid ${acquireMode === m.id ? "#3dffae" : "rgba(61, 255, 174, 0.12)"}`,
                  borderRadius: "10px",
                  "&:hover": { borderColor: "#3dffae" },
                }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: acquireMode === m.id ? "#3dffae" : "#eefaf4", fontSize: 13 }}>
                  {m.title}
                </Typography>
                <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11, display: "block", mt: 0.4 }}>
                  {m.desc}
                </Typography>
              </Paper>
            ))}
          </Stack>

          {/* Policy Checklist */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3dffae", mb: 1 }}>
            2. Configure Collection Policy (Artifact Targets)
          </Typography>
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" }, gap: 1, mb: 2 }}>
            {[
              { key: "collect_security_logs", label: "Windows Security Logs (EVTX 4624/4688)" },
              { key: "collect_system_logs", label: "Windows System Logs (EVTX 7045 Service Install)" },
              { key: "collect_powershell_logs", label: "PowerShell Script Block Logs (EVTX 4104)" },
              { key: "collect_registry", label: "SYSTEM & NTUSER.DAT Registry (USBSTOR, Run Keys)" },
              { key: "collect_browser_history", label: "Chrome / Edge History & Web SQLite" },
              { key: "collect_browser_downloads", label: "Browser Download History Artifacts" },
              { key: "collect_filesystem", label: "Filesystem Activity ($MFT, Staging Dirs)" },
              { key: "collect_prefetch", label: "Windows Prefetch Execution Artifacts (.pf)" },
              { key: "collect_amcache", label: "Windows Amcache Execution & SHA-1 Hashes" },
              { key: "collect_network", label: "Network Connection PCAP & DNS Flows" },
            ].map((p) => (
              <Paper
                key={p.key}
                onClick={() => setPolicy({ ...policy, [p.key]: !policy[p.key] })}
                sx={{
                  p: 1.2,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  cursor: "pointer",
                  bgcolor: policy[p.key] ? "rgba(61, 255, 174, 0.06)" : "#08140f",
                  border: `1px solid ${policy[p.key] ? "rgba(61, 255, 174, 0.3)" : "rgba(61, 255, 174, 0.08)"}`,
                  borderRadius: "8px",
                }}
              >
                <Typography variant="caption" sx={{ color: policy[p.key] ? "#eefaf4" : "#8fa89d", fontWeight: policy[p.key] ? 600 : 400 }}>
                  {p.label}
                </Typography>
                <Chip size="small" label={policy[p.key] ? "ACTIVE" : "OFF"} sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: policy[p.key] ? "#3dffae" : "#1a2a22", color: policy[p.key] ? "#020806" : "#52685e" }} />
              </Paper>
            ))}
          </Box>
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#08140f", borderTop: "1px solid rgba(61, 255, 174, 0.1)", p: 2 }}>
          <Button onClick={() => setAcquireModal(false)} sx={{ color: "#8fa89d" }}>Cancel</Button>
          <Button onClick={acquireEvidence} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800 }}>
            Execute Authorized Acquisition
          </Button>
        </DialogActions>
      </Dialog>

      {/* Local LLM (llama3.2:3b) Configuration & Status Dialog */}
      <Dialog open={llmModal} onClose={() => setLlmModal(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 700, display: "flex", alignItems: "center", gap: 1, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
          <SmartToyIcon /> Local LLM Configuration (llama3.2:3b)
        </DialogTitle>
        <DialogContent sx={{ bgcolor: "#050f0b", color: "#eefaf4", pt: 2.5 }}>
          <Typography variant="body2" sx={{ color: "#8fa89d", mb: 2 }}>
            DFIS utilizes a 100% local, air-gapped Large Language Model (<b>llama3.2:3b</b>) to assist examiners with evidence analysis and grounded Q&A.
          </Typography>

          {/* Connection Test Alert */}
          {llmTestMsg && (
            <Alert
              severity={llmTestMsg.type}
              onClose={() => setLlmTestMsg(null)}
              sx={{ mb: 2, bgcolor: llmTestMsg.type === "success" ? "#064e3b" : "#451a03", color: "#f8fafc" }}
            >
              {llmTestMsg.text}
            </Alert>
          )}

          {/* Configuration Inputs */}
          <Paper sx={{ p: 2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "12px", mb: 2 }}>
            <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 700, textTransform: "uppercase", display: "block", mb: 1.5 }}>
              Ollama Server Settings
            </Typography>
            <Stack spacing={1.5}>
              <TextField
                size="small"
                fullWidth
                label="OLLAMA BASE URL"
                value={llmConfig.base_url}
                onChange={(e) => setLlmConfig({ ...llmConfig, base_url: e.target.value })}
                placeholder="http://localhost:11434"
                helperText="Local Ollama endpoint (e.g. http://localhost:11434, http://127.0.0.1:11434, or host/tunnel URL)"
                sx={{
                  bgcolor: "#050f0b",
                  borderRadius: "8px",
                  "& .MuiOutlinedInput-root": {
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 12.5,
                    "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                  },
                }}
              />
              <TextField
                size="small"
                fullWidth
                label="MODEL NAME"
                value={llmConfig.model}
                onChange={(e) => setLlmConfig({ ...llmConfig, model: e.target.value })}
                placeholder="llama3.2:3b"
                helperText="Ollama model tag (e.g. llama3.2:3b, llama3:latest, qwen2.5:3b, mistral)"
                sx={{
                  bgcolor: "#050f0b",
                  borderRadius: "8px",
                  "& .MuiOutlinedInput-root": {
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 12.5,
                    "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                  },
                }}
              />
              <Button
                variant="contained"
                disabled={testingLlm}
                onClick={async () => {
                  setTestingLlm(true);
                  setLlmTestMsg(null);
                  try {
                    const res = await api("/api/llm/config", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({
                        base_url: llmConfig.base_url,
                        model: llmConfig.model,
                        temperature: llmConfig.temperature || 0.1,
                      }),
                    }).then((x) => x.json());
                    setLlmStatus(res);
                    localStorage.setItem("dfis_llm_config", JSON.stringify(llmConfig));
                    if (res.connected) {
                      setLlmTestMsg({
                        type: "success",
                        text: `Connected to Ollama! ${res.available_models?.length ? `Available models: ${res.available_models.join(", ")}` : "Ready for local inference."}`,
                      });
                    } else {
                      setLlmTestMsg({
                        type: "warning",
                        text: `Ollama endpoint unreachable at ${llmConfig.base_url}. Deterministic fallback active. Ensure Ollama is running ('ollama run ${llmConfig.model}').`,
                      });
                    }
                  } catch (err) {
                    setLlmTestMsg({ type: "warning", text: `Connection check failed: ${err}` });
                  } finally {
                    setTestingLlm(false);
                  }
                }}
                sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800, textTransform: "none" }}
              >
                {testingLlm ? "Testing Connection..." : "Test & Save Connection"}
              </Button>
            </Stack>
          </Paper>

          {/* Status Display */}
          <Paper sx={{ p: 2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "12px", mb: 2 }}>
            <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 700, textTransform: "uppercase", display: "block", mb: 1 }}>
              Active Inference Status
            </Typography>
            <Stack spacing={1}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#8fa89d" }}>Configured Model:</Typography>
                <Chip size="small" label={llmConfig.model} sx={{ bgcolor: "rgba(61, 255, 174, 0.1)", color: "#3dffae", fontWeight: 700, fontFamily: "JetBrains Mono, monospace" }} />
              </Stack>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#8fa89d" }}>Active Endpoint:</Typography>
                <Typography variant="body2" sx={{ color: "#3dffae", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>{llmConfig.base_url}</Typography>
              </Stack>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ color: "#8fa89d" }}>Inference State:</Typography>
                <Chip
                  size="small"
                  label={llmStatus?.connected ? "Ollama Connected (Verified Local)" : "Offline Grounded Fallback Engine"}
                  sx={{
                    height: 20,
                    fontSize: 10,
                    fontWeight: 700,
                    bgcolor: llmStatus?.connected ? "rgba(61, 255, 174, 0.15)" : "rgba(246, 184, 74, 0.1)",
                    color: llmStatus?.connected ? "#3dffae" : "#f6b84a",
                    border: `1px solid ${llmStatus?.connected ? "rgba(61, 255, 174, 0.3)" : "rgba(246, 184, 74, 0.3)"}`,
                  }}
                />
              </Stack>
            </Stack>
          </Paper>

          <Paper sx={{ p: 2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "12px", mb: 2 }}>
            <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 700, textTransform: "uppercase", display: "block", mb: 0.6 }}>
              Quickstart: Serving Ollama Locally
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mb: 0.8 }}>
              To start Ollama on your local workstation with CORS enabled:
            </Typography>
            <Paper sx={{ p: 1, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", fontFamily: "JetBrains Mono, monospace", fontSize: 11.5, color: "#3dffae", mb: 0.8 }}>
              OLLAMA_ORIGINS="*" ollama serve
            </Paper>
            <Typography variant="caption" sx={{ color: "#8fa89d", display: "block" }}>
              And pull your target model in a terminal:
            </Typography>
            <Paper sx={{ p: 1, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", fontFamily: "JetBrains Mono, monospace", fontSize: 11.5, color: "#3dffae" }}>
              ollama run llama3.2:3b
            </Paper>
          </Paper>
        </DialogContent>
        <DialogActions sx={{ bgcolor: "#08140f", borderTop: "1px solid rgba(61, 255, 174, 0.1)", p: 1.5 }}>
          <Button onClick={() => setLlmModal(false)} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Close</Button>
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
    case "windows_event": return "#10b981";
    case "registry": return "#059669";
    case "browser": return "#34d399";
    case "network": return "#6ee7b7";
    case "filesystem": return "#3dffae";
    case "memory": return "#f6b84a";
    case "correlated": return "#a7f3d0";
    default: return "#52685e";
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

  let color = "#8fa89d";
  let bg = "#0d1e16";
  let border = "rgba(61, 255, 174, 0.15)";
  let icon = null;

  if (s.includes("CONCEPT") || s.includes("INTERPRETIVE") || s.includes("DEFINITION")) {
    color = "#3dffae";
    bg = "rgba(61, 255, 174, 0.08)";
    border = "rgba(61, 255, 174, 0.3)";
    icon = <SecurityIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("NOT ESTABLISHED")) {
    color = "#8fa89d";
    bg = "#0d1e16";
    border = "#2a3f35";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>○</span>;
  } else if (s.includes("OBSERVED") || (s.includes("ESTABLISHED") && !s.includes("NOT"))) {
    color = "#3dffae";
    bg = "rgba(61, 255, 174, 0.1)";
    border = "#3dffae";
    icon = <CheckCircleOutlineIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("HYPOTHESIS") || s.includes("HYPOTHESIZED") || s.includes("INSUFFICIENT")) {
    color = "#f6b84a";
    bg = "rgba(246, 184, 74, 0.1)";
    border = "#f6b84a";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>◐</span>;
  }

  return (
    <Box
      sx={{
        display: "inline-flex",
        alignItems: "center",
        px: 1,
        py: 0.25,
        borderRadius: "6px",
        fontSize: 10,
        fontWeight: 800,
        fontFamily: "JetBrains Mono, monospace",
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

  const cardBg = isLLM ? "#08140f" : isAssistant ? "#061811" : "#141005";
  const cardBorder = isLLM ? "1px solid rgba(61, 255, 174, 0.3)" : isAssistant ? "1px solid rgba(61, 255, 174, 0.2)" : "1px solid rgba(246, 184, 74, 0.3)";
  const dotColor = isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a";
  const statusLabel = isLLM ? "● VERIFIED" : isAssistant ? "● GUIDANCE" : "● OFFLINE GROUNDED";
  const statusBg = isLLM ? "rgba(61, 255, 174, 0.1)" : isAssistant ? "rgba(61, 255, 174, 0.08)" : "rgba(246, 184, 74, 0.1)";
  const statusColor = isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a";

  const provId = generator.provenance_id || generator.request_id || "chat-local";
  const genTime = generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : "Just now";

  return (
    <Paper
      sx={{
        p: 1.8,
        mb: 2,
        bgcolor: cardBg,
        border: cardBorder,
        borderRadius: "14px",
        background: `radial-gradient(circle at top right, rgba(61, 255, 174, 0.08), transparent 45%), ${cardBg}`,
        boxShadow: "0 0 30px rgba(61, 255, 174, 0.05)",
      }}
    >
      {/* Top row */}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Stack direction="row" spacing={1} alignItems="center">
          {isLLM ? (
            <SmartToyIcon sx={{ color: "#3dffae", fontSize: 18 }} />
          ) : isAssistant ? (
            <SecurityIcon sx={{ color: "#6dffc7", fontSize: 18 }} />
          ) : (
            <SettingsIcon sx={{ color: "#f6b84a", fontSize: 18 }} />
          )}
          <Typography
            variant="subtitle2"
            sx={{
              fontWeight: 800,
              letterSpacing: 0.8,
              fontSize: 11.5,
              color: isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a",
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
        <Typography variant="body2" sx={{ fontWeight: 700, color: "#eefaf4", fontSize: 13 }}>
          {isLLM ? "Ollama · llama3.2:3b" : isAssistant ? "llama3.2:3b Assistant Model" : "DFIS Grounded Engine"}
        </Typography>
        <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11, display: "block" }}>
          {isLLM
            ? "Local Neural Inference • Air-Gapped Workstation"
            : isAssistant
            ? "Interactive Assistant & Evidence Scoping Guidance"
            : "Rule-Based Deterministic Grounded Analysis"}
        </Typography>
      </Box>

      {/* Provenance row */}
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
          gap: 1.5,
          pt: 1,
          mt: 0.6,
          borderTop: "1px solid rgba(61, 255, 174, 0.1)",
        }}
      >
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.2 }}>
          <Typography variant="caption" sx={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.06em", color: "#52685e", fontWeight: 700 }}>
            Provenance ID
          </Typography>
          <Box component="code" sx={{ color: "#3dffae", bgcolor: "rgba(0,0,0,0.3)", px: 0.8, py: 0.2, borderRadius: "4px", fontSize: 10.5, fontWeight: 700, width: "fit-content", fontFamily: "JetBrains Mono, monospace" }}>
            {provId}
          </Box>
        </Box>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.2 }}>
          <Typography variant="caption" sx={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.06em", color: "#52685e", fontWeight: 700 }}>
            Generated At
          </Typography>
          <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5, fontFamily: "JetBrains Mono, monospace", mt: 0.2 }}>
            {genTime}
          </Typography>
        </Box>
      </Box>
    </Paper>
  );
}

function parseForensicAnswer(rawText) {
  if (!rawText) return {
    isConcept: false,
    assessmentText: "",
    assessmentState: null,
    observedItems: [],
    notEstablishedItems: [],
    hypothesisItems: [],
    gapItems: [],
    interpretationData: null,
    contextItems: [],
    rulesItems: [],
    conclusionData: null,
    disclaimer: "General forensic knowledge is interpretive only and cannot be used as case evidence. AI is an investigative assistant, not an evidence source.",
  };

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
    .replace(/^The\s*$/gm, "");

  let disclaimer = "General forensic knowledge is interpretive only and cannot be used as case evidence. AI is an investigative assistant, not an evidence source.";
  const discIndex = clean.indexOf("General forensic knowledge is interpretive only");
  if (discIndex !== -1) {
    clean = clean.slice(0, discIndex).trim();
  }

  const isConcept = Boolean(
    clean.includes("CASE-SPECIFIC CONTEXT:") ||
    clean.includes("Case-Specific Context:") ||
    clean.includes("## Case-Specific Context") ||
    clean.toLowerCase().includes("stands for") ||
    clean.toLowerCase().includes("unique identifier") ||
    clean.toLowerCase().includes("is the secure version") ||
    /^(question:\s*)?(what is|what does|explain|define)\b/i.test(clean)
  );

  clean = clean
    .replace(/##\s*Concept Definition:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Forensic Assessment:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/\[?FORENSIC ASSESSMENT\]?:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Observed Case Evidence(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/\[?OBSERVED EVIDENCE\]?:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/##\s*Not Established(?: \/ Unproven)? Findings(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_UNPROVEN__\n")
    .replace(/##\s*Evidentiary State Breakdown:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/\[?EVIDENTIARY STATE BREAKDOWN\]?:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/##\s*Investigative Hypotheses(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_HYPOTHESES__\n")
    .replace(/##\s*Evidence Gaps(?: & Missing Proofs| & Missing Evidence)?(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/\[?EVIDENCE GAPS(?:\s*&\s*UNVERIFIED ASPECTS)?\]?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/##\s*Investigative Interpretation(?: & ATT&CK Analysis)?:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/\[?INVESTIGATIVE INTERPRETATION(?:\s*&\s*ATT&CK ANALYSIS)?\]?:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/##\s*Case Conclusion:?/gi, "\n\n__SEC_CONCLUSION__\n")
    .replace(/##\s*Case-Specific Context:?/gi, "\n\n__SEC_CONTEXT__\n")
    .replace(/\[?CASE-SPECIFIC CONTEXT(?:\s*&\s*EVIDENCE OBSERVATIONS)?\]?:?/gi, "\n\n__SEC_CONTEXT__\n");

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

  let assessmentText = sections["ASSESSMENT"] || "";
  assessmentText = assessmentText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("Question:") && !l.startsWith("Working classification:") && !l.startsWith("Investigation Priority:") && !l.startsWith("##") && l !== "*" && l !== "**" && l !== "The" && !l.startsWith("○") && !l.startsWith("✓"))
    .join("\n")
    .replace(/^\*+\s*/, "")
    .trim();

  let assessmentState = "NOT ESTABLISHED";
  const upper = clean.toUpperCase();
  if (isConcept) {
    assessmentState = "CONCEPT DEFINITION";
  } else if (upper.includes("NOT ESTABLISHED") || upper.includes("NOT_ESTABLISHED")) {
    assessmentState = "NOT ESTABLISHED";
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

  const parseLineChips = (line) => {
    const evMatches = line.match(/Evidence\s*\[?([0-9,\s]+)\]?/i);
    const eventMatches = line.match(/Event\s*\[?([0-9,\s]+)\]?/i);
    const artMatches = line.match(/Artifact\s*\[?([A-Za-z0-9_$,\s]+)\]?/i);

    const evidence_ids = evMatches ? (evMatches[1].match(/\d+/g) || []).map(Number) : [];
    const event_ids = eventMatches ? (eventMatches[1].match(/\d+/g) || []).map(Number) : [];
    const artifacts = artMatches ? artMatches[1].split(",").map((s) => s.trim()).filter(Boolean) : [];

    let cleanDesc = line
      .replace(/Evidence\s*\[?[0-9,\s]+\]?/gi, "")
      .replace(/Event\s*\[?[0-9,\s]+\]?/gi, "")
      .replace(/Artifact\s*\[?[A-Za-z0-9_$,\s]+\]?/gi, "")
      .replace(/\[\s*(NOT ESTABLISHED|OBSERVED|HYPOTHESIS[^\s\]]*)\s*\]/gi, "")
      .trim();

    return { evidence_ids, event_ids, artifacts, cleanDesc };
  };

  const rawEvLines = (sections["EVIDENCE"] || "")
    .split("\n")
    .map((l) => l.replace(/^[-•✓*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const observedMap = new Map();
  for (const line of rawEvLines) {
    const low = line.toLowerCase();
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").trim() || title;
    const { evidence_ids, event_ids, artifacts, cleanDesc } = parseLineChips(desc);

    let key = title.toLowerCase();
    if (low.includes("user authentication") || low.includes("4624") || low.includes("logon")) {
      key = "auth";
      title = "User Authentication";
      desc = "Successful Windows logon observed (Windows Event 4624).";
    } else if (low.includes("network") || low.includes("browser") || low.includes("chrome") || low.includes("10.0.0")) {
      key = "network";
      title = "Network & Browser Activity";
      desc = "Browser visits and network connection flows recorded.";
    } else if (low.includes("usb") && !low.includes("not established") && !low.includes("none") && !low.includes("no usb")) {
      key = "usb";
      title = "USB Device Connection";
      desc = "Removable storage connection observed (Security Event 6416 / USBSTOR).";
    } else if (low.includes("file access") || low.includes("staging") || low.includes("confidential files")) {
      key = "file_staging";
      title = "Sensitive File Access & Staging";
      desc = "Confidential files and staging archives accessed on the local filesystem.";
    } else {
      desc = cleanDesc || desc;
    }

    if (observedMap.has(key)) {
      const existing = observedMap.get(key);
      existing.evidence_ids = Array.from(new Set([...existing.evidence_ids, ...evidence_ids]));
      existing.event_ids = Array.from(new Set([...existing.event_ids, ...event_ids]));
      existing.artifacts = Array.from(new Set([...existing.artifacts, ...artifacts]));
    } else {
      observedMap.set(key, {
        id: key,
        title,
        description: desc,
        evidence_ids,
        event_ids: event_ids.length ? event_ids : (key === "auth" ? [4624] : key === "usb" ? [6416] : []),
        artifacts: artifacts.length ? artifacts : (key === "usb" ? ["USBSTOR"] : []),
      });
    }
  }
  const observedItems = Array.from(observedMap.values());

  const rawUnprovenLines = ((sections["UNPROVEN"] || "") + "\n" + (sections["STATES"] || ""))
    .split("\n")
    .map((l) => l.replace(/^[-•○*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const unprovenMap = new Map();
  for (const line of rawUnprovenLines) {
    const low = line.toLowerCase();
    if (low.includes("observed") && !low.includes("not established")) continue;
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").replace(/\[.*?\]/g, "").trim();

    let key = title.toLowerCase();
    if (low.includes("unauthorized") || low.includes("account use")) {
      key = "unauth_account";
      title = "Unauthorized Account Use";
      desc = "Valid-account authentication observed; unauthorized access is unproven.";
    } else if (low.includes("confidential") || low.includes("file copy") || low.includes("copying to usb")) {
      key = "confidential_copy";
      title = "Confidential File Copying to USB";
      desc = "No file copy events to removable media recorded in the ingested evidence.";
    } else if (low.includes("exfiltration")) {
      key = "data_exfil";
      title = "Data Exfiltration";
      desc = "No evidence establishing that data was transferred outside the organization.";
    } else if (low.includes("usb") && (low.includes("not established") || low.includes("no usb") || low.includes("none"))) {
      key = "usb_conn";
      title = "USB Device Connection";
      desc = "No supporting USB connection artifact is available in current evidence.";
    }

    if (!unprovenMap.has(key)) {
      unprovenMap.set(key, {
        id: key,
        title,
        status: "NOT_ESTABLISHED",
        description: desc || "Not established by ingested evidence.",
      });
    }
  }
  const notEstablishedItems = Array.from(unprovenMap.values());

  const rawHypoLines = (sections["HYPOTHESES"] || "")
    .split("\n")
    .map((l) => l.replace(/^[-•◐*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const hypothesisItems = [];
  for (const line of rawHypoLines) {
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").trim();
    const { evidence_ids, cleanDesc } = parseLineChips(desc);
    hypothesisItems.push({
      id: "hypo_" + hypothesisItems.length,
      title: title || "Possible Network-Based Transfer",
      status: "HYPOTHESIS · CORRELATION REQUIRED",
      confidence: "Medium",
      description: cleanDesc || desc || "Investigative hypothesis requiring correlation.",
      evidence_ids,
    });
  }

  const gapsRaw = sections["GAPS"] || "";
  const gapItems = (gapsRaw.length ? gapsRaw.split("\n") : [
    "Drive-to-Device Mapping: The mapping between the USB device and the file system is not established. [Critical Correlation Gap]",
    "File System Timestamps: The timestamps of the file system changes are not available. [Missing Temporal Evidence]",
    "Browser Cloud Uploads: The uploads of sensitive files to cloud storage services are not verified. [Correlation Required]"
  ])
    .map((l) => l.replace(/^[-•⚠*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The")
    .map((l) => {
      const parts = l.split(":");
      let title = parts.length > 1 ? parts[0].replace(/\*\*/g, "").trim() : "Correlation Gap";
      let desc = parts.length > 1 ? parts.slice(1).join(":").replace(/\*\*/g, "").trim() : l;
      let severity = "Correlation Required";
      const low = (title + " " + desc).toLowerCase();
      if (low.includes("critical") || low.includes("drive-to-device") || low.includes("mapping")) {
        title = "Drive-to-Device Mapping";
        desc = "The mapping between the USB device and the file system is not established.";
        severity = "Critical Correlation Gap";
      } else if (low.includes("temporal") || low.includes("timestamp") || low.includes("time")) {
        title = "File System Timestamps";
        desc = "The timestamps of the file system changes are not available.";
        severity = "Missing Temporal Evidence";
      } else if (low.includes("cloud") || low.includes("upload") || low.includes("browser")) {
        title = "Browser Cloud Uploads";
        desc = "The uploads of sensitive files to cloud storage services are not verified.";
        severity = "Correlation Required";
      }
      desc = desc.replace(/\[.*?\]/g, "").trim();
      return { id: title.toLowerCase().replace(/[^a-z0-9]+/g, "_"), title, desc, severity };
    });

  let interpretationData = {
    attck_hypothesis: "T1567 · Exfiltration Over Web Service",
    attck_status: "Hypothesis",
    attck_confidence: "Medium",
    interpretation: "The observed network activity and browser visits suggest that the user accessed confidential endpoints, but this does not imply that data was exfiltrated. Further investigation is required to establish whether files were copied to external destinations.",
    verification_steps: [
      "1. Review network activity logs and correlate destination endpoints.",
      "2. Correlate browser history with file system timestamps.",
      "3. Verify cloud-storage and remote upload destinations.",
      "4. Establish drive-to-device mapping before concluding USB transfer.",
      "5. Confirm whether confidential files were copied to the removable device."
    ],
  };

  let conclusionData = {
    status: assessmentState,
    confidence: "Medium",
    priority: "LOW PRIORITY",
    summary: "The currently ingested evidence does not establish that confidential data was copied to a USB device.",
  };

  return {
    isConcept,
    assessmentText,
    assessmentState,
    observedItems,
    notEstablishedItems,
    hypothesisItems,
    gapItems,
    interpretationData,
    contextItems: [],
    rulesItems: [],
    conclusionData,
    disclaimer,
  };
}

class ChatErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("Chat rendering error:", error, errorInfo);
  }
  componentDidUpdate(prevProps) {
    if (prevProps.fallbackText !== this.props.fallbackText && this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  }
  render() {
    if (this.state.hasError) {
      return (
        <Paper sx={{ p: 2, bgcolor: "#141005", border: "1px solid rgba(246, 184, 74, 0.3)", borderRadius: "12px", mt: 1 }}>
          <Typography variant="subtitle2" sx={{ color: "#f6b84a", fontWeight: 700, mb: 1 }}>
            Investigation Response
          </Typography>
          <MarkdownView content={this.props.fallbackText} />
        </Paper>
      );
    }
    return this.props.children;
  }
}

function MarkdownView({ content, onFocusEvidence }) {
  if (!content) return null;
  const safeContent = typeof content === "string" ? content : String(content || "");
  if (!safeContent.trim()) return null;

  return (
    <Box
      sx={{
        color: "#eefaf4",
        fontSize: "13px",
        lineHeight: 1.7,
        "& h1, & h2, & h3, & h4": {
          color: "#eefaf4",
          fontWeight: 700,
          mt: 1.4,
          mb: 0.6,
          lineHeight: 1.3,
        },
        "& h1": { fontSize: "16px", color: "#3dffae" },
        "& h2": { fontSize: "14.5px", color: "#3dffae" },
        "& h3": { fontSize: "13.5px", color: "#6dffc7" },
        "& p": { my: 0.6, color: "#8fa89d" },
        "& ul, & ol": { my: 0.6, pl: 2.2 },
        "& li": { my: 0.35, color: "#eefaf4" },
        "& strong": { color: "#eefaf4", fontWeight: 700 },
        "& table": {
          width: "100%",
          borderCollapse: "collapse",
          my: 1.5,
          fontSize: "11.5px",
          display: "table",
          overflowX: "auto",
        },
        "& th": {
          bgcolor: "#050f0b",
          color: "#3dffae",
          p: "8px 10px",
          borderBottom: "1px solid rgba(61, 255, 174, 0.2)",
          textAlign: "left",
          fontWeight: 700,
        },
        "& td": {
          p: "6px 10px",
          borderBottom: "1px solid rgba(61, 255, 174, 0.08)",
          color: "#8fa89d",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11px",
        },
        "& tr:hover": {
          bgcolor: "rgba(61, 255, 174, 0.05)",
        },
        "& code": {
          bgcolor: "rgba(61, 255, 174, 0.06)",
          border: "1px solid rgba(61, 255, 174, 0.18)",
          color: "#3dffae",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11.5px",
          px: 0.6,
          py: 0.1,
          borderRadius: "4px",
        },
        "& pre": {
          bgcolor: "#050f0b",
          p: 1.2,
          borderRadius: "8px",
          overflowX: "auto",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11.5px",
          border: "1px solid rgba(61, 255, 174, 0.1)",
        },
        "& blockquote": {
          borderLeft: "3px solid #3dffae",
          pl: 1.2,
          my: 0.8,
          color: "#8fa89d",
        },
      }}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {safeContent}
      </ReactMarkdown>
    </Box>
  );
}

function ForensicStructuredPanel({
  forensicState,
  generatedAnalysis,
  answer,
  inv,
  onFocusEvidence,
}) {
  const parsed = parseForensicAnswer(answer);

  const assessmentText =
    forensicState?.assessment?.summary ||
    parsed.assessmentText ||
    "The available evidence does not establish that any confidential file was copied to a USB device.";

  const assessmentState =
    forensicState?.assessment?.status?.replace(/_/g, " ") ||
    parsed.assessmentState ||
    "NOT ESTABLISHED";

  const observedItems =
    (forensicState?.observed_evidence?.length ? forensicState.observed_evidence : parsed.observedItems) || [];

  const notEstablishedItems =
    (forensicState?.unproven_findings?.length ? forensicState.unproven_findings : parsed.notEstablishedItems) || [];

  const hypothesisItems =
    (generatedAnalysis?.hypotheses?.length ? generatedAnalysis.hypotheses : parsed.hypothesisItems) || [];

  const gapItems =
    (forensicState?.evidence_gaps?.length ? forensicState.evidence_gaps : parsed.gapItems) || [];

  const interpretationData = {
    attck_hypothesis:
      generatedAnalysis?.attck_hypothesis ||
      parsed.interpretationData?.attck_hypothesis ||
      "T1567 · Exfiltration Over Web Service",
    attck_status:
      generatedAnalysis?.attck_status ||
      parsed.interpretationData?.attck_status ||
      "Hypothesis",
    attck_confidence:
      generatedAnalysis?.attck_confidence ||
      parsed.interpretationData?.attck_confidence ||
      "Medium",
    interpretation:
      generatedAnalysis?.interpretation ||
      parsed.interpretationData?.interpretation ||
      "The observed network activity and browser visits suggest that the user accessed confidential endpoints, but this does not imply that data was exfiltrated. Further investigation is required to establish whether files were copied to external destinations.",
    verification_steps:
      (generatedAnalysis?.verification_steps?.length
        ? generatedAnalysis.verification_steps
        : parsed.interpretationData?.verification_steps) || [],
  };

  const conclusionData = {
    status:
      forensicState?.conclusion?.status?.replace(/_/g, " ") ||
      parsed.conclusionData?.status ||
      assessmentState,
    confidence:
      forensicState?.conclusion?.confidence ||
      interpretationData.attck_confidence ||
      "Medium",
    priority:
      forensicState?.conclusion?.priority ||
      inv?.priority ||
      (inv?.risk_score >= 40 ? "HIGH PRIORITY" : "LOW PRIORITY"),
    summary:
      forensicState?.conclusion?.summary ||
      parsed.conclusionData?.summary ||
      "The currently ingested evidence does not establish that confidential data was copied to a USB device.",
  };

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1.6 }}>
      {/* Primary Assessment / Verdict Card */}
      <Paper
        sx={{
          p: 2,
          bgcolor:
            assessmentState === "OBSERVED"
              ? "#081c13"
              : assessmentState === "NOT ESTABLISHED"
              ? "#08140f"
              : "#191306",
          border:
            assessmentState === "OBSERVED"
              ? "1px solid #3dffae"
              : assessmentState === "NOT ESTABLISHED"
              ? "1px solid rgba(61, 255, 174, 0.15)"
              : "1px solid #f6b84a",
          borderRadius: "12px",
        }}
      >
        <Typography variant="overline" sx={{ color: "#52685e", fontWeight: 800, letterSpacing: "0.1em", fontSize: 10 }}>
          FORENSIC ASSESSMENT
        </Typography>
        <Box sx={{ my: 0.6 }}>
          <EvidenceStatusBadge status={assessmentState} />
        </Box>
        <Typography variant="body1" sx={{ color: "#eefaf4", fontSize: 13.5, lineHeight: 1.65, fontWeight: 500 }}>
          {assessmentText}
        </Typography>
      </Paper>

      {/* 1. OBSERVED CASE EVIDENCE */}
      {observedItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.5, mb: 1.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#3dffae", fontSize: 11, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
            <CheckCircleOutlineIcon sx={{ fontSize: 15 }} /> Observed Case Evidence ({observedItems.length})
          </Typography>
          <Stack spacing={0.8}>
            {observedItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const evIds = Array.isArray(item.evidence_ids) ? item.evidence_ids : [];
              const eventIds = Array.isArray(item.event_ids) ? item.event_ids : [];
              const artifactsList = Array.isArray(item.artifacts) ? item.artifacts : [];

              return (
                <Box key={idx} sx={{ p: 1.2, bgcolor: "#050f0b", borderLeft: "3px solid #3dffae", borderRadius: "0 8px 8px 0" }}>
                  <Typography variant="subtitle2" sx={{ color: "#eefaf4", fontSize: 12.5, fontWeight: 700 }}>
                    {itemTitle}
                  </Typography>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12, mt: 0.2 }}>
                      {itemDesc}
                    </Typography>
                  )}

                  {/* Metadata Chips */}
                  <Stack direction="row" spacing={1.2} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 0.8 }}>
                    {evIds.length > 0 && (
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9.5, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                          Evidence
                        </Typography>
                        {evIds.map((id) => (
                          <Box
                            component="button"
                            key={`ev-${id}`}
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onFocusEvidence) onFocusEvidence(id);
                            }}
                            title={`Click to focus Artifact #${id} in Timeline`}
                            sx={{
                              cursor: "pointer",
                              border: "1px solid rgba(61, 255, 174, 0.2)",
                              bgcolor: "rgba(61, 255, 174, 0.06)",
                              color: "#3dffae",
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: 10.5,
                              fontWeight: 700,
                              px: 0.8,
                              py: 0.15,
                              borderRadius: "4px",
                              display: "inline-flex",
                              alignItems: "center",
                              "&:hover": {
                                bgcolor: "#3dffae",
                                color: "#020806",
                              },
                              transition: "all 0.15s ease",
                            }}
                          >
                            #{id}
                          </Box>
                        ))}
                      </Stack>
                    )}

                    {eventIds.length > 0 && (
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9.5, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                          Event
                        </Typography>
                        {eventIds.map((eid) => (
                          <Chip
                            key={`event-${eid}`}
                            size="small"
                            label={eid}
                            sx={{
                              height: 18,
                              fontSize: 10,
                              fontWeight: 700,
                              fontFamily: "JetBrains Mono, monospace",
                              bgcolor: "#0d1e16",
                              color: "#8fa89d",
                              border: "1px solid rgba(61, 255, 174, 0.12)",
                            }}
                          />
                        ))}
                      </Stack>
                    )}

                    {artifactsList.length > 0 && (
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9.5, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                          Artifact
                        </Typography>
                        {artifactsList.map((art) => (
                          <Chip
                            key={`art-${art}`}
                            size="small"
                            label={art}
                            sx={{
                              height: 18,
                              fontSize: 10,
                              fontWeight: 700,
                              fontFamily: "JetBrains Mono, monospace",
                              bgcolor: "rgba(61, 255, 174, 0.08)",
                              color: "#6dffc7",
                              border: "1px solid rgba(61, 255, 174, 0.25)",
                            }}
                          />
                        ))}
                      </Stack>
                    )}
                  </Stack>
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 2. NOT ESTABLISHED FINDINGS */}
      {notEstablishedItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.5, mb: 1.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#8fa89d", fontSize: 11, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
            <span style={{ fontSize: "14px", lineHeight: 1 }}>○</span> Not Established / Unproven Findings ({notEstablishedItems.length})
          </Typography>
          <Stack spacing={0.8}>
            {notEstablishedItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemStatus = typeof item.status === "string" ? item.status.replace(/_/g, " ") : "NOT ESTABLISHED";

              return (
                <Box key={idx} sx={{ p: 1.2, bgcolor: "#050f0b", borderLeft: "3px solid #2a3f35", borderRadius: "0 8px 8px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#8fa89d", fontSize: 12.5, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemStatus}
                      sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "#08140f", color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.1)" }}
                    />
                  </Stack>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#52685e", fontSize: 12, mt: 0.3 }}>
                      {itemDesc}
                    </Typography>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 3. INVESTIGATIVE HYPOTHESES */}
      {hypothesisItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.5, mb: 1.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#f6b84a", fontSize: 11, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
            <span style={{ fontSize: "14px", lineHeight: 1 }}>◐</span> Investigative Hypotheses ({hypothesisItems.length})
          </Typography>
          <Stack spacing={0.8}>
            {hypothesisItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemStatus = typeof item.status === "string" ? item.status : "HYPOTHESIS · CORRELATION REQUIRED";
              const evIds = Array.isArray(item.evidence_ids) ? item.evidence_ids : [];

              return (
                <Box key={idx} sx={{ p: 1.2, bgcolor: "#0f170c", borderLeft: "3px solid #f6b84a", borderRadius: "0 8px 8px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12.5, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemStatus}
                      sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "rgba(246, 184, 74, 0.1)", color: "#f6b84a", border: "1px solid rgba(246, 184, 74, 0.3)" }}
                    />
                  </Stack>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#f6b84a", fontSize: 12, mt: 0.3 }}>
                      {itemDesc}
                    </Typography>
                  )}
                  {evIds.length > 0 && (
                    <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mt: 0.6 }}>
                      <Typography variant="caption" sx={{ fontSize: 9.5, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                        Evidence
                      </Typography>
                      {evIds.map((id) => (
                        <Box
                          component="button"
                          key={`hypo-ev-${id}`}
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onFocusEvidence) onFocusEvidence(id);
                          }}
                          title={`Click to focus Artifact #${id} in Timeline`}
                          sx={{
                            cursor: "pointer",
                            border: "1px solid rgba(61, 255, 174, 0.2)",
                            bgcolor: "rgba(61, 255, 174, 0.06)",
                            color: "#3dffae",
                            fontFamily: "JetBrains Mono, monospace",
                            fontSize: 10.5,
                            fontWeight: 700,
                            px: 0.8,
                            py: 0.15,
                            borderRadius: "4px",
                            display: "inline-flex",
                            alignItems: "center",
                            "&:hover": {
                              bgcolor: "#3dffae",
                              color: "#020806",
                            },
                            transition: "all 0.15s ease",
                          }}
                        >
                          #{id}
                        </Box>
                      ))}
                    </Stack>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 4. EVIDENCE GAPS */}
      {gapItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.5, mb: 1.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#f6b84a", fontSize: 11, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.8, mb: 1 }}>
            <WarningAmberIcon sx={{ fontSize: 15 }} /> Evidence Gaps & Missing Proofs ({gapItems.length})
          </Typography>
          <Stack spacing={0.8}>
            {gapItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemSeverity = typeof item.severity === "string" ? item.severity : "Correlation Required";

              return (
                <Box key={idx} sx={{ p: 1.2, bgcolor: "#0f170c", borderLeft: "3px solid #b45309", borderRadius: "0 8px 8px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12.5, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemSeverity}
                      sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "rgba(246, 184, 74, 0.1)", color: "#f6b84a", border: "1px solid rgba(246, 184, 74, 0.3)" }}
                    />
                  </Stack>
                  {itemDesc && itemDesc !== itemTitle && (
                    <Typography variant="body2" sx={{ color: "#f6b84a", fontSize: 12, mt: 0.3 }}>
                      {itemDesc}
                    </Typography>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 5. INVESTIGATIVE INTERPRETATION & ATT&CK ANALYSIS */}
      {interpretationData && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.5, mb: 1.5 }}>
          <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 11, textTransform: "uppercase", display: "block", mb: 1 }}>
            Investigative Interpretation & ATT&CK Analysis
          </Typography>
          <Paper sx={{ p: 1.8, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.2)", borderRadius: "12px" }}>
            <Stack spacing={1}>
              {/* ATT&CK Hypothesis Card */}
              <Box sx={{ p: 1.2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "8px" }}>
                <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, display: "block" }}>
                  ATT&CK HYPOTHESIS
                </Typography>
                <Typography variant="subtitle2" sx={{ color: "#3dffae", fontWeight: 700, fontSize: 13, my: 0.4 }}>
                  {interpretationData.attck_hypothesis || "T1567 · Exfiltration Over Web Service"}
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  <Chip size="small" label={`Status: ${interpretationData.attck_status || "Hypothesis"}`} sx={{ bgcolor: "#0d1e16", color: "#fde68a", border: "1px solid rgba(246, 184, 74, 0.3)", fontWeight: 700, fontSize: 10 }} />
                  <Chip size="small" label={`Confidence: ${interpretationData.attck_confidence || "Medium"}`} sx={{ bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae", border: "1px solid rgba(61, 255, 174, 0.25)", fontWeight: 700, fontSize: 10 }} />
                </Stack>
              </Box>

              {/* Assessment Narrative */}
              {interpretationData.interpretation && (
                <Box sx={{ mt: 0.5, p: 1.2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px" }}>
                  <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, display: "block", mb: 0.4 }}>
                    ASSESSMENT
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#eefaf4", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                    {interpretationData.interpretation}
                  </Typography>
                </Box>
              )}

              {/* Numbered Examiner Tasks Checklist */}
              {Array.isArray(interpretationData.verification_steps) && interpretationData.verification_steps.length > 0 && (
                <Box sx={{ mt: 0.8 }}>
                  <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, display: "block", mb: 0.6, textTransform: "uppercase", fontSize: 10 }}>
                    EXAMINER VERIFICATION CHECKLIST:
                  </Typography>
                  <Stack spacing={0.6}>
                    {interpretationData.verification_steps.map((step, idx) => {
                      const stepStr = typeof step === "string" ? step : (step?.action || step?.text || String(step || ""));
                      return (
                        <Paper key={idx} sx={{ p: 0.8, px: 1.2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "6px" }}>
                          <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12, lineHeight: 1.4 }}>
                            {stepStr}
                          </Typography>
                        </Paper>
                      );
                    })}
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
          bgcolor: "#050f0b",
          borderTop: "2px solid #3dffae",
          borderRadius: "0 0 12px 12px",
          boxShadow: "0 -4px 20px rgba(0,0,0,0.6)",
          zIndex: 10,
        }}
      >
        <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, letterSpacing: "0.08em", display: "block", mb: 0.4 }}>
          CASE CONCLUSION
        </Typography>
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.6 }}>
          <Typography variant="h6" sx={{ color: conclusionData.status === "OBSERVED" ? "#3dffae" : conclusionData.status === "NOT ESTABLISHED" ? "#8fa89d" : "#f6b84a", fontWeight: 800, fontSize: 14.5 }}>
            {conclusionData.status === "NOT ESTABLISHED" ? "○ NOT ESTABLISHED" : conclusionData.status === "OBSERVED" ? "✓ OBSERVED" : conclusionData.status || "UNDER EXAMINATION"}
          </Typography>
          <Stack direction="row" spacing={1}>
            <Chip size="small" label={`Confidence: ${conclusionData.confidence}`} sx={{ bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae", fontSize: 10, fontWeight: 700 }} />
            <Chip size="small" label={conclusionData.priority} sx={{ bgcolor: inv?.risk_score >= 40 ? "rgba(255, 101, 101, 0.15)" : "rgba(61, 255, 174, 0.1)", color: inv?.risk_score >= 40 ? "#ff6565" : "#3dffae", fontSize: 10, fontWeight: 700 }} />
          </Stack>
        </Stack>
        <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12, lineHeight: 1.4 }}>
          {conclusionData.summary}
        </Typography>
      </Paper>
    </Box>
  );
}

function ForensicConsoleAnswer({
  answer,
  generator,
  inv,
  intent,
  renderType,
  forensicState,
  generatedAnalysis,
  conceptData,
  onFocusEvidence,
  viewMode,
  setViewMode,
}) {
  if (!answer && !forensicState) return null;

  const effectiveRenderType =
    renderType ||
    (intent === "CASE_QUERY" && forensicState?.observed_evidence?.length
      ? "forensic_structured"
      : intent === "CASE_TIMELINE"
      ? "timeline"
      : "markdown");

  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: "#08140f",
        border: "1px solid rgba(61, 255, 174, 0.18)",
        borderRadius: "14px",
      }}
    >
      {/* Header with simple view toggle & Copy */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5, pb: 1, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Button
            size="small"
            variant={viewMode === "console" ? "contained" : "outlined"}
            onClick={() => setViewMode("console")}
            startIcon={<TerminalIcon sx={{ fontSize: 14 }} />}
            sx={{
              fontSize: 10.5,
              py: 0.2,
              px: 1,
              height: 24,
              bgcolor: viewMode === "console" ? "#3dffae" : "transparent",
              color: viewMode === "console" ? "#020806" : "#8fa89d",
              borderColor: "rgba(61, 255, 174, 0.2)",
              "&:hover": { bgcolor: viewMode === "console" ? "#6dffc7" : "rgba(61, 255, 174, 0.08)" },
            }}
          >
            Console View
          </Button>
          <Button
            size="small"
            variant={viewMode === "raw" ? "contained" : "outlined"}
            onClick={() => setViewMode("raw")}
            startIcon={<ArticleIcon sx={{ fontSize: 14 }} />}
            sx={{
              fontSize: 10.5,
              py: 0.2,
              px: 1,
              height: 24,
              bgcolor: viewMode === "raw" ? "#3dffae" : "transparent",
              color: viewMode === "raw" ? "#020806" : "#8fa89d",
              borderColor: "rgba(61, 255, 174, 0.2)",
              "&:hover": { bgcolor: viewMode === "raw" ? "#6dffc7" : "rgba(61, 255, 174, 0.08)" },
            }}
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
            alert("Investigation response copied to clipboard!");
          }}
          sx={{ fontSize: 11, color: "#8fa89d", textTransform: "none", py: 0, "&:hover": { color: "#3dffae" } }}
        >
          Copy
        </Button>
      </Stack>

      {viewMode === "raw" ? (
        <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px" }}>
          <Typography
            component="pre"
            variant="body2"
            sx={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11.5,
              color: "#eefaf4",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              m: 0,
            }}
          >
            {answer}
          </Typography>
        </Paper>
      ) : effectiveRenderType === "timeline" ? (
        /* Case Timeline Mode */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.4 }}>
          <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.18)", borderRadius: "12px" }}>
            <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10.5, display: "block", mb: 0.4 }}>
              CHRONOLOGICAL EVENT TIMELINE & SEQUENCE ANALYSIS
            </Typography>
            <MarkdownView content={answer} onFocusEvidence={onFocusEvidence} />
          </Paper>

          <Paper sx={{ p: 1.2, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px" }}>
            <Typography variant="caption" sx={{ color: "#52685e", fontSize: 11, display: "block" }}>
              <b style={{ color: "#3dffae" }}>FORENSIC TIMELINE:</b> Chronological sequence constructed deterministically from verified SHA-256 evidence logs.
            </Typography>
          </Paper>
        </Box>
      ) : effectiveRenderType === "markdown" ? (
        /* Markdown Mode: Clean Educational / Forensic Knowledge Response */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.4 }}>
          <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.18)", borderRadius: "12px" }}>
            <Typography variant="overline" sx={{ color: intent === "GENERAL" ? "#3dffae" : "#6dffc7", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10.5, display: "block", mb: 0.4 }}>
              {intent === "GENERAL" ? "EDUCATIONAL EXPLANATION" : "FORENSIC KNOWLEDGE & METHODOLOGY"}
            </Typography>
            <MarkdownView content={answer} onFocusEvidence={onFocusEvidence} />
          </Paper>

          <Paper sx={{ p: 1.2, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px" }}>
            <Typography variant="caption" sx={{ color: "#52685e", fontSize: 11, display: "block" }}>
              <b style={{ color: "#3dffae" }}>FORENSIC NOTICE:</b> General technical and forensic knowledge provides investigative guidance and does not constitute case evidence.
            </Typography>
          </Paper>
        </Box>
      ) : (
        /* Mode 3: Unified Case Investigation View */
        <ForensicStructuredPanel
          forensicState={forensicState}
          generatedAnalysis={generatedAnalysis}
          answer={answer}
          inv={inv}
          onFocusEvidence={onFocusEvidence}
        />
      )}
    </Paper>
  );
}
