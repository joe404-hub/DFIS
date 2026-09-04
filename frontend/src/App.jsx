import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AppBar,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  LinearProgress,
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
  Toolbar,
  Tooltip,
  Typography,
} from "@mui/material";
import TimelineIcon from "@mui/icons-material/Timeline";
import HubIcon from "@mui/icons-material/Hub";
import FolderZipIcon from "@mui/icons-material/FolderZip";
import SecurityIcon from "@mui/icons-material/Security";
import FactCheckIcon from "@mui/icons-material/FactCheck";
import DescriptionIcon from "@mui/icons-material/Description";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SettingsIcon from "@mui/icons-material/Settings";
import ViewSidebarIcon from "@mui/icons-material/ViewSidebar";
import { DataSet } from "vis-data";
import { Timeline } from "vis-timeline";
import { Network } from "vis-network";
import "vis-timeline/styles/vis-timeline-graph2d.css";

import Sidebar from "./components/Sidebar.jsx";
import TimelineWorkspace from "./components/TimelineWorkspace.jsx";
import LocalAiCopilot from "./components/LocalAiCopilot.jsx";
import EvidenceStatusBadge from "./components/EvidenceStatusBadge.jsx";
import { NewCaseModal, IngestModal, AcquireModal, LlmConfigModal } from "./components/Modals.jsx";
import { escapeHtml, riskClass, sourceColor, formatClassification, parseForensicAnswer } from "./utils/forensicParser.js";

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

  // Intelligent Progressive Reveal Sidebar State
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarPinned, setSidebarPinned] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_sidebar_pinned");
      if (saved) return JSON.parse(saved);
    } catch {}
    return false;
  });
  const [caseSearch, setCaseSearch] = useState("");
  const closeTimer = useRef(null);

  const openSidebar = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    setSidebarOpen(true);
  };

  const scheduleCloseSidebar = () => {
    if (sidebarPinned) return;
    if (closeTimer.current) clearTimeout(closeTimer.current);
    closeTimer.current = setTimeout(() => {
      setSidebarOpen(false);
    }, 700);
  };

  const togglePinSidebar = () => {
    setSidebarPinned((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("dfis_sidebar_pinned", JSON.stringify(next));
      } catch {}
      return next;
    });
    setSidebarOpen(true);
  };

  // Keyboard shortcut Ctrl+B / Cmd+B for Sidebar
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        togglePinSidebar();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [sidebarPinned]);

  const tlRef = useRef(null);
  const netRef = useRef(null);
  const tlInst = useRef(null);
  const netInst = useRef(null);
  const tableContainerRef = useRef(null);

  const loadCases = async () => {
    try {
      const r = await api("/api/cases").then((x) => x.json());
      setCases(r || []);
      if (!active && r && r.length > 0) setActive(r[0].id);
    } catch (e) {
      console.error("Failed to load cases:", e);
    }
  };

  const loadCase = async (id) => {
    if (!id) return;
    setBusy(true);
    try {
      const [d, t, evs, g, invr, recr] = await Promise.all([
        api(`/api/cases/${id}`).then((x) => x.json()).catch(() => null),
        api(`/api/cases/${id}/timeline`).then((x) => x.json()).catch(() => []),
        api(`/api/cases/${id}/evidence`).then((x) => x.json()).catch(() => []),
        api(`/api/cases/${id}/graph`).then((x) => x.json()).catch(() => ({ nodes: [], edges: [] })),
        api(`/api/cases/${id}/investigation`).then((x) => x.json()).catch(() => null),
        api(`/api/cases/${id}/recommendations`).then((x) => x.json()).catch(() => []),
      ]);
      if (d) setDetail(d);
      setTimeline(Array.isArray(t) ? t : []);
      setEvidenceList(Array.isArray(evs) ? evs : []);
      setGraph(g || { nodes: [], edges: [] });
      setInv(invr);
      setRecs(Array.isArray(recr) ? recr : recr?.next_actions || []);
      setAnswer("");
      setGenerator(null);
      setAnswerMeta(null);
      setSelectedEvent(null);
    } catch (err) {
      console.error("Failed to load case detail:", err);
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

  // Synchronized Selection Handler (Timeline ↔ Table ↔ AI Copilot)
  const handleSelectEvent = (event) => {
    if (!event) return;
    setSelectedEvent(event);
    if (event.timestamp && tlInst.current) {
      try {
        tlInst.current.setSelection(event.id);
        tlInst.current.moveTo(event.timestamp);
      } catch {}
    }
    const rowEl = document.getElementById(`timeline-row-${event.id}`);
    if (rowEl) {
      rowEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  };

  // Vis Timeline initialization with Black & Emerald theme & Structured Lane Headers
  useEffect(() => {
    if (!tlRef.current || tab !== 0) return;
    try {
      const filtered = (timeline || []).filter((e) => e && e.timestamp);
      if (!filtered.length) return;

      const sourceLabels = {
        windows_event: "▣ WINDOWS LOGS",
        registry: "▣ REGISTRY HIVES",
        browser: "▣ BROWSER ACTIVITY",
        network: "▣ NETWORK TRAFFIC",
        filesystem: "▣ FILE SYSTEM",
        memory: "▣ MEMORY SNAPSHOT",
        correlated: "▣ CORRELATED CLUSTERS",
      };

      const uniqueSources = [...new Set(filtered.map((e) => e.source_type || "other"))];
      const groups = new DataSet(
        uniqueSources.map((src) => ({
          id: src,
          content: `<span style="color:#3dffae;font-weight:800;font-size:10px;letter-spacing:0.06em;">${sourceLabels[src] || src.toUpperCase()}</span>`,
          style: "color:#8fa89d;font-weight:700;font-size:11px;padding:6px 10px;background-color:#07140f;border-bottom:1px solid rgba(61, 255, 174, 0.08);",
        }))
      );

      const items = new DataSet(
        filtered.map((e) => {
          const shortTitle = escapeHtml(e.target || e.object || e.process || e.description || "").slice(0, 36);
          return {
            id: e.id,
            content: `<div class="tl-item-content"><span class="tl-tag ${e.source_type || "other"}">${e.event_type || "EVENT"}</span> <span class="tl-title">${shortTitle}</span></div>`,
            start: e.timestamp,
            group: e.source_type || "other",
            className: `tl-src-${e.source_type || "other"} ${e.source_type === "correlated" ? "tl-correlated" : riskClass(e)}`,
            title: `[${e.source_type || "unknown"}] ${e.event_type || ""}\n${e.description || ""}\nTime: ${e.timestamp || ""}`,
          };
        })
      );

      if (tlInst.current) {
        try { tlInst.current.destroy(); } catch {}
      }
      tlInst.current = new Timeline(tlRef.current, items, groups, {
        stack: true,
        stackSubgroups: true,
        orientation: "top",
        margin: { item: { horizontal: 6, vertical: 8 }, axis: 6 },
        zoomKey: "ctrlKey",
        minHeight: "280px",
        maxHeight: "380px",
        verticalScroll: true,
        showCurrentTime: false,
      });

      tlInst.current.on("select", (properties) => {
        const selectedId = properties.items[0];
        const match = (timeline || []).find((e) => e && e.id === selectedId);
        if (match) {
          setSelectedEvent(match);
          const rowEl = document.getElementById(`timeline-row-${match.id}`);
          if (rowEl) {
            rowEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
      });
    } catch (err) {
      console.warn("Timeline init error:", err);
    }
  }, [timeline, tab]);

  // Vis Network Graph initialization
  useEffect(() => {
    if (!netRef.current || tab !== 1) return;
    try {
      if (netInst.current) {
        try { netInst.current.destroy(); } catch {}
      }
      netInst.current = new Network(
        netRef.current,
        { nodes: graph?.nodes || [], edges: graph?.edges || [] },
        {
          nodes: { shape: "dot", size: 14, font: { color: "#eefaf4", size: 12, face: "Inter" } },
          edges: { color: "rgba(61, 255, 174, 0.2)", font: { color: "#8fa89d", size: 10 }, arrows: "to" },
          physics: { stabilization: true },
        }
      );
    } catch (err) {
      console.warn("Network init error:", err);
    }
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
    const match = timeline.find((e) => e && (e.id === numericId || String(e.event_id) === String(evId)));
    if (match) {
      setTab(0);
      handleSelectEvent(match);
      setTimeout(() => {
        const rowEl = document.getElementById(`timeline-row-${match.id}`);
        if (rowEl) rowEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 100);
    }
  };

  const filteredTimeline = useMemo(() => {
    return (timeline || []).filter((e) => {
      if (!e) return false;
      if (sourceFilter !== "all" && e.source_type !== sourceFilter) return false;
      if (search.trim()) {
        const s = search.toLowerCase();
        const blob = `${e.event_type || ""} ${e.artifact_type || ""} ${e.user || ""} ${e.process || ""} ${e.target || ""} ${e.object || ""} ${e.description || ""} ${e.source || ""} ${e.source_ip || ""} ${e.destination_ip || ""}`.toLowerCase();
        if (!blob.includes(s)) return false;
      }
      return true;
    });
  }, [timeline, sourceFilter, search]);

  const filteredCases = useMemo(() => {
    if (!caseSearch.trim()) return cases;
    const cs = caseSearch.toLowerCase();
    return (cases || []).filter(
      (c) =>
        c &&
        (c.case_number.toLowerCase().includes(cs) ||
          (c.title || "").toLowerCase().includes(cs) ||
          (c.investigator || "").toLowerCase().includes(cs))
    );
  }, [cases, caseSearch]);

  const risk = inv?.risk_score || finding?.risk_score || 0;

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100vh", bgcolor: "#020806", color: "#eefaf4", overflow: "hidden", position: "relative" }}>
      <style>{`
        /* Vis Timeline Black & Emerald Theme */
        .vis-timeline {
          border: 1px solid rgba(61, 255, 174, 0.12) !important;
          font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif !important;
          background-color: #050f0b !important;
          border-radius: 10px !important;
          width: 100% !important;
          box-sizing: border-box !important;
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
          cursor: pointer !important;
        }
        .vis-item.vis-selected {
          border-color: #3dffae !important;
          background-color: #12281e !important;
          box-shadow: 0 0 0 1px #3dffae, 0 0 18px rgba(61, 255, 174, 0.35) !important;
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

      {/* TOP NAVIGATION BAR (Fixed height: 56px) */}
      <AppBar
        position="static"
        sx={{
          height: 56,
          bgcolor: "#020806",
          borderBottom: "1px solid rgba(61, 255, 174, 0.14)",
          backdropFilter: "blur(12px)",
          flexShrink: 0,
        }}
        elevation={0}
      >
        <Toolbar variant="dense" sx={{ height: 56, minHeight: 56, px: 2, justifyContent: "space-between" }}>
          {/* Brand Logo & Sidebar Quick Toggle */}
          <Stack direction="row" spacing={1.2} alignItems="center">
            <Tooltip title={sidebarPinned ? "Sidebar is pinned open" : "Reveal investigations sidebar (Ctrl+B)"} arrow>
              <IconButton
                size="small"
                onClick={openSidebar}
                sx={{
                  color: sidebarOpen || sidebarPinned ? "#3dffae" : "#8fa89d",
                  border: "1px solid rgba(61, 255, 174, 0.15)",
                  bgcolor: "#08140f",
                  "&:hover": { color: "#3dffae", borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.08)" },
                }}
              >
                <ViewSidebarIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>

            <Box
              sx={{
                width: 28,
                height: 28,
                borderRadius: "6px",
                bgcolor: "rgba(61, 255, 174, 0.1)",
                border: "1px solid rgba(61, 255, 174, 0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 12px rgba(61, 255, 174, 0.15)",
              }}
            >
              <FingerprintIcon sx={{ color: "#3dffae", fontSize: 17 }} />
            </Box>
            <Stack direction="row" spacing={0.6} alignItems="center">
              <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: "-0.02em", color: "#eefaf4", fontSize: 15 }}>
                DFIS
              </Typography>
              <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: "#3dffae", boxShadow: "0 0 8px #3dffae" }} />
            </Stack>
            <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5, letterSpacing: "0.03em", display: { xs: "none", sm: "block" } }}>
              Digital Forensics Intelligence System
            </Typography>
          </Stack>

          {/* Active Case Context Banner (Middle) */}
          {detail && (
            <Stack direction="row" spacing={1.2} alignItems="center" sx={{ display: { xs: "none", md: "flex" } }}>
              <Chip
                size="small"
                label={detail.case_number}
                sx={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 10.5,
                  fontWeight: 800,
                  bgcolor: "rgba(61, 255, 174, 0.1)",
                  color: "#3dffae",
                  border: "1px solid rgba(61, 255, 174, 0.25)",
                  height: 22,
                }}
              />
              <Typography variant="body2" sx={{ color: "#eefaf4", fontWeight: 700, fontSize: 12.5, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {detail.title}
              </Typography>
              <Chip
                size="small"
                label={`${timeline.length} Artifacts`}
                sx={{ height: 20, fontSize: 9.5, fontWeight: 700, bgcolor: "#08140f", color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.1)" }}
              />
              <Chip
                size="small"
                label={`Risk: ${risk}/100`}
                sx={{
                  height: 20,
                  fontSize: 9.5,
                  fontWeight: 800,
                  fontFamily: "JetBrains Mono, monospace",
                  bgcolor: risk >= 40 ? "rgba(255, 101, 101, 0.15)" : "rgba(61, 255, 174, 0.1)",
                  color: risk >= 40 ? "#ff6565" : "#3dffae",
                  border: `1px solid ${risk >= 40 ? "rgba(255, 101, 101, 0.3)" : "rgba(61, 255, 174, 0.2)"}`,
                }}
              />
            </Stack>
          )}

          {/* Actions & AI Indicator (Right) */}
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              icon={<SmartToyIcon sx={{ fontSize: "13px !important", color: llmStatus?.connected ? "#3dffae" : "#f6b84a" }} />}
              label={llmStatus?.connected ? "LOCAL AI READY" : "OFFLINE GROUNDED"}
              size="small"
              onClick={() => setLlmModal(true)}
              sx={{
                bgcolor: llmStatus?.connected ? "rgba(61, 255, 174, 0.08)" : "rgba(246, 184, 74, 0.08)",
                color: llmStatus?.connected ? "#3dffae" : "#f6b84a",
                border: `1px solid ${llmStatus?.connected ? "rgba(61, 255, 174, 0.25)" : "rgba(246, 184, 74, 0.25)"}`,
                fontWeight: 800,
                fontSize: 10.5,
                height: 24,
                cursor: "pointer",
                "&:hover": { bgcolor: "rgba(61, 255, 174, 0.15)" },
              }}
            />

            <IconButton
              size="small"
              onClick={() => setLlmModal(true)}
              title="Local LLM Settings"
              sx={{ color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.12)", bgcolor: "#08140f", height: 28, width: 28, "&:hover": { color: "#3dffae", borderColor: "#3dffae" } }}
            >
              <SettingsIcon sx={{ fontSize: 15 }} />
            </IconButton>

            {active && (
              <Button
                variant="outlined"
                size="small"
                href={`/api/cases/${active}/report`}
                target="_blank"
                startIcon={<DescriptionIcon sx={{ fontSize: 13 }} />}
                sx={{
                  borderColor: "rgba(61, 255, 174, 0.25)",
                  color: "#3dffae",
                  fontSize: 11,
                  fontWeight: 700,
                  height: 28,
                  px: 1.2,
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
                fontWeight: 800,
                fontSize: 11,
                height: 28,
                px: 1.4,
                "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 15px rgba(61, 255, 174, 0.4)" },
              }}
            >
              + New Case
            </Button>
          </Stack>
        </Toolbar>
        {busy && <LinearProgress sx={{ bgcolor: "#020806", height: 2, "& .MuiLinearProgress-bar": { bgcolor: "#3dffae" } }} />}
      </AppBar>

      {/* WORKSPACE BODY (occupies calc(100vh - 56px), flex: 1, overflow: hidden) */}
      <Box sx={{ flex: 1, display: "flex", position: "relative", overflow: "hidden", minHeight: 0 }}>

        {/* Sidebar */}
        <Sidebar
          sidebarOpen={sidebarOpen}
          sidebarPinned={sidebarPinned}
          openSidebar={openSidebar}
          scheduleCloseSidebar={scheduleCloseSidebar}
          togglePinSidebar={togglePinSidebar}
          filteredCases={filteredCases}
          active={active}
          setActive={setActive}
          setSidebarOpen={setSidebarOpen}
          caseSearch={caseSearch}
          setCaseSearch={setCaseSearch}
          setOpenNewCase={setOpen}
        />

        {/* UNIFIED FORENSIC WORKSPACE GRID (Left: Timeline Workspace | Right: AI Copilot) */}
        <Box
          component="main"
          sx={{
            flex: 1,
            minWidth: 0,
            height: "100%",
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              lg: "minmax(0, 1fr) minmax(420px, 490px)",
              xl: "minmax(0, 1fr) minmax(460px, 530px)",
            },
            gap: "16px",
            p: { xs: 1.5, md: 2 },
            boxSizing: "border-box",
            overflow: "hidden",
            ml: sidebarPinned ? "280px" : 0,
            transition: "margin-left 320ms cubic-bezier(0.22, 1, 0.36, 1)",
          }}
        >
          {/* LEFT PANEL: TIMELINE & INVESTIGATION WORKSPACE */}
          <Paper
            className="timeline-workspace"
            sx={{
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              minHeight: 0,
              height: "100%",
              bgcolor: "#06100d",
              border: "1px solid rgba(61, 255, 174, 0.16)",
              borderRadius: "14px",
              overflow: "hidden",
              boxShadow: "0 10px 40px rgba(0,0,0,0.4)",
            }}
          >
            {/* Navigation Tabs Header */}
            <Box sx={{ flexShrink: 0, bgcolor: "#050f0b", borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
              <Tabs
                value={tab}
                onChange={(_, v) => setTab(v)}
                sx={{
                  minHeight: 44,
                  "& .MuiTab-root": {
                    textTransform: "none",
                    fontWeight: 600,
                    minHeight: 44,
                    py: 0,
                    fontSize: 12,
                    color: "#8fa89d",
                    "&.Mui-selected": { color: "#3dffae", fontWeight: 700 },
                  },
                  "& .MuiTabs-indicator": { bgcolor: "#3dffae", height: 2.5 },
                }}
              >
                <Tab icon={<TimelineIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Timeline (${timeline.length})`} />
                <Tab icon={<HubIcon sx={{ fontSize: 15 }} />} iconPosition="start" label="Graph" />
                <Tab icon={<FolderZipIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Evidence (${evidenceList.length})`} />
                <Tab icon={<SecurityIcon sx={{ fontSize: 15 }} />} iconPosition="start" label="AI Investigation" />
                <Tab icon={<FactCheckIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Tasks (${recs.length})`} />
                <Tab icon={<DescriptionIcon sx={{ fontSize: 15 }} />} iconPosition="start" label="Report" />
              </Tabs>
            </Box>

            {/* TAB 0: UNIFIED CHRONOLOGICAL TIMELINE WORKSPACE */}
            {tab === 0 && (
              <TimelineWorkspace
                timeline={timeline}
                filteredTimeline={filteredTimeline}
                search={search}
                setSearch={setSearch}
                sourceFilter={sourceFilter}
                setSourceFilter={setSourceFilter}
                selectedEvent={selectedEvent}
                setSelectedEvent={setSelectedEvent}
                handleSelectEvent={handleSelectEvent}
                tlRef={tlRef}
                tlInst={tlInst}
                tableContainerRef={tableContainerRef}
                onOpenAcquire={() => setAcquireModal(true)}
                onUploadFile={upload}
              />
            )}

            {/* TAB 1: RELATIONSHIP GRAPH */}
            {tab === 1 && (
              <Box sx={{ p: 2, flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
                <Typography variant="caption" sx={{ color: "#8fa89d", mb: 1, display: "block" }}>
                  Cross-artifact entity graph: linking actors, processes, files, USB media, and network destinations.
                </Typography>
                <Box ref={netRef} sx={{ flex: 1, bgcolor: "#050f0b", borderRadius: "10px", border: "1px solid rgba(61, 255, 174, 0.12)", minHeight: 380 }} />
              </Box>
            )}

            {/* TAB 2: EVIDENCE & CUSTODY */}
            {tab === 2 && (
              <Box sx={{ p: 2.5, flex: 1, overflowY: "auto" }}>
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
              <Box sx={{ p: 2.5, flex: 1, overflowY: "auto" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3dffae" }}>
                  Incident Classification: {formatClassification(inv?.category || finding?.category, inv?.secondary)}
                </Typography>
                <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mb: 2 }}>
                  ATT&CK techniques and attack-chain stages are investigative hypotheses synthesized from multi-source correlations.
                </Typography>

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
              <Box sx={{ p: 2.5, flex: 1, overflowY: "auto" }}>
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
              <Box sx={{ p: 2.5, flex: 1, overflowY: "auto" }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#eefaf4" }}>Evidence-Linked Investigation Report</Typography>
                  <Button variant="contained" href={`/api/cases/${active}/report`} target="_blank" startIcon={<DescriptionIcon sx={{ fontSize: 14 }} />} sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>
                    Download PDF Report
                  </Button>
                </Stack>
                <Paper sx={{ p: 2.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px" }}>
                  <Typography variant="h6" sx={{ color: "#3dffae", fontWeight: 700 }}>{detail?.title}</Typography>
                  <Typography variant="body2" sx={{ color: "#8fa89d", my: 1, fontFamily: "JetBrains Mono, monospace", fontSize: 11.5 }}>
                    Case: {detail?.case_number} | Examiner: {detail?.investigator} | Status: {detail?.status}
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

          {/* RIGHT PANEL: PERSISTENT LOCAL AI COPILOT WORKSPACE */}
          <LocalAiCopilot
            llmStatus={llmStatus}
            answer={answer}
            generator={generator}
            inv={inv}
            answerMeta={answerMeta}
            chatViewMode={chatViewMode}
            setChatViewMode={setChatViewMode}
            busy={busy}
            q={q}
            setQ={setQ}
            ask={ask}
            focusEvidence={focusEvidence}
            onOpenSettings={() => setLlmModal(true)}
            selectedEvent={selectedEvent}
            caseNumber={detail?.case_number}
            artifactCount={timeline.length}
          />

        </Box>

      </Box>

      {/* Case Creation Dialog */}
      <NewCaseModal
        open={open}
        onClose={() => setOpen(false)}
        form={form}
        setForm={setForm}
        onCreate={createCase}
      />

      {/* Ingest Summary Dialog */}
      <IngestModal
        ingestModal={ingestModal}
        onClose={() => setIngestModal(null)}
      />

      {/* Evidence Acquisition Modal Dialog */}
      <AcquireModal
        open={acquireModal}
        onClose={() => setAcquireModal(false)}
        acquireMode={acquireMode}
        setAcquireMode={setAcquireMode}
        policy={policy}
        setPolicy={setPolicy}
        onExecute={acquireEvidence}
      />

      {/* Local LLM (llama3.2:3b) Configuration & Status Dialog */}
      <LlmConfigModal
        open={llmModal}
        onClose={() => setLlmModal(false)}
        llmConfig={llmConfig}
        setLlmConfig={setLlmConfig}
        llmStatus={llmStatus}
        setLlmStatus={setLlmStatus}
        testingLlm={testingLlm}
        setTestingLlm={setTestingLlm}
        llmTestMsg={llmTestMsg}
        setLlmTestMsg={setLlmTestMsg}
        api={api}
      />
    </Box>
  );
}
