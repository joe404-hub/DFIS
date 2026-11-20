import React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import SmartToyIcon from "@mui/icons-material/SmartToy";

export function NewCaseModal({ open, onClose, form, setForm, onCreate }) {
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
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
        <Button onClick={onClose} sx={{ color: "#8fa89d" }}>Cancel</Button>
        <Button onClick={onCreate} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Create Case</Button>
      </DialogActions>
    </Dialog>
  );
}

export function IngestModal({ ingestModal, onClose }) {
  if (!ingestModal) return null;
  return (
    <Dialog open={Boolean(ingestModal)} onClose={onClose} maxWidth="sm" fullWidth>
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
        <Button onClick={onClose} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Done</Button>
      </DialogActions>
    </Dialog>
  );
}

export function AcquireModal({ open, onClose, acquireMode, setAcquireMode, policy, setPolicy, onExecute }) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
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
        <Button onClick={onClose} sx={{ color: "#8fa89d" }}>Cancel</Button>
        <Button onClick={onExecute} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800 }}>
          Execute Authorized Acquisition
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function LlmConfigModal({
  open,
  onClose,
  llmConfig,
  setLlmConfig,
  llmStatus,
  setLlmStatus,
  testingLlm,
  setTestingLlm,
  llmTestMsg,
  setLlmTestMsg,
  api,
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 700, display: "flex", alignItems: "center", gap: 1, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
        <SmartToyIcon /> Local LLM Configuration (llama3.2:3b)
      </DialogTitle>
      <DialogContent sx={{ bgcolor: "#050f0b", color: "#eefaf4", pt: 2.5 }}>
        <Typography variant="body2" sx={{ color: "#8fa89d", mb: 2 }}>
          DFIS utilizes a 100% local, air-gapped Large Language Model (<b>llama3.2:3b</b>) to assist examiners with evidence analysis and grounded Q&A.
        </Typography>

        {llmTestMsg && (
          <Alert
            severity={llmTestMsg.type}
            onClose={() => setLlmTestMsg(null)}
            sx={{ mb: 2, bgcolor: llmTestMsg.type === "success" ? "#064e3b" : "#451a03", color: "#f8fafc" }}
          >
            {llmTestMsg.text}
          </Alert>
        )}

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
        <Button onClick={onClose} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 700 }}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
