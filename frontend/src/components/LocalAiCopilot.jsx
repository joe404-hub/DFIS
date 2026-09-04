import React from "react";
import {
  Box,
  Button,
  Chip,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import LockIcon from "@mui/icons-material/Lock";
import SettingsIcon from "@mui/icons-material/Settings";
import GenerationProvenanceCard from "./GenerationProvenanceCard.jsx";
import ChatErrorBoundary from "./ChatErrorBoundary.jsx";
import ForensicConsoleAnswer from "./ForensicConsoleAnswer.jsx";

export default function LocalAiCopilot({
  llmStatus,
  answer,
  generator,
  inv,
  answerMeta,
  chatViewMode,
  setChatViewMode,
  busy,
  q,
  setQ,
  ask,
  focusEvidence,
  onOpenSettings,
}) {
  return (
    <Paper
      className="ai-workspace"
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
      {/* 1. COPILOT HEADER */}
      <Box
        sx={{
          flexShrink: 0,
          p: "10px 14px",
          bgcolor: "#08140f",
          borderBottom: "1px solid rgba(61, 255, 174, 0.12)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 1,
        }}
      >
        <Stack direction="row" spacing={0.8} alignItems="center" sx={{ minWidth: 0 }}>
          <SmartToyIcon sx={{ color: "#3dffae", fontSize: 17 }} />
          <Typography variant="subtitle2" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#eefaf4", fontSize: 12.5, textTransform: "uppercase" }}>
            LOCAL AI COPILOT
          </Typography>
          <Chip
            size="small"
            label={llmStatus?.connected ? "llama3.2:3b • VERIFIED" : "OFFLINE GROUNDED"}
            sx={{
              height: 18,
              fontSize: 9,
              fontWeight: 800,
              fontFamily: "JetBrains Mono, monospace",
              bgcolor: llmStatus?.connected ? "rgba(61, 255, 174, 0.1)" : "rgba(246, 184, 74, 0.1)",
              color: llmStatus?.connected ? "#3dffae" : "#f6b84a",
              border: `1px solid ${llmStatus?.connected ? "rgba(61, 255, 174, 0.25)" : "rgba(246, 184, 74, 0.25)"}`,
            }}
          />
        </Stack>

        <Stack direction="row" spacing={0.5} alignItems="center">
          {answer && (
            <Stack direction="row" spacing={0.4} sx={{ mr: 0.5 }}>
              <Button
                size="small"
                variant={chatViewMode === "console" ? "contained" : "text"}
                onClick={() => setChatViewMode("console")}
                sx={{
                  fontSize: 9.5,
                  py: 0.1,
                  px: 0.8,
                  height: 22,
                  minWidth: "auto",
                  bgcolor: chatViewMode === "console" ? "#3dffae" : "transparent",
                  color: chatViewMode === "console" ? "#020806" : "#8fa89d",
                  fontWeight: 700,
                }}
              >
                Console
              </Button>
              <Button
                size="small"
                variant={chatViewMode === "raw" ? "contained" : "text"}
                onClick={() => setChatViewMode("raw")}
                sx={{
                  fontSize: 9.5,
                  py: 0.1,
                  px: 0.8,
                  height: 22,
                  minWidth: "auto",
                  bgcolor: chatViewMode === "raw" ? "#3dffae" : "transparent",
                  color: chatViewMode === "raw" ? "#020806" : "#8fa89d",
                  fontWeight: 700,
                }}
              >
                Raw
              </Button>
            </Stack>
          )}

          <IconButton
            size="small"
            onClick={onOpenSettings}
            title="Local Model Settings"
            sx={{ color: "#8fa89d", height: 24, width: 24, "&:hover": { color: "#3dffae" } }}
          >
            <SettingsIcon sx={{ fontSize: 15 }} />
          </IconButton>
        </Stack>
      </Box>

      {/* 2. SCROLLABLE CHAT & FORENSIC ANALYSIS AREA */}
      <Box
        className="ai-chat-content"
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          p: 2,
          display: "flex",
          flexDirection: "column",
          gap: 1.5,
        }}
      >
        {/* Air-gap guarantee badge */}
        <Box sx={{ p: 0.8, px: 1.2, bgcolor: "#040a08", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px", display: "flex", alignItems: "center", gap: 1 }}>
          <LockIcon sx={{ fontSize: 13, color: "#3dffae" }} />
          <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5 }}>
            <b style={{ color: "#eefaf4" }}>100% Air-Gapped Local Inference:</b> Running <code>llama3.2:3b</code> locally on workstation.
          </Typography>
        </Box>

        {busy ? (
          /* Reasoning Progress */
          <Box sx={{ p: 4, textAlign: "center", my: "auto" }}>
            <LinearProgress sx={{ bgcolor: "#050f0b", mb: 2, "& .MuiLinearProgress-bar": { bgcolor: "#3dffae" } }} />
            <Typography variant="subtitle2" sx={{ color: "#3dffae", fontWeight: 800 }}>
              Reasoning over verified evidence logs...
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", mt: 0.5 }}>
              Synthesizing multi-source temporal correlations & MITRE ATT&CK mappings
            </Typography>
          </Box>
        ) : answer ? (
          /* Active Forensic Answer */
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
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
          /* Empty / Ready State */
          <Box sx={{ p: 3, textAlign: "center", border: "1px dashed rgba(61, 255, 174, 0.15)", borderRadius: "12px", bgcolor: "#050f0b", my: "auto" }}>
            <SmartToyIcon sx={{ color: "#3dffae", fontSize: 32, opacity: 0.8, mb: 1 }} />
            <Typography variant="subtitle2" sx={{ color: "#eefaf4", fontWeight: 700, mb: 0.5 }}>
              Investigation Assistant Ready
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", maxWidth: 280, mx: "auto" }}>
              Ask a query in the chat bar below or click one of the suggested investigative prompts.
            </Typography>
          </Box>
        )}
      </Box>

      {/* 3. QUICK SUGGESTIONS STRIP */}
      <Box
        className="ai-suggestions"
        sx={{
          flexShrink: 0,
          p: "6px 12px",
          bgcolor: "#050f0b",
          borderTop: "1px solid rgba(61, 255, 174, 0.08)",
          display: "flex",
          gap: 0.6,
          overflowX: "auto",
          whiteSpace: "nowrap",
          "&::-webkit-scrollbar": { height: 3 },
          "&::-webkit-scrollbar-thumb": { bgcolor: "rgba(61, 255, 174, 0.2)", borderRadius: 2 },
        }}
      >
        {[
          { label: "Timeline", query: "generate the timeline of events occurred" },
          { label: "Was USB mounted?", query: "Was confidential data copied to USB?" },
          { label: "Suspicious activity", query: "how could we find the suspicious activity taken place?" },
          { label: "Evidence gaps", query: "What are the evidence gaps in this investigation?" },
          { label: "Next steps", query: "What are the recommended next steps?" },
          { label: "Summarize case", query: "summarize the case" },
        ].map((sug, i) => (
          <Chip
            key={i}
            size="small"
            label={sug.label}
            clickable
            onClick={() => {
              setQ(sug.query);
              ask(sug.query);
            }}
            sx={{
              flexShrink: 0,
              fontSize: 10,
              height: 22,
              fontWeight: 600,
              bgcolor: "rgba(61, 255, 174, 0.06)",
              color: "#8fa89d",
              border: "1px solid rgba(61, 255, 174, 0.12)",
              "&:hover": {
                bgcolor: "rgba(61, 255, 174, 0.14)",
                color: "#3dffae",
                borderColor: "#3dffae",
              },
            }}
          />
        ))}
      </Box>

      {/* 4. PINNED BOTTOM CHAT INPUT BAR */}
      <Box
        className="ai-input-container"
        sx={{
          flexShrink: 0,
          p: "10px 12px",
          bgcolor: "#081410",
          borderTop: "1px solid rgba(61, 255, 174, 0.12)",
        }}
      >
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1,
            bgcolor: "#030806",
            border: "1px solid rgba(61, 255, 174, 0.2)",
            borderRadius: "8px",
            p: "3px 4px 3px 10px",
            "&:focus-within": {
              borderColor: "#3dffae",
              boxShadow: "0 0 10px rgba(61, 255, 174, 0.2)",
            },
          }}
        >
          <TextField
            fullWidth
            variant="standard"
            placeholder="Ask about this investigation (e.g. was data copied to USB)..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                ask();
              }
            }}
            InputProps={{
              disableUnderline: true,
              sx: {
                color: "#eefaf4",
                fontSize: 12.5,
                fontFamily: "Inter, sans-serif",
              },
            }}
          />

          <Button
            variant="contained"
            disabled={busy || !q.trim()}
            onClick={() => ask()}
            sx={{
              minWidth: 32,
              width: 32,
              height: 28,
              p: 0,
              borderRadius: "6px",
              bgcolor: "#3dffae",
              color: "#020806",
              fontWeight: 800,
              fontSize: 13,
              "&:hover": {
                bgcolor: "#6dffc7",
                boxShadow: "0 0 12px rgba(61, 255, 174, 0.4)",
              },
            }}
          >
            ➤
          </Button>
        </Box>

        <Stack direction="row" justifyContent="space-between" sx={{ mt: 0.5, px: 0.5 }}>
          <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5 }}>
            Press <b>Enter</b> or <b>⌘↵</b> to analyze
          </Typography>
          <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5, fontFamily: "JetBrains Mono" }}>
            Ollama · llama3.2:3b
          </Typography>
        </Stack>
      </Box>
    </Paper>
  );
}
