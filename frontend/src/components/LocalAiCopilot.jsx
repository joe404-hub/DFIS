import React, { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Collapse,
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
import CheckBoxIcon from "@mui/icons-material/CheckBox";
import CheckBoxOutlineBlankIcon from "@mui/icons-material/CheckBoxOutlineBlank";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import SendIcon from "@mui/icons-material/Send";

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
  selectedEvent,
  caseNumber,
  artifactCount,
}) {
  const [useCaseEvidence, setUseCaseEvidence] = useState(true);
  const [useSelectedEvent, setUseSelectedEvent] = useState(true);
  const [showMoreSuggestions, setShowMoreSuggestions] = useState(false);

  const handleAskWithContext = (overrideQuery) => {
    let queryText = overrideQuery || q;
    if (!queryText || !queryText.trim()) return;

    if (useSelectedEvent && selectedEvent && !overrideQuery) {
      queryText = `Regarding Artifact #${selectedEvent.id} (${selectedEvent.event_type} - ${selectedEvent.target || selectedEvent.object || selectedEvent.description}): ${queryText}`;
    }

    ask(queryText);
  };

  const isKnowledge = answerMeta?.intent === "GENERAL" || answerMeta?.intent === "FORENSIC_KNOWLEDGE";

  // Context-aware dynamic suggestion chips
  const contextualPrompts = selectedEvent
    ? [
        {
          label: `✦ Investigate Event #${selectedEvent.id}`,
          query: `Explain the forensic significance of Artifact #${selectedEvent.id} (${selectedEvent.event_type} - ${selectedEvent.target || selectedEvent.object || selectedEvent.description}) in this case.`,
        },
        {
          label: "✦ Show Related Activity",
          query: `What forensic activity preceded or followed Artifact #${selectedEvent.id} (${selectedEvent.event_type})?`,
        },
        {
          label: `✦ Check Evidence Gaps for #${selectedEvent.id}`,
          query: `What evidence gaps or unverified assertions exist regarding Artifact #${selectedEvent.id}?`,
        },
      ]
    : [
        { label: "✦ Generate Timeline", query: "generate the timeline of events occurred" },
        { label: "✦ Find Suspicious Activity", query: "how could we find the suspicious activity taken place?" },
        { label: "✦ Evidence Gaps", query: "What are the evidence gaps in this investigation?" },
      ];

  const secondaryPrompts = [
    { label: "Was USB mounted?", query: "Was confidential data copied to USB?" },
    { label: "Recommend next steps", query: "What are the recommended next steps?" },
    { label: "Summarize case", query: "summarize the case" },
    { label: "Explain DFIR methodology", query: "What is the forensic methodology for investigating suspected insider threat exfiltration?" },
  ];

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
      {/* 1. COPILOT HEADER WITH CLEAR MODE INDICATOR */}
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

      {/* 2. SCROLLABLE CHAT & FORENSIC ANALYSIS AREA (With 18px 20px padding and 65ch width) */}
      <Box
        className="ai-chat-content"
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          p: { xs: 1.8, md: 2.2 },
          display: "flex",
          flexDirection: "column",
          gap: 1.5,
        }}
      >
        {/* Air-gap guarantee badge */}
        <Box sx={{ p: 0.9, px: 1.4, bgcolor: "#040a08", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <LockIcon sx={{ fontSize: 13, color: "#3dffae" }} />
            <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5 }}>
              <b style={{ color: "#eefaf4" }}>Air-Gapped Workstation:</b> <code>llama3.2:3b</code> local inference.
            </Typography>
          </Stack>
          <Chip
            size="small"
            label={isKnowledge ? "MODE: GENERAL KNOWLEDGE" : "MODE: EVIDENCE-GROUNDED"}
            sx={{
              height: 18,
              fontSize: 8.5,
              fontWeight: 800,
              fontFamily: "JetBrains Mono, monospace",
              bgcolor: isKnowledge ? "rgba(109, 255, 199, 0.08)" : "rgba(61, 255, 174, 0.08)",
              color: isKnowledge ? "#6dffc7" : "#3dffae",
              border: `1px solid ${isKnowledge ? "rgba(109, 255, 199, 0.2)" : "rgba(61, 255, 174, 0.2)"}`,
            }}
          />
        </Box>

        {/* Currently Selected Event Context Strip in AI Panel */}
        {selectedEvent && (
          <Paper
            sx={{
              p: 1.2,
              bgcolor: "#0d1e16",
              border: "1px solid rgba(61, 255, 174, 0.3)",
              borderRadius: "8px",
              boxShadow: "0 0 15px rgba(61, 255, 174, 0.08)",
            }}
          >
            <Stack direction="row" justifyContent="space-between" alignItems="center">
              <Stack direction="row" spacing={0.8} alignItems="center">
                <AutoFixHighIcon sx={{ color: "#3dffae", fontSize: 14 }} />
                <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  TIMELINE CONTEXT
                </Typography>
                <Chip size="small" label={`#${selectedEvent.id}`} sx={{ height: 16, fontSize: 9, fontWeight: 800, fontFamily: "JetBrains Mono", bgcolor: "rgba(61, 255, 174, 0.15)", color: "#3dffae" }} />
              </Stack>

              <Button
                size="small"
                variant="text"
                onClick={() => handleAskWithContext(`Explain the forensic significance of artifact #${selectedEvent.id} (${selectedEvent.event_type} - ${selectedEvent.target || selectedEvent.object || selectedEvent.description})`)}
                sx={{ fontSize: 10, py: 0.1, px: 0.8, color: "#3dffae", textTransform: "none", fontWeight: 700, "&:hover": { bgcolor: "rgba(61, 255, 174, 0.1)" } }}
              >
                Ask AI about this event →
              </Button>
            </Stack>
            <Typography variant="body2" sx={{ color: "#eefaf4", fontSize: 11.5, mt: 0.4, lineHeight: 1.3 }}>
              <b>{selectedEvent.event_type}</b> {selectedEvent.target ? `on ${selectedEvent.target}` : ""} • {selectedEvent.description}
            </Typography>
          </Paper>
        )}

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
            <GenerationProvenanceCard
              generator={generator}
              intent={answerMeta?.intent}
              caseNumber={caseNumber}
              artifactCount={artifactCount}
              forensicState={answerMeta?.forensic_state}
            />
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
              Investigation Copilot Ready
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", display: "block", maxWidth: 280, mx: "auto" }}>
              Ask a query in the chat bar below or click one of the suggested prompts to analyze evidence with local AI.
            </Typography>
          </Box>
        )}
      </Box>

      {/* 3. CONTEXT-AWARE SUGGESTIONS STRIP (3 Contextual Chips + Expandable "More") */}
      <Box
        className="ai-suggestions"
        sx={{
          flexShrink: 0,
          p: "6px 12px",
          bgcolor: "#050f0b",
          borderTop: "1px solid rgba(61, 255, 174, 0.08)",
          display: "flex",
          flexDirection: "column",
          gap: 0.5,
        }}
      >
        <Stack direction="row" spacing={0.6} alignItems="center" sx={{ overflowX: "auto", whiteSpace: "nowrap" }}>
          {contextualPrompts.map((sug, i) => (
            <Chip
              key={i}
              size="small"
              label={sug.label}
              clickable
              onClick={() => {
                setQ(sug.query);
                handleAskWithContext(sug.query);
              }}
              sx={{
                flexShrink: 0,
                fontSize: 10,
                height: 22,
                fontWeight: 600,
                bgcolor: selectedEvent ? "rgba(61, 255, 174, 0.1)" : "rgba(61, 255, 174, 0.06)",
                color: selectedEvent ? "#3dffae" : "#8fa89d",
                border: `1px solid ${selectedEvent ? "rgba(61, 255, 174, 0.3)" : "rgba(61, 255, 174, 0.14)"}`,
                "&:hover": {
                  bgcolor: "rgba(61, 255, 174, 0.18)",
                  color: "#3dffae",
                  borderColor: "#3dffae",
                },
              }}
            />
          ))}

          <Button
            size="small"
            onClick={() => setShowMoreSuggestions((prev) => !prev)}
            endIcon={showMoreSuggestions ? <ExpandLessIcon sx={{ fontSize: 13 }} /> : <ExpandMoreIcon sx={{ fontSize: 13 }} />}
            sx={{
              fontSize: 9.5,
              py: 0.1,
              px: 0.8,
              height: 22,
              minWidth: "auto",
              color: "#3dffae",
              textTransform: "none",
              fontWeight: 700,
            }}
          >
            {showMoreSuggestions ? "Less" : "More prompts"}
          </Button>
        </Stack>

        {/* Collapsible secondary prompt chips */}
        <Collapse in={showMoreSuggestions}>
          <Stack direction="row" spacing={0.6} flexWrap="wrap" useFlexGap sx={{ pt: 0.4 }}>
            {secondaryPrompts.map((sug, i) => (
              <Chip
                key={`more-${i}`}
                size="small"
                label={sug.label}
                clickable
                onClick={() => {
                  setQ(sug.query);
                  handleAskWithContext(sug.query);
                }}
                sx={{
                  fontSize: 9.5,
                  height: 20,
                  bgcolor: "rgba(61, 255, 174, 0.04)",
                  color: "#8fa89d",
                  border: "1px solid rgba(61, 255, 174, 0.1)",
                  "&:hover": { bgcolor: "rgba(61, 255, 174, 0.12)", color: "#3dffae" },
                }}
              />
            ))}
          </Stack>
        </Collapse>
      </Box>

      {/* 4. PINNED BOTTOM CHAT INPUT BAR WITH 2-TIER WORKSTATION LAYOUT */}
      <Box
        className="ai-input-container"
        sx={{
          flexShrink: 0,
          p: "10px 14px",
          bgcolor: "#081410",
          borderTop: "1px solid rgba(61, 255, 174, 0.12)",
        }}
      >
        {/* Context Toggles Row */}
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 0.8, px: 0.2 }}>
          <Stack
            direction="row"
            spacing={0.4}
            alignItems="center"
            onClick={() => setUseCaseEvidence((p) => !p)}
            sx={{ cursor: "pointer", userSelect: "none" }}
          >
            {useCaseEvidence ? <CheckBoxIcon sx={{ fontSize: 14, color: "#3dffae" }} /> : <CheckBoxOutlineBlankIcon sx={{ fontSize: 14, color: "#52685e" }} />}
            <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 700, color: useCaseEvidence ? "#3dffae" : "#8fa89d" }}>
              Case Evidence
            </Typography>
          </Stack>

          {selectedEvent && (
            <Stack
              direction="row"
              spacing={0.4}
              alignItems="center"
              onClick={() => setUseSelectedEvent((p) => !p)}
              sx={{ cursor: "pointer", userSelect: "none" }}
            >
              {useSelectedEvent ? <CheckBoxIcon sx={{ fontSize: 14, color: "#3dffae" }} /> : <CheckBoxOutlineBlankIcon sx={{ fontSize: 14, color: "#52685e" }} />}
              <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 700, color: useSelectedEvent ? "#3dffae" : "#8fa89d" }}>
                Selected Event (#{selectedEvent.id})
              </Typography>
            </Stack>
          )}
        </Stack>

        {/* Input Field Box */}
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1,
            bgcolor: "#030806",
            border: "1px solid rgba(61, 255, 174, 0.22)",
            borderRadius: "8px",
            p: "4px 6px 4px 12px",
            "&:focus-within": {
              borderColor: "#3dffae",
              boxShadow: "0 0 12px rgba(61, 255, 174, 0.2)",
            },
          }}
        >
          <TextField
            fullWidth
            variant="standard"
            placeholder={`Ask about ${caseNumber || "this investigation"}...`}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleAskWithContext();
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
            onClick={() => handleAskWithContext()}
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

        <Stack direction="row" justifyContent="space-between" sx={{ mt: 0.6, px: 0.5 }}>
          <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5 }}>
            Press <b>Enter</b> to analyze • <b>Shift+Enter</b> for new line
          </Typography>
          <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5, fontFamily: "JetBrains Mono" }}>
            Ollama · llama3.2:3b
          </Typography>
        </Stack>
      </Box>
    </Paper>
  );
}
