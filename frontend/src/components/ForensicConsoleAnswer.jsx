import React from "react";
import { Box, Button, Paper, Stack, Typography } from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MarkdownView from "./MarkdownView.jsx";
import ForensicStructuredPanel from "./ForensicStructuredPanel.jsx";

export default function ForensicConsoleAnswer({
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
        p: 1.5,
        bgcolor: "#08140f",
        border: "1px solid rgba(61, 255, 174, 0.16)",
        borderRadius: "10px",
      }}
    >
      {/* Header with simple view toggle & Copy */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.2, pb: 0.8, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
        <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.08em" }}>
          {intent === "CASE_TIMELINE" ? "TIMELINE ANALYSIS" : intent === "GENERAL" ? "KNOWLEDGE BASE" : "EVIDENCE ANALYSIS"}
        </Typography>
        <Button
          size="small"
          variant="text"
          startIcon={<ContentCopyIcon sx={{ fontSize: 12 }} />}
          onClick={() => {
            navigator.clipboard?.writeText(answer);
            alert("Investigation response copied to clipboard!");
          }}
          sx={{ fontSize: 10.5, color: "#8fa89d", textTransform: "none", py: 0, px: 0.6, "&:hover": { color: "#3dffae" } }}
        >
          Copy
        </Button>
      </Stack>

      {viewMode === "raw" ? (
        <Paper sx={{ p: 1.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "8px" }}>
          <Typography
            component="pre"
            variant="body2"
            sx={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11,
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
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.2 }}>
          <Paper sx={{ p: 1.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.16)", borderRadius: "10px" }}>
            <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10, display: "block", mb: 0.4 }}>
              CHRONOLOGICAL EVENT TIMELINE & SEQUENCE ANALYSIS
            </Typography>
            <MarkdownView content={answer} onFocusEvidence={onFocusEvidence} />
          </Paper>

          <Paper sx={{ p: 1, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "6px" }}>
            <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10.5, display: "block" }}>
              <b style={{ color: "#3dffae" }}>FORENSIC TIMELINE:</b> Chronological sequence constructed deterministically from verified SHA-256 evidence logs.
            </Typography>
          </Paper>
        </Box>
      ) : effectiveRenderType === "markdown" ? (
        /* Markdown Mode: Clean Educational / Forensic Knowledge Response */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.2 }}>
          <Paper sx={{ p: 1.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.16)", borderRadius: "10px" }}>
            <Typography variant="overline" sx={{ color: intent === "GENERAL" ? "#3dffae" : "#6dffc7", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10, display: "block", mb: 0.4 }}>
              {intent === "GENERAL" ? "EDUCATIONAL EXPLANATION" : "FORENSIC KNOWLEDGE & METHODOLOGY"}
            </Typography>
            <MarkdownView content={answer} onFocusEvidence={onFocusEvidence} />
          </Paper>

          <Paper sx={{ p: 1, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "6px" }}>
            <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10.5, display: "block" }}>
              <b style={{ color: "#3dffae" }}>FORENSIC NOTICE:</b> General technical and forensic knowledge provides investigative guidance and does not constitute case evidence.
            </Typography>
          </Paper>
        </Box>
      ) : (
        /* Mode 3: Structured Forensic Evidence Breakdown */
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
