import React from "react";
import { Box, Button, Chip, Paper, Stack, Typography } from "@mui/material";
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

  const isKnowledge = intent === "GENERAL" || intent === "FORENSIC_KNOWLEDGE";
  const isTimeline = intent === "CASE_TIMELINE";

  const effectiveRenderType =
    renderType ||
    (intent === "CASE_QUERY" && forensicState?.observed_evidence?.length
      ? "forensic_structured"
      : isTimeline
      ? "timeline"
      : "markdown");

  return (
    <Paper
      sx={{
        p: { xs: 2, md: 2.2 },
        bgcolor: "#08140f",
        border: "1px solid rgba(61, 255, 174, 0.18)",
        borderRadius: "12px",
      }}
    >
      {/* Header: AI RESPONSE + Source / Mode Notice */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5, pb: 1, borderBottom: "1px solid rgba(61, 255, 174, 0.1)" }}>
        <Stack spacing={0.2}>
          <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 10, letterSpacing: "0.1em", lineHeight: 1.2 }}>
            AI RESPONSE
          </Typography>
          <Typography variant="caption" sx={{ color: isKnowledge ? "#f6b84a" : "#8fa89d", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}>
            {isKnowledge
              ? "General Technical Knowledge • ⚠ Not Case Evidence"
              : isTimeline
              ? "Chronological Sequence Analysis • Evidence-Derived"
              : "Evidence-Grounded Forensic Assessment"}
          </Typography>
        </Stack>

        <Button
          size="small"
          variant="text"
          startIcon={<ContentCopyIcon sx={{ fontSize: 12 }} />}
          onClick={() => {
            navigator.clipboard?.writeText(answer);
            alert("Investigation response copied to clipboard!");
          }}
          sx={{ fontSize: 10.5, color: "#8fa89d", textTransform: "none", py: 0.2, px: 0.8, "&:hover": { color: "#3dffae" } }}
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
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, maxWidth: "68ch" }}>
          <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.16)", borderRadius: "10px" }}>
            <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10, display: "block", mb: 0.6 }}>
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
        /* Markdown Mode: Clean Educational / Forensic Knowledge Response with 65ch width */
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, maxWidth: "68ch" }}>
          <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.16)", borderRadius: "10px" }}>
            <Typography variant="overline" sx={{ color: isKnowledge ? "#6dffc7" : "#3dffae", fontWeight: 800, letterSpacing: "0.08em", fontSize: 10, display: "block", mb: 0.6 }}>
              {isKnowledge ? "EDUCATIONAL EXPLANATION" : "FORENSIC INVESTIGATION SUMMARY"}
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
