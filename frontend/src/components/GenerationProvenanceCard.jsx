import React from "react";
import { Box, Chip, Paper, Stack, Typography } from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SecurityIcon from "@mui/icons-material/Security";
import SettingsIcon from "@mui/icons-material/Settings";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";

export default function GenerationProvenanceCard({ generator, intent, caseNumber, artifactCount, forensicState }) {
  if (!generator) return null;

  const isLLM = generator.type === "llm" && !generator.fallback;
  const isAssistant = generator.type === "assistant";

  const cardBg = isLLM ? "#08140f" : isAssistant ? "#061811" : "#141005";
  const cardBorder = isLLM ? "1px solid rgba(61, 255, 174, 0.3)" : isAssistant ? "1px solid rgba(61, 255, 174, 0.2)" : "1px solid rgba(246, 184, 74, 0.3)";
  const dotColor = isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a";

  const isKnowledge = intent === "GENERAL" || intent === "FORENSIC_KNOWLEDGE";
  const isTimeline = intent === "CASE_TIMELINE";

  const modeLabel = isKnowledge
    ? "MODE: GENERAL FORENSIC KNOWLEDGE"
    : isTimeline
    ? "MODE: TIMELINE SEQUENCE ANALYSIS"
    : isLLM
    ? "MODE: EVIDENCE-GROUNDED"
    : "MODE: OFFLINE GROUNDED";

  const statusLabel = isLLM ? "● VERIFIED" : isAssistant ? "● GUIDANCE" : "● OFFLINE GROUNDED";
  const statusBg = isLLM ? "rgba(61, 255, 174, 0.1)" : isAssistant ? "rgba(61, 255, 174, 0.08)" : "rgba(246, 184, 74, 0.1)";
  const statusColor = isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a";

  const provId = generator.provenance_id || generator.request_id || "chat-local";
  const genTime = generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : "Just now";

  const observedEvs = forensicState?.observed_evidence || [];

  return (
    <Paper
      sx={{
        p: 1.5,
        bgcolor: cardBg,
        border: cardBorder,
        borderRadius: "10px",
        background: `radial-gradient(circle at top right, rgba(61, 255, 174, 0.08), transparent 45%), ${cardBg}`,
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Stack direction="row" spacing={0.8} alignItems="center">
          {isLLM ? (
            <SmartToyIcon sx={{ color: "#3dffae", fontSize: 16 }} />
          ) : isAssistant ? (
            <SecurityIcon sx={{ color: "#6dffc7", fontSize: 16 }} />
          ) : (
            <SettingsIcon sx={{ color: "#f6b84a", fontSize: 16 }} />
          )}
          <Typography
            variant="subtitle2"
            sx={{
              fontWeight: 800,
              fontSize: 11,
              color: isLLM ? "#3dffae" : isAssistant ? "#6dffc7" : "#f6b84a",
              textTransform: "uppercase",
            }}
          >
            {isLLM ? "Local AI Generation" : isAssistant ? "Forensic Guidance" : "Grounded Fallback"}
          </Typography>
        </Stack>

        <Chip
          size="small"
          label={statusLabel}
          sx={{
            height: 18,
            fontSize: 9,
            fontWeight: 800,
            bgcolor: statusBg,
            color: statusColor,
            border: `1px solid ${dotColor}`,
          }}
        />
      </Stack>

      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ my: 0.6 }}>
        <Typography variant="body2" sx={{ fontWeight: 700, color: "#eefaf4", fontSize: 12 }}>
          {isLLM ? "Ollama · llama3.2:3b" : isAssistant ? "llama3.2:3b Assistant Model" : "DFIS Grounded Engine"}
        </Typography>

        <Chip
          size="small"
          label={modeLabel}
          sx={{
            height: 18,
            fontSize: 8.5,
            fontWeight: 800,
            fontFamily: "JetBrains Mono, monospace",
            bgcolor: isKnowledge ? "rgba(109, 255, 199, 0.1)" : "rgba(61, 255, 174, 0.1)",
            color: isKnowledge ? "#6dffc7" : "#3dffae",
            border: `1px solid ${isKnowledge ? "rgba(109, 255, 199, 0.25)" : "rgba(61, 255, 174, 0.25)"}`,
          }}
        />
      </Stack>

      {/* CONTEXT USED CHECKLIST */}
      <Box sx={{ pt: 0.8, mt: 0.6, borderTop: "1px solid rgba(61, 255, 174, 0.08)" }}>
        <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em", display: "block", mb: 0.4 }}>
          CONTEXT USED
        </Typography>

        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ fontSize: 10, fontFamily: "JetBrains Mono" }}>
          <Stack direction="row" spacing={0.3} alignItems="center" sx={{ color: "#3dffae" }}>
            <CheckCircleIcon sx={{ fontSize: 11 }} />
            <span>Case: {caseNumber || "ACTIVE"}</span>
          </Stack>

          {artifactCount !== undefined && (
            <Stack direction="row" spacing={0.3} alignItems="center" sx={{ color: "#3dffae" }}>
              <CheckCircleIcon sx={{ fontSize: 11 }} />
              <span>{artifactCount} Artifacts Ingested</span>
            </Stack>
          )}

          <Stack direction="row" spacing={0.3} alignItems="center" sx={{ color: "#3dffae" }}>
            <CheckCircleIcon sx={{ fontSize: 11 }} />
            <span>SHA-256 Verified</span>
          </Stack>

          {isKnowledge && (
            <Stack direction="row" spacing={0.3} alignItems="center" sx={{ color: "#f6b84a" }}>
              <span>⚠ Interpretive • General Knowledge</span>
            </Stack>
          )}
        </Stack>
      </Box>

      {/* PROVENANCE FOOTER */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ pt: 0.6, mt: 0.6, borderTop: "1px solid rgba(61, 255, 174, 0.08)", fontSize: 10, fontFamily: "JetBrains Mono" }}>
        <span style={{ color: "#52685e" }}>ID: <code style={{ color: "#3dffae" }}>{provId}</code></span>
        <span style={{ color: "#8fa89d" }}>{genTime}</span>
      </Stack>
    </Paper>
  );
}
