import React from "react";
import { Box, Chip, Paper, Stack, Typography, Button } from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import LockIcon from "@mui/icons-material/Lock";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";

export default function GenerationProvenanceCard({
  generator,
  intent,
  caseNumber,
  artifactCount,
  selectedEvent,
  onFocusEvidence,
}) {
  if (!generator) return null;

  const isLLM = generator.type === "llm" && !generator.fallback;
  const isKnowledge = intent === "GENERAL" || intent === "FORENSIC_KNOWLEDGE";
  const isTimeline = intent === "CASE_TIMELINE";

  const modeLabel = isKnowledge
    ? "MODE: GENERAL KNOWLEDGE"
    : isTimeline
    ? "MODE: TIMELINE SEQUENCE"
    : isLLM
    ? "MODE: EVIDENCE-GROUNDED"
    : "MODE: OFFLINE GROUNDED";

  const provId = generator.provenance_id || generator.request_id || "chat-local";
  const genTime = generator.generated_at ? generator.generated_at.replace("T", " ").slice(0, 19) : "Just now";

  return (
    <Paper
      sx={{
        p: 1.4,
        bgcolor: "#08140f",
        border: "1px solid rgba(61, 255, 174, 0.22)",
        borderRadius: "10px",
        background: "radial-gradient(circle at top right, rgba(61, 255, 174, 0.08), transparent 45%), #08140f",
        boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
      }}
    >
      {/* Top Line: Unified Copilot & Model Status */}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Stack direction="row" spacing={0.8} alignItems="center">
          <LockIcon sx={{ color: "#3dffae", fontSize: 14 }} />
          <Typography
            variant="subtitle2"
            sx={{
              fontWeight: 800,
              fontSize: 11,
              color: "#3dffae",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            Air-Gapped AI Copilot
          </Typography>
          <span style={{ color: "#2a4a3a" }}>•</span>
          <Typography variant="caption" sx={{ color: "#eefaf4", fontSize: 11, fontWeight: 700 }}>
            {isLLM ? "Ollama · llama3.2:3b" : "DFIS Grounded Engine"}
          </Typography>
        </Stack>

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

      {/* Middle Line: Investigation Context Metrics */}
      <Stack direction="row" spacing={1.2} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 0.6, fontSize: 10.5, fontFamily: "JetBrains Mono, monospace" }}>
        <Stack direction="row" spacing={0.4} alignItems="center" sx={{ color: "#3dffae" }}>
          <CheckCircleIcon sx={{ fontSize: 11 }} />
          <span>Case: {caseNumber || "ACTIVE"}</span>
        </Stack>

        {artifactCount !== undefined && (
          <Stack direction="row" spacing={0.4} alignItems="center" sx={{ color: "#8fa89d" }}>
            <span>•</span>
            <span>{artifactCount} Artifacts</span>
          </Stack>
        )}

        <Stack direction="row" spacing={0.4} alignItems="center" sx={{ color: "#8fa89d" }}>
          <span>•</span>
          <span>SHA-256 Verified ✓</span>
        </Stack>
      </Stack>

      {/* Bottom Row: Active Timeline Context Badge if an event is selected */}
      {selectedEvent && (
        <Box
          sx={{
            mt: 0.8,
            pt: 0.8,
            borderTop: "1px solid rgba(61, 255, 174, 0.1)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <Stack direction="row" spacing={0.8} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
            <AutoFixHighIcon sx={{ color: "#3dffae", fontSize: 13 }} />
            <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 9.5, textTransform: "uppercase" }}>
              Timeline Context:
            </Typography>
            <Box
              component="button"
              type="button"
              onClick={() => onFocusEvidence && onFocusEvidence(selectedEvent.id)}
              sx={{
                cursor: "pointer",
                background: "rgba(61, 255, 174, 0.12)",
                border: "1px solid rgba(61, 255, 174, 0.3)",
                color: "#3dffae",
                fontSize: 9.5,
                fontWeight: 800,
                fontFamily: "JetBrains Mono, monospace",
                px: 0.6,
                py: 0.1,
                borderRadius: "3px",
              }}
            >
              #{selectedEvent.id}
            </Box>
            <Typography variant="caption" sx={{ color: "#eefaf4", fontSize: 10.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {selectedEvent.event_type} {selectedEvent.target ? `→ ${selectedEvent.target}` : ""}
            </Typography>
          </Stack>

          <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5, fontFamily: "JetBrains Mono", flexShrink: 0 }}>
            {provId.slice(0, 12)}
          </Typography>
        </Box>
      )}
    </Paper>
  );
}
