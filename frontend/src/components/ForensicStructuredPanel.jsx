import React from "react";
import { Box, Chip, Paper, Stack, Typography } from "@mui/material";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import EvidenceStatusBadge from "./EvidenceStatusBadge.jsx";
import { parseForensicAnswer, sourceColor } from "../utils/forensicParser.js";

export default function ForensicStructuredPanel({
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
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1.2 }}>
      {/* 1. Primary Assessment / Verdict Card */}
      <Paper
        sx={{
          p: 1.5,
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
          borderRadius: "10px",
        }}
      >
        <Typography variant="overline" sx={{ color: "#52685e", fontWeight: 800, letterSpacing: "0.1em", fontSize: 9.5 }}>
          FORENSIC ASSESSMENT
        </Typography>
        <Box sx={{ my: 0.4 }}>
          <EvidenceStatusBadge status={assessmentState} />
        </Box>
        <Typography variant="body2" sx={{ color: "#eefaf4", fontSize: 12.5, lineHeight: 1.6, fontWeight: 500 }}>
          {assessmentText}
        </Typography>
      </Paper>

      {/* 2. OBSERVED CASE EVIDENCE */}
      {observedItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.2, mb: 0.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#3dffae", fontSize: 10.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.6, mb: 0.8 }}>
            <CheckCircleOutlineIcon sx={{ fontSize: 14 }} /> Observed Case Evidence ({observedItems.length})
          </Typography>
          <Stack spacing={0.6}>
            {observedItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const evIds = Array.isArray(item.evidence_ids) ? item.evidence_ids : [];
              const eventIds = Array.isArray(item.event_ids) ? item.event_ids : [];
              const artifactsList = Array.isArray(item.artifacts) ? item.artifacts : [];

              return (
                <Box key={idx} sx={{ p: 1, bgcolor: "#050f0b", borderLeft: "3px solid #3dffae", borderRadius: "0 6px 6px 0" }}>
                  <Typography variant="subtitle2" sx={{ color: "#eefaf4", fontSize: 12, fontWeight: 700 }}>
                    {itemTitle}
                  </Typography>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 11.5, mt: 0.2 }}>
                      {itemDesc}
                    </Typography>
                  )}

                  {/* Clickable Evidence Token Chips */}
                  <Stack direction="row" spacing={0.8} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 0.6 }}>
                    {evIds.length > 0 && (
                      <Stack direction="row" spacing={0.4} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
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
                              border: "1px solid rgba(61, 255, 174, 0.25)",
                              bgcolor: "rgba(61, 255, 174, 0.08)",
                              color: "#3dffae",
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: 10,
                              fontWeight: 700,
                              px: 0.6,
                              py: 0.1,
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
                      <Stack direction="row" spacing={0.4} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                          Event
                        </Typography>
                        {eventIds.map((eid) => (
                          <Chip
                            key={`event-${eid}`}
                            size="small"
                            label={eid}
                            sx={{
                              height: 16,
                              fontSize: 9.5,
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
                      <Stack direction="row" spacing={0.4} alignItems="center">
                        <Typography variant="caption" sx={{ fontSize: 9, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
                          Artifact
                        </Typography>
                        {artifactsList.map((art) => (
                          <Chip
                            key={`art-${art}`}
                            size="small"
                            label={art}
                            sx={{
                              height: 16,
                              fontSize: 9.5,
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

      {/* 3. NOT ESTABLISHED FINDINGS */}
      {notEstablishedItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.2, mb: 0.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#8fa89d", fontSize: 10.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.6, mb: 0.8 }}>
            <span style={{ fontSize: "12px", lineHeight: 1 }}>○</span> Not Established / Unproven Findings ({notEstablishedItems.length})
          </Typography>
          <Stack spacing={0.6}>
            {notEstablishedItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemStatus = typeof item.status === "string" ? item.status.replace(/_/g, " ") : "NOT ESTABLISHED";

              return (
                <Box key={idx} sx={{ p: 1, bgcolor: "#050f0b", borderLeft: "3px solid #2a3f35", borderRadius: "0 6px 6px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#8fa89d", fontSize: 12, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemStatus}
                      sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: "#08140f", color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.1)" }}
                    />
                  </Stack>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#52685e", fontSize: 11.5, mt: 0.2 }}>
                      {itemDesc}
                    </Typography>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 4. INVESTIGATIVE HYPOTHESES */}
      {hypothesisItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.2, mb: 0.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#f6b84a", fontSize: 10.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.6, mb: 0.8 }}>
            <span style={{ fontSize: "12px", lineHeight: 1 }}>◐</span> Investigative Hypotheses ({hypothesisItems.length})
          </Typography>
          <Stack spacing={0.6}>
            {hypothesisItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemStatus = typeof item.status === "string" ? item.status : "HYPOTHESIS · CORRELATION REQUIRED";
              const evIds = Array.isArray(item.evidence_ids) ? item.evidence_ids : [];

              return (
                <Box key={idx} sx={{ p: 1, bgcolor: "#0f170c", borderLeft: "3px solid #f6b84a", borderRadius: "0 6px 6px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemStatus}
                      sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: "rgba(246, 184, 74, 0.1)", color: "#f6b84a", border: "1px solid rgba(246, 184, 74, 0.3)" }}
                    />
                  </Stack>
                  {itemDesc && (
                    <Typography variant="body2" sx={{ color: "#f6b84a", fontSize: 11.5, mt: 0.2 }}>
                      {itemDesc}
                    </Typography>
                  )}
                  {evIds.length > 0 && (
                    <Stack direction="row" spacing={0.4} alignItems="center" sx={{ mt: 0.5 }}>
                      <Typography variant="caption" sx={{ fontSize: 9, color: "#52685e", fontWeight: 700, textTransform: "uppercase" }}>
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
                            border: "1px solid rgba(61, 255, 174, 0.25)",
                            bgcolor: "rgba(61, 255, 174, 0.08)",
                            color: "#3dffae",
                            fontFamily: "JetBrains Mono, monospace",
                            fontSize: 10,
                            fontWeight: 700,
                            px: 0.6,
                            py: 0.1,
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

      {/* 5. EVIDENCE GAPS */}
      {gapItems.length > 0 && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.2, mb: 0.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 800, letterSpacing: "0.06em", color: "#f6b84a", fontSize: 10.5, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 0.6, mb: 0.8 }}>
            <WarningAmberIcon sx={{ fontSize: 14 }} /> Evidence Gaps & Missing Proofs ({gapItems.length})
          </Typography>
          <Stack spacing={0.6}>
            {gapItems.map((item, idx) => {
              const itemTitle = typeof item.title === "string" ? item.title : String(item.title || "");
              const itemDesc = typeof item.description === "string" ? item.description : (typeof item.desc === "string" ? item.desc : "");
              const itemSeverity = typeof item.severity === "string" ? item.severity : "Correlation Required";

              return (
                <Box key={idx} sx={{ p: 1, bgcolor: "#0f170c", borderLeft: "3px solid #b45309", borderRadius: "0 6px 6px 0" }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="subtitle2" sx={{ color: "#fde68a", fontSize: 12, fontWeight: 700 }}>
                      {itemTitle}
                    </Typography>
                    <Chip
                      size="small"
                      label={itemSeverity}
                      sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: "rgba(246, 184, 74, 0.1)", color: "#f6b84a", border: "1px solid rgba(246, 184, 74, 0.3)" }}
                    />
                  </Stack>
                  {itemDesc && itemDesc !== itemTitle && (
                    <Typography variant="body2" sx={{ color: "#f6b84a", fontSize: 11.5, mt: 0.2 }}>
                      {itemDesc}
                    </Typography>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* 6. INVESTIGATIVE INTERPRETATION & ATT&CK ANALYSIS */}
      {interpretationData && (
        <Box sx={{ borderBottom: "1px solid rgba(61, 255, 174, 0.1)", pb: 1.2, mb: 0.5 }}>
          <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 10.5, textTransform: "uppercase", display: "block", mb: 0.8 }}>
            Investigative Interpretation & ATT&CK Analysis
          </Typography>
          <Paper sx={{ p: 1.5, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.18)", borderRadius: "10px" }}>
            <Stack spacing={0.8}>
              <Box sx={{ p: 1, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "6px" }}>
                <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9, display: "block" }}>
                  ATT&CK HYPOTHESIS
                </Typography>
                <Typography variant="subtitle2" sx={{ color: "#3dffae", fontWeight: 700, fontSize: 12, my: 0.3 }}>
                  {interpretationData.attck_hypothesis || "T1567 · Exfiltration Over Web Service"}
                </Typography>
                <Stack direction="row" spacing={0.8} sx={{ mt: 0.4 }}>
                  <Chip size="small" label={`Status: ${interpretationData.attck_status || "Hypothesis"}`} sx={{ bgcolor: "#0d1e16", color: "#fde68a", border: "1px solid rgba(246, 184, 74, 0.3)", fontWeight: 700, fontSize: 9, height: 18 }} />
                  <Chip size="small" label={`Confidence: ${interpretationData.attck_confidence || "Medium"}`} sx={{ bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae", border: "1px solid rgba(61, 255, 174, 0.25)", fontWeight: 700, fontSize: 9, height: 18 }} />
                </Stack>
              </Box>

              {interpretationData.interpretation && (
                <Box sx={{ p: 1, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.08)", borderRadius: "6px" }}>
                  <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9, display: "block", mb: 0.3 }}>
                    ASSESSMENT
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#eefaf4", fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
                    {interpretationData.interpretation}
                  </Typography>
                </Box>
              )}

              {Array.isArray(interpretationData.verification_steps) && interpretationData.verification_steps.length > 0 && (
                <Box sx={{ mt: 0.5 }}>
                  <Typography variant="caption" sx={{ color: "#3dffae", fontWeight: 800, display: "block", mb: 0.5, textTransform: "uppercase", fontSize: 9.5 }}>
                    EXAMINER VERIFICATION CHECKLIST:
                  </Typography>
                  <Stack spacing={0.5}>
                    {interpretationData.verification_steps.map((step, idx) => {
                      const stepStr = typeof step === "string" ? step : (step?.action || step?.text || String(step || ""));
                      return (
                        <Paper key={idx} sx={{ p: 0.6, px: 1, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "4px" }}>
                          <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 11.5, lineHeight: 1.35 }}>
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

      {/* 7. Sticky Conclusion Summary Banner at Bottom */}
      <Paper
        sx={{
          position: "sticky",
          bottom: -10,
          mt: 1,
          p: 1.2,
          bgcolor: "#050f0b",
          borderTop: "2px solid #3dffae",
          borderRadius: "0 0 10px 10px",
          boxShadow: "0 -4px 15px rgba(0,0,0,0.5)",
          zIndex: 10,
        }}
      >
        <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9, letterSpacing: "0.08em", display: "block", mb: 0.3 }}>
          CASE CONCLUSION
        </Typography>
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.4 }}>
          <Typography variant="subtitle2" sx={{ color: conclusionData.status === "OBSERVED" ? "#3dffae" : conclusionData.status === "NOT ESTABLISHED" ? "#8fa89d" : "#f6b84a", fontWeight: 800, fontSize: 13 }}>
            {conclusionData.status === "NOT ESTABLISHED" ? "○ NOT ESTABLISHED" : conclusionData.status === "OBSERVED" ? "✓ OBSERVED" : conclusionData.status || "UNDER EXAMINATION"}
          </Typography>
          <Stack direction="row" spacing={0.8}>
            <Chip size="small" label={`Confidence: ${conclusionData.confidence}`} sx={{ bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae", fontSize: 9.5, fontWeight: 700, height: 18 }} />
            <Chip size="small" label={conclusionData.priority} sx={{ bgcolor: inv?.risk_score >= 40 ? "rgba(255, 101, 101, 0.15)" : "rgba(61, 255, 174, 0.1)", color: inv?.risk_score >= 40 ? "#ff6565" : "#3dffae", fontSize: 9.5, fontWeight: 700, height: 18 }} />
          </Stack>
        </Stack>
        <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 11.5, lineHeight: 1.35 }}>
          {conclusionData.summary}
        </Typography>
      </Paper>
    </Box>
  );
}
