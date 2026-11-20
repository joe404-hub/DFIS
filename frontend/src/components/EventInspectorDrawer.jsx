import React from "react";
import {
  Box,
  Button,
  Chip,
  Drawer,
  IconButton,
  Paper,
  Stack,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import { sourceColor } from "../utils/forensicParser.js";

export default function EventInspectorDrawer({
  open,
  onClose,
  event,
  timeline,
  onSelectEvent,
  onAskAi,
}) {
  if (!event) return null;

  const currentIndex = timeline.findIndex((e) => e.id === event.id);
  const prevEvent = currentIndex > 0 ? timeline[currentIndex - 1] : null;
  const nextEvent = currentIndex < timeline.length - 1 ? timeline[currentIndex + 1] : null;

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: { xs: "100%", sm: 460 },
          bgcolor: "#06100d",
          borderLeft: "1px solid rgba(61, 255, 174, 0.2)",
          color: "#eefaf4",
          p: 0,
          display: "flex",
          flexDirection: "column",
        },
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 2,
          bgcolor: "#08140f",
          borderBottom: "1px solid rgba(61, 255, 174, 0.15)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <Stack direction="row" spacing={1} alignItems="center">
          <FingerprintIcon sx={{ color: "#3dffae", fontSize: 20 }} />
          <Typography variant="subtitle1" sx={{ fontWeight: 800, color: "#eefaf4", letterSpacing: "-0.01em" }}>
            ARTIFACT INSPECTOR
          </Typography>
          <Chip
            size="small"
            label={`#${event.id}`}
            sx={{
              fontFamily: "JetBrains Mono, monospace",
              fontWeight: 800,
              bgcolor: "rgba(61, 255, 174, 0.15)",
              color: "#3dffae",
              border: "1px solid rgba(61, 255, 174, 0.3)",
              height: 22,
            }}
          />
        </Stack>

        <IconButton size="small" onClick={onClose} sx={{ color: "#8fa89d", "&:hover": { color: "#3dffae" } }}>
          <CloseIcon sx={{ fontSize: 18 }} />
        </IconButton>
      </Box>

      {/* Body Content */}
      <Box sx={{ p: 2.5, flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 2 }}>
        {/* Source & Event Type Banner */}
        <Paper sx={{ p: 2, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.15)", borderRadius: "10px" }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 10 }}>
              SOURCE & ARTIFACT TYPE
            </Typography>
            <Chip
              size="small"
              label={event.source_type}
              sx={{ bgcolor: sourceColor(event.source_type), color: "#fff", fontWeight: 700, height: 20, fontSize: 10 }}
            />
          </Stack>
          <Typography variant="h6" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 16 }}>
            {event.event_type}
          </Typography>
          {event.action && (
            <Typography variant="body2" sx={{ color: "#eefaf4", fontWeight: 600, mt: 0.4 }}>
              Action: {event.action}
            </Typography>
          )}
        </Paper>

        {/* Temporal & Host Details */}
        <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "10px" }}>
          <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 10, display: "block", mb: 1.2 }}>
            TEMPORAL & HOST CONTEXT
          </Typography>

          <Stack spacing={1} sx={{ fontSize: 12, fontFamily: "JetBrains Mono, monospace" }}>
            <Stack direction="row" justifyContent="space-between">
              <span style={{ color: "#8fa89d" }}>Timestamp (UTC):</span>
              <span style={{ color: "#3dffae", fontWeight: 700 }}>{event.timestamp || "N/A"}</span>
            </Stack>

            <Stack direction="row" justifyContent="space-between">
              <span style={{ color: "#8fa89d" }}>Actor / User:</span>
              <span style={{ color: "#eefaf4" }}>{event.user || event.actor || "—"}</span>
            </Stack>

            <Stack direction="row" justifyContent="space-between">
              <span style={{ color: "#8fa89d" }}>Host / Endpoint:</span>
              <span style={{ color: "#eefaf4" }}>{event.host || "WORKSTATION-14"}</span>
            </Stack>

            {event.process && (
              <Stack direction="row" justifyContent="space-between">
                <span style={{ color: "#8fa89d" }}>Process Name:</span>
                <span style={{ color: "#6dffc7" }}>{event.process}</span>
              </Stack>
            )}

            {event.target && (
              <Box sx={{ pt: 0.5, borderTop: "1px solid rgba(61, 255, 174, 0.08)" }}>
                <span style={{ color: "#8fa89d", display: "block", mb: 0.3 }}>Target / Object:</span>
                <Box sx={{ p: 0.8, bgcolor: "#08140f", borderRadius: "6px", wordBreak: "break-all", color: "#eefaf4", fontSize: 11.5 }}>
                  {event.target || event.object}
                </Box>
              </Box>
            )}
          </Stack>
        </Paper>

        {/* Full Forensic Description */}
        <Paper sx={{ p: 2, bgcolor: "#050f0b", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "10px" }}>
          <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 10, display: "block", mb: 0.8 }}>
            FORENSIC LOG RECORD & DETAILS
          </Typography>
          <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12.5, lineHeight: 1.6 }}>
            {event.description}
          </Typography>
          {event.evidence_hash && (
            <Box sx={{ mt: 1.5, pt: 1, borderTop: "1px solid rgba(61, 255, 174, 0.08)" }}>
              <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10, display: "block" }}>
                SHA-256 Evidence Hash
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: "JetBrains Mono, monospace", color: "#f6b84a", fontSize: 11, wordBreak: "break-all" }}>
                {event.evidence_hash}
              </Typography>
            </Box>
          )}
        </Paper>

        {/* Primary AI Investigation Action */}
        <Button
          fullWidth
          variant="contained"
          startIcon={<SmartToyIcon sx={{ fontSize: 16 }} />}
          onClick={() => {
            onAskAi(`Investigate Artifact #${event.id} (${event.event_type} - ${event.target || event.object || event.description}). What is its forensic significance in this insider threat case?`);
            onClose();
          }}
          sx={{
            py: 1.2,
            bgcolor: "#3dffae",
            color: "#020806",
            fontWeight: 800,
            fontSize: 12.5,
            borderRadius: "10px",
            boxShadow: "0 0 15px rgba(61, 255, 174, 0.3)",
            "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 25px rgba(61, 255, 174, 0.5)" },
          }}
        >
          Ask Local AI About This Artifact
        </Button>
      </Box>

      {/* Footer with Prev / Next Timeline Navigation */}
      <Box
        sx={{
          p: 1.5,
          bgcolor: "#08140f",
          borderTop: "1px solid rgba(61, 255, 174, 0.12)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Button
          size="small"
          disabled={!prevEvent}
          onClick={() => prevEvent && onSelectEvent(prevEvent)}
          startIcon={<ArrowBackIcon sx={{ fontSize: 14 }} />}
          sx={{ color: prevEvent ? "#3dffae" : "#52685e", fontSize: 11 }}
        >
          {prevEvent ? `Artifact #${prevEvent.id}` : "Earliest"}
        </Button>

        <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10, fontFamily: "JetBrains Mono" }}>
          {currentIndex + 1} of {timeline.length}
        </Typography>

        <Button
          size="small"
          disabled={!nextEvent}
          onClick={() => nextEvent && onSelectEvent(nextEvent)}
          endIcon={<ArrowForwardIcon sx={{ fontSize: 14 }} />}
          sx={{ color: nextEvent ? "#3dffae" : "#52685e", fontSize: 11 }}
        >
          {nextEvent ? `Artifact #${nextEvent.id}` : "Latest"}
        </Button>
      </Box>
    </Drawer>
  );
}
