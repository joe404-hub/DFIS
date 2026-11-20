import React from "react";
import { Box } from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";

export default function EvidenceStatusBadge({ status }) {
  if (!status) return null;
  const s = String(status).toUpperCase();

  let color = "#8fa89d";
  let bg = "#0d1e16";
  let border = "rgba(61, 255, 174, 0.15)";
  let icon = null;

  if (s.includes("CONCEPT") || s.includes("INTERPRETIVE") || s.includes("DEFINITION")) {
    color = "#3dffae";
    bg = "rgba(61, 255, 174, 0.08)";
    border = "rgba(61, 255, 174, 0.3)";
    icon = <SecurityIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("NOT ESTABLISHED")) {
    color = "#8fa89d";
    bg = "#0d1e16";
    border = "#2a3f35";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>○</span>;
  } else if (s.includes("OBSERVED") || (s.includes("ESTABLISHED") && !s.includes("NOT"))) {
    color = "#3dffae";
    bg = "rgba(61, 255, 174, 0.1)";
    border = "#3dffae";
    icon = <CheckCircleOutlineIcon sx={{ fontSize: 13, mr: 0.4 }} />;
  } else if (s.includes("HYPOTHESIS") || s.includes("HYPOTHESIZED") || s.includes("INSUFFICIENT")) {
    color = "#f6b84a";
    bg = "rgba(246, 184, 74, 0.1)";
    border = "#f6b84a";
    icon = <span style={{ fontSize: "12px", marginRight: "4px", lineHeight: 1 }}>◐</span>;
  }

  return (
    <Box
      sx={{
        display: "inline-flex",
        alignItems: "center",
        px: 1,
        py: 0.25,
        borderRadius: "6px",
        fontSize: 10,
        fontWeight: 800,
        fontFamily: "JetBrains Mono, monospace",
        letterSpacing: 0.6,
        bgcolor: bg,
        color: color,
        border: `1px solid ${border}`,
      }}
    >
      {icon}
      {status}
    </Box>
  );
}
