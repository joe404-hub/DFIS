import React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Box } from "@mui/material";

export default function MarkdownView({ content, onFocusEvidence }) {
  if (!content) return null;
  const safeContent = typeof content === "string" ? content : String(content || "");
  if (!safeContent.trim()) return null;

  return (
    <Box
      sx={{
        color: "#eefaf4",
        fontSize: "12.5px",
        lineHeight: 1.65,
        "& h1, & h2, & h3, & h4": {
          color: "#eefaf4",
          fontWeight: 700,
          mt: 1.2,
          mb: 0.5,
          lineHeight: 1.3,
        },
        "& h1": { fontSize: "15px", color: "#3dffae" },
        "& h2": { fontSize: "14px", color: "#3dffae" },
        "& h3": { fontSize: "13px", color: "#6dffc7" },
        "& p": { my: 0.5, color: "#8fa89d" },
        "& ul, & ol": { my: 0.5, pl: 2 },
        "& li": { my: 0.3, color: "#eefaf4" },
        "& strong": { color: "#eefaf4", fontWeight: 700 },
        "& table": {
          width: "100%",
          borderCollapse: "collapse",
          my: 1.2,
          fontSize: "11px",
          display: "table",
          overflowX: "auto",
        },
        "& th": {
          bgcolor: "#050f0b",
          color: "#3dffae",
          p: "6px 8px",
          borderBottom: "1px solid rgba(61, 255, 174, 0.2)",
          textAlign: "left",
          fontWeight: 700,
        },
        "& td": {
          p: "5px 8px",
          borderBottom: "1px solid rgba(61, 255, 174, 0.08)",
          color: "#8fa89d",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "10.5px",
        },
        "& tr:hover": {
          bgcolor: "rgba(61, 255, 174, 0.05)",
        },
        "& code": {
          bgcolor: "rgba(61, 255, 174, 0.06)",
          border: "1px solid rgba(61, 255, 174, 0.18)",
          color: "#3dffae",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11px",
          px: 0.5,
          py: 0.1,
          borderRadius: "4px",
        },
        "& pre": {
          bgcolor: "#050f0b",
          p: 1,
          borderRadius: "8px",
          overflowX: "auto",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11px",
          border: "1px solid rgba(61, 255, 174, 0.1)",
        },
        "& blockquote": {
          borderLeft: "3px solid #3dffae",
          pl: 1,
          my: 0.6,
          color: "#8fa89d",
        },
      }}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {safeContent}
      </ReactMarkdown>
    </Box>
  );
}
