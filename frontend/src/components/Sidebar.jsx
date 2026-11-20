import React from "react";
import {
  Box,
  Button,
  Chip,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import PushPinIcon from "@mui/icons-material/PushPin";
import PushPinOutlinedIcon from "@mui/icons-material/PushPinOutlined";

export default function Sidebar({
  sidebarOpen,
  sidebarPinned,
  openSidebar,
  scheduleCloseSidebar,
  togglePinSidebar,
  filteredCases,
  active,
  setActive,
  setSidebarOpen,
  caseSearch,
  setCaseSearch,
  setOpenNewCase,
}) {
  return (
    <>
      {/* LEFT EDGE REVEAL TRIGGER (HOT ZONE) */}
      {!sidebarPinned && (
        <Box
          onMouseEnter={openSidebar}
          sx={{
            position: "fixed",
            top: 56,
            left: 0,
            width: 14,
            height: "calc(100vh - 56px)",
            zIndex: 1100,
            cursor: "pointer",
            background: "transparent",
            transition: "background 0.2s ease",
            "&:hover": {
              background: "linear-gradient(90deg, rgba(61, 255, 174, 0.18), transparent)",
            },
          }}
        />
      )}

      {/* LEFT EDGE GLOWING STRIPE INDICATOR (WHEN UNPINNED) */}
      {!sidebarPinned && (
        <Box
          onMouseEnter={openSidebar}
          onClick={openSidebar}
          title="Hover to reveal Investigations (Ctrl+B to pin)"
          sx={{
            position: "fixed",
            top: "50%",
            left: 0,
            width: sidebarOpen ? 0 : 4,
            height: 70,
            transform: "translateY(-50%)",
            borderRadius: "0 8px 8px 0",
            background: "linear-gradient(to bottom, transparent, #3dffae, transparent)",
            opacity: 0.6,
            zIndex: 1099,
            cursor: "pointer",
            transition: "all 0.2s ease",
            boxShadow: "0 0 10px rgba(61, 255, 174, 0.4)",
            "&:hover": {
              width: 7,
              opacity: 1,
              boxShadow: "0 0 18px rgba(61, 255, 174, 0.8)",
            },
          }}
        />
      )}

      {/* PROGRESSIVE REVEAL SIDEBAR */}
      <Box
        component="aside"
        onMouseEnter={openSidebar}
        onMouseLeave={scheduleCloseSidebar}
        sx={{
          position: "fixed",
          top: 56,
          left: 0,
          width: 280,
          height: "calc(100vh - 56px)",
          zIndex: 1200,
          display: "flex",
          flexDirection: "column",
          bgcolor: "#050f0b",
          background: "linear-gradient(180deg, rgba(8, 20, 15, 0.98), rgba(2, 8, 6, 0.99))",
          backdropFilter: "blur(16px)",
          borderRight: "1px solid rgba(61, 255, 174, 0.15)",
          boxShadow: sidebarOpen && !sidebarPinned ? "20px 0 60px rgba(0, 0, 0, 0.75)" : "none",
          transform: sidebarOpen || sidebarPinned ? "translateX(0)" : "translateX(-280px)",
          transition: "transform 320ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 320ms ease",
          overflow: "hidden",
        }}
      >
        {/* SIDEBAR HEADER */}
        <Box sx={{ p: 2, pb: 1.5, borderBottom: "1px solid rgba(61, 255, 174, 0.08)" }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography
                variant="overline"
                sx={{
                  fontWeight: 800,
                  letterSpacing: "0.14em",
                  color: "#3dffae",
                  fontSize: 10.5,
                  textTransform: "uppercase",
                }}
              >
                INVESTIGATIONS
              </Typography>
              <Chip
                size="small"
                label={filteredCases.length}
                sx={{
                  height: 18,
                  fontSize: 9.5,
                  fontWeight: 800,
                  fontFamily: "JetBrains Mono, monospace",
                  bgcolor: "rgba(61, 255, 174, 0.1)",
                  color: "#3dffae",
                  border: "1px solid rgba(61, 255, 174, 0.2)",
                }}
              />
            </Stack>

            <Tooltip title={sidebarPinned ? "Unpin sidebar (auto-hide mode)" : "Pin sidebar open (Ctrl+B)"} arrow>
              <IconButton
                size="small"
                onClick={togglePinSidebar}
                sx={{
                  color: sidebarPinned ? "#3dffae" : "#8fa89d",
                  bgcolor: sidebarPinned ? "rgba(61, 255, 174, 0.12)" : "transparent",
                  border: `1px solid ${sidebarPinned ? "rgba(61, 255, 174, 0.3)" : "rgba(61, 255, 174, 0.1)"}`,
                  "&:hover": { color: "#3dffae", borderColor: "#3dffae" },
                }}
              >
                {sidebarPinned ? <PushPinIcon sx={{ fontSize: 14 }} /> : <PushPinOutlinedIcon sx={{ fontSize: 14 }} />}
              </IconButton>
            </Tooltip>
          </Stack>

          {/* SEARCH INPUT */}
          <TextField
            size="small"
            fullWidth
            placeholder="Search cases..."
            value={caseSearch}
            onChange={(e) => setCaseSearch(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ color: "#52685e", fontSize: 16 }} />
                </InputAdornment>
              ),
            }}
            sx={{
              mt: 1.5,
              bgcolor: "#020806",
              borderRadius: "8px",
              "& .MuiOutlinedInput-root": {
                fontSize: 12,
                fontFamily: "Inter, sans-serif",
                "& fieldset": { borderColor: "rgba(61, 255, 174, 0.12)" },
                "&:hover fieldset": { borderColor: "#3dffae" },
              },
            }}
          />
        </Box>

        {/* CASE LIST */}
        <List sx={{ px: 1, py: 1, flex: 1, overflowY: "auto" }}>
          {filteredCases.map((c) => {
            const isSel = c.id === active;
            return (
              <ListItemButton
                key={c.id}
                selected={isSel}
                onClick={() => {
                  setActive(c.id);
                  if (!sidebarPinned) {
                    setSidebarOpen(false);
                  }
                }}
                sx={{
                  borderRadius: "8px",
                  mb: 0.8,
                  py: 1,
                  px: 1.2,
                  border: isSel ? "1px solid rgba(61, 255, 174, 0.25)" : "1px solid transparent",
                  borderLeft: isSel ? "3px solid #3dffae !important" : "1px solid transparent",
                  background: isSel
                    ? "linear-gradient(90deg, rgba(61, 255, 174, 0.14), rgba(61, 255, 174, 0.02)) !important"
                    : "transparent",
                  "&:hover": {
                    bgcolor: "#0d1e16",
                  },
                }}
              >
                <Box sx={{ width: "100%", display: "grid", gridTemplateColumns: "10px 1fr auto", gap: 1, alignItems: "start" }}>
                  <Box
                    sx={{
                      width: 6,
                      height: 6,
                      mt: 0.8,
                      borderRadius: "50%",
                      bgcolor: isSel ? "#3dffae" : "transparent",
                      border: `1px solid ${isSel ? "#3dffae" : "#52685e"}`,
                      boxShadow: isSel ? "0 0 8px #3dffae" : "none",
                    }}
                  />

                  <Box sx={{ minWidth: 0 }}>
                    <Typography
                      variant="subtitle2"
                      sx={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontWeight: isSel ? 800 : 600,
                        color: isSel ? "#3dffae" : "#8fa89d",
                        fontSize: 12,
                      }}
                    >
                      {c.case_number}
                    </Typography>
                    <Typography
                      variant="body2"
                      sx={{
                        fontSize: 11.5,
                        color: isSel ? "#eefaf4" : "#8fa89d",
                        fontWeight: isSel ? 600 : 400,
                        lineHeight: 1.25,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        mt: 0.2,
                      }}
                    >
                      {c.title}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10, display: "block", mt: 0.2 }}>
                      {c.artifact_count} artifacts • {c.evidence_count} evidence
                    </Typography>
                  </Box>

                  <Chip
                    size="small"
                    label={`${c.risk_score ?? 0}`}
                    sx={{
                      height: 18,
                      fontSize: 9.5,
                      fontWeight: 800,
                      fontFamily: "JetBrains Mono, monospace",
                      bgcolor: c.risk_score >= 40 ? "rgba(255, 101, 101, 0.15)" : "rgba(61, 255, 174, 0.1)",
                      color: c.risk_score >= 40 ? "#ff6565" : "#3dffae",
                      border: `1px solid ${c.risk_score >= 40 ? "rgba(255, 101, 101, 0.3)" : "rgba(61, 255, 174, 0.2)"}`,
                    }}
                  />
                </Box>
              </ListItemButton>
            );
          })}
        </List>

        {/* SIDEBAR FOOTER */}
        <Box sx={{ p: 2, borderTop: "1px solid rgba(61, 255, 174, 0.08)" }}>
          <Button
            fullWidth
            variant="outlined"
            size="small"
            onClick={() => setOpenNewCase(true)}
            sx={{
              borderColor: "rgba(61, 255, 174, 0.2)",
              color: "#3dffae",
              fontSize: 11.5,
              fontWeight: 700,
              py: 0.8,
              "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.06)" },
            }}
          >
            + New Investigation
          </Button>
        </Box>
      </Box>
    </>
  );
}
