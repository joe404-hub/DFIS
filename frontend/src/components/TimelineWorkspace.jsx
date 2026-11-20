import React from "react";
import {
  Box,
  Button,
  Chip,
  IconButton,
  InputAdornment,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import SecurityIcon from "@mui/icons-material/Security";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import ZoomInIcon from "@mui/icons-material/ZoomIn";
import ZoomOutIcon from "@mui/icons-material/ZoomOut";
import CenterFocusStrongIcon from "@mui/icons-material/CenterFocusStrong";
import VisibilityIcon from "@mui/icons-material/Visibility";
import CloseIcon from "@mui/icons-material/Close";
import { sourceColor } from "../utils/forensicParser.js";

export default function TimelineWorkspace({
  timeline,
  filteredTimeline,
  search,
  setSearch,
  sourceFilter,
  setSourceFilter,
  selectedEvent,
  setSelectedEvent,
  handleSelectEvent,
  tlRef,
  tlInst,
  tableContainerRef,
  onOpenAcquire,
  onUploadFile,
  onOpenInspector,
}) {
  const handleZoomIn = () => {
    if (tlInst && tlInst.current) {
      try {
        tlInst.current.zoomIn(0.4);
      } catch {}
    }
  };

  const handleZoomOut = () => {
    if (tlInst && tlInst.current) {
      try {
        tlInst.current.zoomOut(0.4);
      } catch {}
    }
  };

  const handleFit = () => {
    if (tlInst && tlInst.current) {
      try {
        tlInst.current.fit({ animation: { duration: 300, easingFunction: "easeInOutQuad" } });
      } catch {}
    }
  };

  return (
    <Box sx={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, overflow: "hidden" }}>
      {/* 1. TIMELINE CONTROLS BAR (Search + Filter Chips + Actions) */}
      <Box
        className="timeline-controls"
        sx={{
          flexShrink: 0,
          p: "10px 16px",
          bgcolor: "#081410",
          borderBottom: "1px solid rgba(61, 255, 174, 0.1)",
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 1.2,
        }}
      >
        {/* Search Input */}
        <TextField
          size="small"
          placeholder="Search timeline (user, process, artifact, IP, action)..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon sx={{ color: "#52685e", fontSize: 17 }} />
              </InputAdornment>
            ),
            endAdornment: search ? (
              <InputAdornment position="end">
                <IconButton size="small" onClick={() => setSearch("")} sx={{ color: "#52685e" }}>
                  <ClearIcon sx={{ fontSize: 14 }} />
                </IconButton>
              </InputAdornment>
            ) : null,
          }}
          sx={{
            flex: { xs: "1 1 100%", sm: "1 1 200px" },
            maxWidth: { sm: 300 },
            bgcolor: "#030806",
            borderRadius: "8px",
            "& .MuiOutlinedInput-root": {
              height: 32,
              fontSize: 12,
              "& fieldset": { borderColor: "rgba(61, 255, 174, 0.14)" },
              "&:hover fieldset": { borderColor: "#3dffae" },
              "&.Mui-focused fieldset": { borderColor: "#3dffae" },
            },
          }}
        />

        {/* Filter Chips */}
        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap alignItems="center">
          {["all", "windows_event", "registry", "browser", "network", "filesystem", "memory", "correlated"].map((src) => (
            <Chip
              key={src}
              size="small"
              label={src === "all" ? `All (${timeline.length})` : src.replace("_", " ")}
              clickable
              onClick={() => setSourceFilter(src)}
              sx={{
                height: 24,
                textTransform: "capitalize",
                fontSize: 10.5,
                fontWeight: 600,
                bgcolor: sourceFilter === src ? "rgba(61, 255, 174, 0.16)" : "transparent",
                color: sourceFilter === src ? "#3dffae" : "#8fa89d",
                border: `1px solid ${sourceFilter === src ? "#3dffae" : "rgba(61, 255, 174, 0.1)"}`,
                "&:hover": { bgcolor: "rgba(61, 255, 174, 0.08)" },
              }}
            />
          ))}
        </Stack>

        {/* Evidence Actions */}
        <Stack direction="row" spacing={0.8} alignItems="center">
          <Button
            size="small"
            variant="outlined"
            startIcon={<SecurityIcon sx={{ fontSize: 13 }} />}
            onClick={onOpenAcquire}
            sx={{
              fontSize: 10.5,
              fontWeight: 700,
              height: 26,
              px: 1,
              borderColor: "rgba(61, 255, 174, 0.25)",
              color: "#3dffae",
              "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.08)" },
            }}
          >
            Acquire
          </Button>
          <Button
            size="small"
            variant="outlined"
            component="label"
            startIcon={<CloudUploadIcon sx={{ fontSize: 13 }} />}
            sx={{
              fontSize: 10.5,
              height: 26,
              px: 1,
              borderColor: "rgba(61, 255, 174, 0.15)",
              color: "#8fa89d",
              "&:hover": { color: "#eefaf4", borderColor: "#8fa89d" },
            }}
          >
            Import
            <input hidden type="file" onChange={(e) => e.target.files[0] && onUploadFile(e.target.files[0])} />
          </Button>
        </Stack>
      </Box>

      {/* 2. VISUAL TIMELINE MAP SECTION (Increased proportional height 46–50%) */}
      <Box
        className="timeline-map"
        sx={{
          flex: "0 0 350px",
          minHeight: "320px",
          maxHeight: "440px",
          p: "8px 16px",
          bgcolor: "#050f0b",
          borderBottom: "1px solid rgba(61, 255, 174, 0.12)",
          overflow: "hidden",
          position: "relative",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Header with Title & Zoom Controls */}
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.6, flexShrink: 0 }}>
          <Typography variant="overline" sx={{ color: "#3dffae", fontWeight: 800, fontSize: 10, letterSpacing: "0.12em" }}>
            VISUAL EVENT TIMELINE & CORRELATION LANES
          </Typography>

          <Stack direction="row" spacing={0.6} alignItems="center">
            <Tooltip title="Zoom in timeline" arrow>
              <IconButton
                size="small"
                onClick={handleZoomIn}
                sx={{
                  color: "#8fa89d",
                  bgcolor: "#08140f",
                  border: "1px solid rgba(61, 255, 174, 0.15)",
                  width: 24,
                  height: 24,
                  "&:hover": { color: "#3dffae", borderColor: "#3dffae" },
                }}
              >
                <ZoomInIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>

            <Tooltip title="Zoom out timeline" arrow>
              <IconButton
                size="small"
                onClick={handleZoomOut}
                sx={{
                  color: "#8fa89d",
                  bgcolor: "#08140f",
                  border: "1px solid rgba(61, 255, 174, 0.15)",
                  width: 24,
                  height: 24,
                  "&:hover": { color: "#3dffae", borderColor: "#3dffae" },
                }}
              >
                <ZoomOutIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>

            <Tooltip title="Fit all events in view" arrow>
              <IconButton
                size="small"
                onClick={handleFit}
                sx={{
                  color: "#8fa89d",
                  bgcolor: "#08140f",
                  border: "1px solid rgba(61, 255, 174, 0.15)",
                  width: 24,
                  height: 24,
                  "&:hover": { color: "#3dffae", borderColor: "#3dffae" },
                }}
              >
                <CenterFocusStrongIcon sx={{ fontSize: 13 }} />
              </IconButton>
            </Tooltip>
          </Stack>
        </Box>

        {/* Vis Timeline Canvas */}
        <Box ref={tlRef} sx={{ width: "100%", flex: 1, minHeight: 0 }} />
      </Box>

      {/* 3. REDESIGNED SELECTED EVENT CONTEXT CARD (Strong, high-contrast, height ~46px) */}
      {selectedEvent && (
        <Box
          className="selected-event-bar"
          sx={{
            flexShrink: 0,
            px: 2,
            py: 1,
            bgcolor: "#0b1c14",
            borderBottom: "1px solid rgba(61, 255, 174, 0.3)",
            boxShadow: "inset 0 0 20px rgba(61, 255, 174, 0.08)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 1.5,
          }}
        >
          {/* Left Context Tokens */}
          <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
            <Box
              sx={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 11,
                fontWeight: 800,
                px: 1,
                py: 0.25,
                borderRadius: "5px",
                bgcolor: "rgba(61, 255, 174, 0.16)",
                color: "#3dffae",
                border: "1px solid rgba(61, 255, 174, 0.4)",
                boxShadow: "0 0 10px rgba(61, 255, 174, 0.2)",
                whiteSpace: "nowrap",
              }}
            >
              #{selectedEvent.id}
            </Box>

            <Chip
              size="small"
              label={selectedEvent.source_type}
              sx={{
                bgcolor: sourceColor(selectedEvent.source_type),
                color: "#fff",
                fontWeight: 800,
                height: 20,
                fontSize: 9.5,
                textTransform: "uppercase",
              }}
            />

            <Box sx={{ minWidth: 0 }}>
              <Stack direction="row" spacing={0.8} alignItems="baseline">
                <Typography variant="body2" sx={{ color: "#eefaf4", fontWeight: 800, fontSize: 12.5, whiteSpace: "nowrap" }}>
                  {selectedEvent.event_type}
                </Typography>
                {selectedEvent.target && (
                  <Typography variant="caption" sx={{ color: "#3dffae", fontFamily: "JetBrains Mono, monospace", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    → {selectedEvent.target}
                  </Typography>
                )}
              </Stack>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11, display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {selectedEvent.description}
              </Typography>
            </Box>
          </Stack>

          {/* Right Action Buttons */}
          <Stack direction="row" spacing={0.8} alignItems="center" sx={{ flexShrink: 0 }}>
            <Button
              size="small"
              variant="outlined"
              startIcon={<VisibilityIcon sx={{ fontSize: 13 }} />}
              onClick={onOpenInspector}
              sx={{
                fontSize: 10.5,
                fontWeight: 700,
                py: 0.2,
                px: 1,
                borderColor: "rgba(61, 255, 174, 0.3)",
                color: "#3dffae",
                "&:hover": { borderColor: "#3dffae", bgcolor: "rgba(61, 255, 174, 0.1)" },
              }}
            >
              Inspect 🔍
            </Button>

            <IconButton
              size="small"
              onClick={() => setSelectedEvent(null)}
              title="Clear Selection"
              sx={{ color: "#8fa89d", "&:hover": { color: "#ff6565" } }}
            >
              <CloseIcon sx={{ fontSize: 16 }} />
            </IconButton>
          </Stack>
        </Box>
      )}

      {/* 4. STRONG SECTION DIVIDER (Explicit separation between Timeline Visual and Event Log) */}
      <Box
        className="timeline-section-divider"
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          px: 2,
          py: 0.8,
          bgcolor: "#07120e",
          borderTop: "1px solid rgba(61, 255, 174, 0.12)",
          borderBottom: "1px solid rgba(61, 255, 174, 0.1)",
          flexShrink: 0,
        }}
      >
        <Stack direction="row" spacing={1.2} alignItems="center">
          <Typography sx={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.12em", color: "#3dffae", textTransform: "uppercase" }}>
            EVENT LOG
          </Typography>
          <Chip
            size="small"
            label={`${filteredTimeline.length} EVENTS`}
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
        <Typography variant="caption" sx={{ color: "#52685e", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}>
          Click row to select • Double click to inspect
        </Typography>
      </Box>

      {/* 5. SYNCHRONIZED CHRONOLOGICAL EVENT TABLE */}
      <Box
        ref={tableContainerRef}
        className="timeline-events"
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          bgcolor: "#06100d",
        }}
      >
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow sx={{ "& th": { bgcolor: "#08140f", color: "#8fa89d", fontWeight: 700, fontSize: 11, borderBottom: "1px solid rgba(61, 255, 174, 0.15)", py: 1 } }}>
              <TableCell sx={{ pl: 2, width: 140 }}>Timestamp (UTC)</TableCell>
              <TableCell sx={{ width: 130 }}>Source & Type</TableCell>
              <TableCell sx={{ width: 130 }}>Actor / Host</TableCell>
              <TableCell sx={{ width: 230 }}>Action & Object</TableCell>
              <TableCell>Forensic Description</TableCell>
              <TableCell align="right" sx={{ pr: 2, width: 80 }}>Provenance</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredTimeline.map((e) => {
              const isSelected = selectedEvent?.id === e.id;
              return (
                <TableRow
                  key={e.id || e.fingerprint}
                  id={`timeline-row-${e.id}`}
                  hover
                  onClick={() => handleSelectEvent(e)}
                  onDoubleClick={() => {
                    handleSelectEvent(e);
                    if (onOpenInspector) onOpenInspector();
                  }}
                  sx={{
                    cursor: "pointer",
                    bgcolor: isSelected
                      ? "rgba(61, 255, 174, 0.14) !important"
                      : e.source_type === "correlated"
                      ? "rgba(61, 255, 174, 0.03)"
                      : "inherit",
                    borderLeft: isSelected ? "3px solid #3dffae !important" : "3px solid transparent",
                    boxShadow: isSelected ? "inset 0 0 20px rgba(61, 255, 174, 0.06)" : "none",
                    "& td": {
                      borderColor: "rgba(61, 255, 174, 0.06)",
                      fontSize: 12,
                      py: 0.9,
                      color: isSelected ? "#eefaf4" : "#8fa89d",
                    },
                    "&:hover": { bgcolor: "rgba(61, 255, 174, 0.06) !important" },
                  }}
                >
                  <TableCell sx={{ pl: 2, fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap", color: isSelected ? "#3dffae" : "#3dffae", fontSize: 11, fontWeight: isSelected ? 700 : 500 }}>
                    {e.timestamp ? e.timestamp.replace("T", " ") : "Observation"}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={e.artifact_type || e.source_type}
                      sx={{
                        height: 18,
                        fontSize: 9.5,
                        fontWeight: 700,
                        bgcolor: sourceColor(e.source_type),
                        color: "#fff",
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ color: isSelected ? "#eefaf4" : "#8fa89d", fontWeight: isSelected ? 600 : 400 }}>
                    {e.user || e.actor || "—"} {e.host ? `(${e.host})` : ""}
                  </TableCell>
                  <TableCell>
                    {/* Two-level Action & Object hierarchy */}
                    <Typography sx={{ fontSize: "11px", fontWeight: 700, color: isSelected ? "#3dffae" : "#eefaf4", textTransform: "uppercase", letterSpacing: "0.02em" }}>
                      {e.action || e.event_type || "—"}
                    </Typography>
                    <Typography sx={{ fontSize: "10.5px", color: isSelected ? "#8fa89d" : "#52685e", fontFamily: "JetBrains Mono, monospace", mt: 0.3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {e.target || e.object || "—"}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ color: isSelected ? "#eefaf4" : "#8fa89d", maxWidth: 320, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {e.description}
                  </TableCell>
                  <TableCell align="right" sx={{ pr: 2 }}>
                    <Box
                      component="span"
                      sx={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 10.5,
                        fontWeight: 700,
                        color: isSelected ? "#020806" : "#3dffae",
                        bgcolor: isSelected ? "#3dffae" : "rgba(61, 255, 174, 0.08)",
                        px: 0.8,
                        py: 0.2,
                        borderRadius: "4px",
                        border: `1px solid ${isSelected ? "#3dffae" : "rgba(61, 255, 174, 0.2)"}`,
                        boxShadow: isSelected ? "0 0 8px #3dffae" : "none",
                      }}
                    >
                      #{e.id}
                    </Box>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Box>
    </Box>
  );
}
