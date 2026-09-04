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
  Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import SecurityIcon from "@mui/icons-material/Security";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
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
  tableContainerRef,
  onOpenAcquire,
  onUploadFile,
}) {
  return (
    <Box sx={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, overflow: "hidden" }}>
      {/* 1. DEDICATED TIMELINE CONTROLS BAR */}
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
            flex: { xs: "1 1 100%", sm: "1 1 220px" },
            maxWidth: { sm: 340 },
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

      {/* 2. VISUAL TIMELINE MAP */}
      <Box
        className="timeline-map"
        sx={{
          flex: "0 0 260px",
          minHeight: "240px",
          maxHeight: "280px",
          p: "8px 16px",
          bgcolor: "#050f0b",
          borderBottom: "1px solid rgba(61, 255, 174, 0.12)",
          overflow: "hidden",
          position: "relative",
        }}
      >
        <Box ref={tlRef} sx={{ width: "100%", height: "100%" }} />
      </Box>

      {/* 3. SELECTED EVENT INSPECTOR STRIP */}
      {selectedEvent && (
        <Box
          sx={{
            flexShrink: 0,
            p: "6px 16px",
            bgcolor: "#0d1e16",
            borderBottom: "1px solid rgba(61, 255, 174, 0.2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 1.5,
          }}
        >
          <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
            <Box
              sx={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 10,
                fontWeight: 800,
                px: 0.8,
                py: 0.2,
                borderRadius: "4px",
                bgcolor: "rgba(61, 255, 174, 0.12)",
                color: "#3dffae",
                border: "1px solid rgba(61, 255, 174, 0.3)",
              }}
            >
              Artifact #{selectedEvent.id}
            </Box>
            <Chip
              size="small"
              label={selectedEvent.source_type}
              sx={{ bgcolor: sourceColor(selectedEvent.source_type), color: "#fff", fontWeight: 700, height: 18, fontSize: 9.5 }}
            />
            <Typography variant="body2" sx={{ color: "#eefaf4", fontWeight: 700, fontSize: 12, whiteSpace: "nowrap" }}>
              {selectedEvent.event_type}
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {selectedEvent.description}
            </Typography>
          </Stack>

          <Button
            size="small"
            onClick={() => setSelectedEvent(null)}
            sx={{ color: "#8fa89d", fontSize: 10.5, minWidth: "auto", py: 0.2, px: 0.8 }}
          >
            Close
          </Button>
        </Box>
      )}

      {/* 4. CHRONOLOGICAL EVENT TABLE */}
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
              <TableCell sx={{ width: 220 }}>Action & Object</TableCell>
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
                  sx={{
                    cursor: "pointer",
                    bgcolor: isSelected
                      ? "rgba(61, 255, 174, 0.12) !important"
                      : e.source_type === "correlated"
                      ? "rgba(61, 255, 174, 0.03)"
                      : "inherit",
                    borderLeft: isSelected ? "3px solid #3dffae" : "3px solid transparent",
                    "& td": {
                      borderColor: "rgba(61, 255, 174, 0.06)",
                      fontSize: 12,
                      py: 0.8,
                      color: isSelected ? "#eefaf4" : "#8fa89d",
                    },
                    "&:hover": { bgcolor: "rgba(61, 255, 174, 0.06) !important" },
                  }}
                >
                  <TableCell sx={{ pl: 2, fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap", color: isSelected ? "#3dffae" : "#3dffae", fontSize: 11 }}>
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
                  <TableCell sx={{ color: "#8fa89d" }}>
                    {e.user || e.actor || "—"} {e.host ? `(${e.host})` : ""}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", color: "#eefaf4" }}>{e.action || "—"}</Typography>
                    <Typography variant="caption" sx={{ color: "#8fa89d", fontFamily: "JetBrains Mono, monospace", fontSize: 10.5 }}>
                      {e.target || e.object || "—"}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ color: "#8fa89d", maxWidth: 300, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {e.description}
                  </TableCell>
                  <TableCell align="right" sx={{ pr: 2 }}>
                    <Box
                      component="span"
                      sx={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 10.5,
                        color: "#3dffae",
                        bgcolor: "rgba(61, 255, 174, 0.06)",
                        px: 0.8,
                        py: 0.2,
                        borderRadius: "4px",
                        border: "1px solid rgba(61, 255, 174, 0.15)",
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
