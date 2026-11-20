import React, { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import CloseIcon from "@mui/icons-material/Close";
import SearchIcon from "@mui/icons-material/Search";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { useAuth } from "./AuthContext.jsx";

export default function AuditTrailModal({ open, onClose }) {
  const { auditLogs } = useAuth();
  const [filter, setFilter] = useState("");

  const filteredLogs = auditLogs.filter((log) => {
    if (!filter.trim()) return true;
    const f = filter.toLowerCase();
    return (
      log.action.toLowerCase().includes(f) ||
      log.actor.toLowerCase().includes(f) ||
      log.resourceType.toLowerCase().includes(f) ||
      log.resourceId.toLowerCase().includes(f) ||
      log.details.toLowerCase().includes(f)
    );
  });

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", p: 2, borderBottom: "1px solid rgba(61, 255, 174, 0.12)" }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Stack direction="row" spacing={1.2} alignItems="center">
            <SecurityIcon sx={{ color: "#3dffae", fontSize: 20 }} />
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 800, color: "#eefaf4", fontSize: 15 }}>
                FORENSIC SECURITY AUDIT TRAIL
              </Typography>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10 }}>
                Immutable local action records & session custody log
              </Typography>
            </Box>
          </Stack>

          <IconButton size="small" onClick={onClose} sx={{ color: "#8fa89d", "&:hover": { color: "#3dffae" } }}>
            <CloseIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ bgcolor: "#050f0b", p: 2 }}>
        {/* Controls Bar */}
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }}>
          <TextField
            size="small"
            fullWidth
            placeholder="Search audit trail (actor, action, case ID, artifact)..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ color: "#52685e", fontSize: 16 }} />
                </InputAdornment>
              ),
            }}
            sx={{
              bgcolor: "#08140f",
              borderRadius: "8px",
              "& .MuiOutlinedInput-root": {
                height: 34,
                fontSize: 12,
                fontFamily: "JetBrains Mono",
                "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                "&:hover fieldset": { borderColor: "#3dffae" },
              },
            }}
          />

          <Chip
            size="small"
            label={`${filteredLogs.length} Records`}
            sx={{
              height: 24,
              fontSize: 10,
              fontWeight: 800,
              fontFamily: "JetBrains Mono",
              bgcolor: "rgba(61, 255, 174, 0.1)",
              color: "#3dffae",
              border: "1px solid rgba(61, 255, 174, 0.25)",
            }}
          />
        </Stack>

        {/* Audit Table */}
        <TableContainer sx={{ border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "8px", maxHeight: 420 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow sx={{ "& th": { bgcolor: "#08140f", color: "#8fa89d", fontWeight: 700, fontSize: 11, borderBottom: "1px solid rgba(61, 255, 174, 0.15)", py: 1 } }}>
                <TableCell sx={{ width: 140 }}>Timestamp (UTC)</TableCell>
                <TableCell sx={{ width: 140 }}>Actor & Role</TableCell>
                <TableCell sx={{ width: 170 }}>Action</TableCell>
                <TableCell sx={{ width: 100 }}>Resource</TableCell>
                <TableCell>Audit Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredLogs.map((log) => (
                <TableRow key={log.id} hover sx={{ "& td": { borderColor: "rgba(61, 255, 174, 0.06)", fontSize: 11.5, py: 0.8 } }}>
                  <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", color: "#3dffae", whiteSpace: "nowrap" }}>
                    {log.timestamp}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: 11.5, fontWeight: 700, color: "#eefaf4" }}>
                      {log.actor}
                    </Typography>
                    <Chip
                      size="small"
                      label={log.role}
                      sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: "#0d1e16", color: "#8fa89d", mt: 0.2 }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", fontWeight: 700, color: "#6dffc7" }}>
                    {log.action}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={`${log.resourceType}: ${log.resourceId}`}
                      sx={{ height: 18, fontSize: 9, fontWeight: 700, fontFamily: "JetBrains Mono", bgcolor: "rgba(61, 255, 174, 0.08)", color: "#3dffae" }}
                    />
                  </TableCell>
                  <TableCell sx={{ color: "#8fa89d", fontSize: 11 }}>
                    {log.details}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </DialogContent>

      <DialogActions sx={{ bgcolor: "#08140f", borderTop: "1px solid rgba(61, 255, 174, 0.1)", p: 1.5 }}>
        <Button
          size="small"
          startIcon={<ContentCopyIcon sx={{ fontSize: 13 }} />}
          onClick={() => {
            navigator.clipboard?.writeText(JSON.stringify(auditLogs, null, 2));
            alert("Audit log exported to clipboard as JSON!");
          }}
          sx={{ color: "#8fa89d", fontSize: 11 }}
        >
          Export Log JSON
        </Button>
        <Button onClick={onClose} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800, fontSize: 11 }}>
          Done
        </Button>
      </DialogActions>
    </Dialog>
  );
}
