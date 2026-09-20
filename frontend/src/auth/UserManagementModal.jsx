import React, { useState } from "react";
import {
  Avatar,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import PersonAddIcon from "@mui/icons-material/PersonAdd";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BlockIcon from "@mui/icons-material/Block";
import { useAuth } from "./AuthContext.jsx";

export default function UserManagementModal({ open, onClose, availableCases = [] }) {
  const { users, currentUser, updateUserRole, updateUserStatus, updateUserCases, registerUser, switchUser } = useAuth();

  const [addMode, setAddMode] = useState(false);
  const [form, setForm] = useState({
    name: "",
    email: "",
    username: "",
    role: "EXAMINER",
    assignedCases: ["CASE-DEMO"],
  });

  const [editingCasesUser, setEditingCasesUser] = useState(null);
  const [selectedCases, setSelectedCases] = useState([]);

  const caseOptions = availableCases.length > 0
    ? availableCases.map((c) => c.case_number)
    : ["CASE-DEMO", "CASE-001", "CASE-002", "CASE-003"];

  const handleCreateUser = (e) => {
    e?.preventDefault();
    if (!form.name || !form.email) {
      alert("Please provide a valid name and email.");
      return;
    }
    registerUser({
      name: form.name,
      email: form.email,
      username: form.username || form.email.split("@")[0],
      role: form.role,
      assignedCases: form.assignedCases,
    });
    setAddMode(false);
    setForm({ name: "", email: "", username: "", role: "EXAMINER", assignedCases: ["CASE-DEMO"] });
  };

  const handleOpenCaseEditor = (user) => {
    setEditingCasesUser(user);
    setSelectedCases(user.assignedCases || []);
  };

  const handleSaveCases = () => {
    if (editingCasesUser) {
      updateUserCases(editingCasesUser.id, selectedCases);
      setEditingCasesUser(null);
    }
  };

  const roleColor = (r) => {
    switch (r) {
      case "ADMIN": return { bg: "rgba(255, 101, 101, 0.15)", text: "#ff6565", border: "rgba(255, 101, 101, 0.3)" };
      case "EXAMINER": return { bg: "rgba(61, 255, 174, 0.15)", text: "#3dffae", border: "rgba(61, 255, 174, 0.3)" };
      case "ANALYST": return { bg: "rgba(56, 189, 248, 0.15)", text: "#38bdf8", border: "rgba(56, 189, 248, 0.3)" };
      case "VIEWER": return { bg: "rgba(246, 184, 74, 0.15)", text: "#f6b84a", border: "rgba(246, 184, 74, 0.3)" };
      default: return { bg: "#0d1e16", text: "#8fa89d", border: "rgba(61, 255, 174, 0.1)" };
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", p: 2, borderBottom: "1px solid rgba(61, 255, 174, 0.12)" }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Stack direction="row" spacing={1.2} alignItems="center">
            <AdminPanelSettingsIcon sx={{ color: "#3dffae", fontSize: 22 }} />
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 800, color: "#eefaf4", fontSize: 16 }}>
                DFIS USER ACCESS & ROLE MANAGEMENT CONSOLE
              </Typography>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5 }}>
                Role-Based Access Control (RBAC) • Case-Level Authorization Boundaries
              </Typography>
            </Box>
          </Stack>

          <IconButton size="small" onClick={onClose} sx={{ color: "#8fa89d", "&:hover": { color: "#3dffae" } }}>
            <CloseIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ bgcolor: "#050f0b", p: 2.5 }}>
        {/* Top Actions Bar */}
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={`Total Personnel: ${users.length}`}
              sx={{ height: 24, fontSize: 10.5, fontWeight: 800, bgcolor: "rgba(61, 255, 174, 0.1)", color: "#3dffae", border: "1px solid rgba(61, 255, 174, 0.2)" }}
            />
            <Chip
              label="Active Security Policy: Enforced"
              sx={{ height: 24, fontSize: 10.5, fontWeight: 700, bgcolor: "#08140f", color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.1)" }}
            />
          </Stack>

          <Button
            size="small"
            variant={addMode ? "outlined" : "contained"}
            startIcon={<PersonAddIcon sx={{ fontSize: 15 }} />}
            onClick={() => setAddMode(!addMode)}
            sx={{
              bgcolor: addMode ? "transparent" : "#3dffae",
              color: addMode ? "#3dffae" : "#020806",
              fontWeight: 800,
              fontSize: 11.5,
              borderColor: "#3dffae",
              "&:hover": { bgcolor: addMode ? "rgba(61, 255, 174, 0.1)" : "#6dffc7" },
            }}
          >
            {addMode ? "Cancel Add User" : "+ Register Forensic User"}
          </Button>
        </Stack>

        {/* Add User Form Drawer/Box */}
        {addMode && (
          <Paper sx={{ p: 2, mb: 2.5, bgcolor: "#08140f", border: "1px solid rgba(61, 255, 174, 0.25)", borderRadius: "10px" }}>
            <Typography variant="subtitle2" sx={{ color: "#3dffae", fontWeight: 800, mb: 1.5, fontSize: 13 }}>
              Provision New Forensic Personnel
            </Typography>
            <Box component="form" onSubmit={handleCreateUser} sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", md: "1fr 1fr 1fr 1fr" }, gap: 1.5, alignItems: "center" }}>
              <TextField
                size="small"
                label="FULL NAME"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
                sx={{ bgcolor: "#050f0b", borderRadius: "6px" }}
              />

              <TextField
                size="small"
                label="OFFICIAL EMAIL"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                required
                sx={{ bgcolor: "#050f0b", borderRadius: "6px" }}
              />

              <FormControl size="small" sx={{ bgcolor: "#050f0b", borderRadius: "6px" }}>
                <InputLabel sx={{ color: "#8fa89d" }}>ROLE</InputLabel>
                <Select
                  value={form.role}
                  label="ROLE"
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                  sx={{ color: "#eefaf4" }}
                >
                  <MenuItem value="EXAMINER">EXAMINER (Manage Cases & Evidence)</MenuItem>
                  <MenuItem value="ADMIN">ADMIN (Full Oversight)</MenuItem>
                  <MenuItem value="ANALYST">ANALYST (Read & Analyze)</MenuItem>
                  <MenuItem value="VIEWER">VIEWER (Read-Only Review)</MenuItem>
                </Select>
              </FormControl>

              <Button
                type="submit"
                variant="contained"
                sx={{ height: 40, bgcolor: "#3dffae", color: "#020806", fontWeight: 800 }}
              >
                Save & Provision
              </Button>
            </Box>
          </Paper>
        )}

        {/* User List Table */}
        <TableContainer sx={{ border: "1px solid rgba(61, 255, 174, 0.12)", borderRadius: "10px", mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ "& th": { bgcolor: "#08140f", color: "#8fa89d", fontWeight: 700, fontSize: 11, borderBottom: "1px solid rgba(61, 255, 174, 0.15)", py: 1.2 } }}>
                <TableCell>Personnel</TableCell>
                <TableCell>Email / Username</TableCell>
                <TableCell>Assigned Role</TableCell>
                <TableCell>Case Isolation Scope</TableCell>
                <TableCell>Account Status</TableCell>
                <TableCell align="right">Controls</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((u) => {
                const isSelf = u.id === currentUser.id;
                const rStyle = roleColor(u.role);
                return (
                  <TableRow
                    key={u.id}
                    hover
                    sx={{
                      bgcolor: isSelf ? "rgba(61, 255, 174, 0.04)" : "inherit",
                      "& td": { borderColor: "rgba(61, 255, 174, 0.06)", fontSize: 12, py: 1.2 },
                    }}
                  >
                    <TableCell>
                      <Stack direction="row" spacing={1.2} alignItems="center">
                        <Avatar sx={{ width: 26, height: 26, fontSize: 11, fontWeight: 800, bgcolor: rStyle.text, color: "#020806" }}>
                          {u.avatar || u.name[0]}
                        </Avatar>
                        <Box>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: "#eefaf4", fontSize: 12.5 }}>
                            {u.name} {isSelf && <span style={{ color: "#3dffae", fontSize: 10 }}>(You)</span>}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10 }}>
                            {u.badge}
                          </Typography>
                        </Box>
                      </Stack>
                    </TableCell>

                    <TableCell sx={{ fontFamily: "JetBrains Mono, monospace", color: "#8fa89d", fontSize: 11.5 }}>
                      {u.email}
                      <Typography variant="caption" sx={{ display: "block", color: "#52685e", fontSize: 10 }}>
                        @{u.username}
                      </Typography>
                    </TableCell>

                    <TableCell>
                      <FormControl size="small" variant="standard" sx={{ minWidth: 110 }}>
                        <Select
                          value={u.role}
                          onChange={(e) => updateUserRole(u.id, e.target.value)}
                          sx={{
                            color: rStyle.text,
                            fontWeight: 800,
                            fontSize: 11,
                            fontFamily: "JetBrains Mono",
                            bgcolor: rStyle.bg,
                            border: `1px solid ${rStyle.border}`,
                            borderRadius: "4px",
                            px: 0.8,
                            py: 0.2,
                            "& .MuiSelect-select": { py: 0.2 },
                            "&:before, &:after": { display: "none" },
                          }}
                        >
                          <MenuItem value="ADMIN">ADMIN</MenuItem>
                          <MenuItem value="EXAMINER">EXAMINER</MenuItem>
                          <MenuItem value="ANALYST">ANALYST</MenuItem>
                          <MenuItem value="VIEWER">VIEWER</MenuItem>
                        </Select>
                      </FormControl>
                    </TableCell>

                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap alignItems="center">
                        {u.role === "ADMIN" || u.assignedCases?.includes("*") ? (
                          <Chip size="small" label="All Cases (*)" sx={{ height: 18, fontSize: 9.5, fontWeight: 800, bgcolor: "rgba(61, 255, 174, 0.12)", color: "#3dffae", border: "1px solid rgba(61, 255, 174, 0.3)" }} />
                        ) : (
                          (u.assignedCases || []).map((c) => (
                            <Chip key={c} size="small" label={c} sx={{ height: 18, fontSize: 9, fontWeight: 700, fontFamily: "JetBrains Mono", bgcolor: "#08140f", color: "#8fa89d", border: "1px solid rgba(61, 255, 174, 0.1)" }} />
                          ))
                        )}
                        <Button
                          size="small"
                          onClick={() => handleOpenCaseEditor(u)}
                          sx={{ fontSize: 9.5, p: 0, minWidth: "auto", color: "#3dffae", textTransform: "none", ml: 0.5 }}
                        >
                          Edit ✎
                        </Button>
                      </Stack>
                    </TableCell>

                    <TableCell>
                      <Chip
                        size="small"
                        icon={u.status === "ACTIVE" ? <CheckCircleIcon sx={{ fontSize: "12px !important", color: "#3dffae" }} /> : <BlockIcon sx={{ fontSize: "12px !important", color: "#ff6565" }} />}
                        label={u.status || "ACTIVE"}
                        onClick={() => updateUserStatus(u.id, u.status === "ACTIVE" ? "SUSPENDED" : "ACTIVE")}
                        sx={{
                          height: 20,
                          fontSize: 9.5,
                          fontWeight: 800,
                          fontFamily: "JetBrains Mono",
                          cursor: "pointer",
                          bgcolor: u.status === "ACTIVE" ? "rgba(61, 255, 174, 0.1)" : "rgba(255, 101, 101, 0.15)",
                          color: u.status === "ACTIVE" ? "#3dffae" : "#ff6565",
                          border: `1px solid ${u.status === "ACTIVE" ? "rgba(61, 255, 174, 0.3)" : "rgba(255, 101, 101, 0.3)"}`,
                        }}
                      />
                    </TableCell>

                    <TableCell align="right">
                      {!isSelf && (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => {
                            switchUser(u.id);
                            onClose();
                          }}
                          sx={{ fontSize: 10, py: 0.2, px: 1, borderColor: "rgba(61, 255, 174, 0.25)", color: "#3dffae", textTransform: "none" }}
                        >
                          Switch Persona →
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Case Access Editor Dialog */}
        {editingCasesUser && (
          <Dialog open={Boolean(editingCasesUser)} onClose={() => setEditingCasesUser(null)} maxWidth="xs" fullWidth>
            <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", fontWeight: 800, fontSize: 15 }}>
              Assign Cases to {editingCasesUser.name}
            </DialogTitle>
            <DialogContent sx={{ bgcolor: "#050f0b", pt: 2 }}>
              <Typography variant="body2" sx={{ color: "#8fa89d", mb: 2, fontSize: 12 }}>
                Select investigations this user is authorized to access and examine:
              </Typography>

              <Stack spacing={1}>
                {caseOptions.map((cNum) => {
                  const isChecked = selectedCases.includes(cNum);
                  return (
                    <Paper
                      key={cNum}
                      onClick={() => {
                        setSelectedCases((prev) =>
                          prev.includes(cNum) ? prev.filter((x) => x !== cNum) : [...prev, cNum]
                        );
                      }}
                      sx={{
                        p: 1.2,
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        bgcolor: isChecked ? "rgba(61, 255, 174, 0.1)" : "#08140f",
                        border: `1px solid ${isChecked ? "#3dffae" : "rgba(61, 255, 174, 0.1)"}`,
                        borderRadius: "8px",
                      }}
                    >
                      <Typography sx={{ fontFamily: "JetBrains Mono", fontSize: 12, fontWeight: 700, color: isChecked ? "#3dffae" : "#eefaf4" }}>
                        {cNum}
                      </Typography>
                      <Chip
                        size="small"
                        label={isChecked ? "AUTHORIZED" : "RESTRICTED"}
                        sx={{ height: 16, fontSize: 8.5, fontWeight: 800, bgcolor: isChecked ? "#3dffae" : "#0d1e16", color: isChecked ? "#020806" : "#52685e" }}
                      />
                    </Paper>
                  );
                })}
              </Stack>
            </DialogContent>
            <DialogActions sx={{ bgcolor: "#08140f" }}>
              <Button onClick={() => setEditingCasesUser(null)} sx={{ color: "#8fa89d" }}>Cancel</Button>
              <Button onClick={handleSaveCases} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800 }}>
                Save Access Rules
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </DialogContent>

      <DialogActions sx={{ bgcolor: "#08140f", borderTop: "1px solid rgba(61, 255, 174, 0.1)", p: 1.5 }}>
        <Button onClick={onClose} variant="contained" sx={{ bgcolor: "#3dffae", color: "#020806", fontWeight: 800, fontSize: 11 }}>
          Done
        </Button>
      </DialogActions>
    </Dialog>
  );
}
