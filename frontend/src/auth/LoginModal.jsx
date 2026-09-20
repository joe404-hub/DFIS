import React, { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import LockIcon from "@mui/icons-material/Lock";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import SecurityIcon from "@mui/icons-material/Security";
import { useAuth } from "./AuthContext.jsx";

export default function LoginModal({ open, onClose }) {
  const { presetUsers, login, currentUser } = useAuth();
  const [selectedPreset, setSelectedPreset] = useState(currentUser || presetUsers[0]);
  const [email, setEmail] = useState(selectedPreset.email);
  const [password, setPassword] = useState("••••••••••••");
  const [showPassword, setShowPassword] = useState(false);

  const handleSelectPreset = (user) => {
    setSelectedPreset(user);
    setEmail(user.email);
    setPassword("••••••••••••");
  };

  const handleLoginSubmit = (e) => {
    e?.preventDefault();
    login(email, password, selectedPreset.role);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ bgcolor: "#08140f", color: "#3dffae", p: 2.5, pb: 1.5, borderBottom: "1px solid rgba(61, 255, 174, 0.12)" }}>
        <Stack direction="row" spacing={1.2} alignItems="center">
          <Box
            sx={{
              width: 32,
              height: 32,
              borderRadius: "8px",
              bgcolor: "rgba(61, 255, 174, 0.1)",
              border: "1px solid rgba(61, 255, 174, 0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <FingerprintIcon sx={{ color: "#3dffae", fontSize: 20 }} />
          </Box>
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 800, fontSize: 16, color: "#eefaf4", lineHeight: 1.2 }}>
              DFIS Access Control
            </Typography>
            <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10 }}>
              Forensic Role-Based Authentication
            </Typography>
          </Box>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ bgcolor: "#050f0b", p: 2.5, pt: 2 }}>
        {/* Quick Persona Selector */}
        <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, display: "block", mb: 1 }}>
          SELECT FORENSIC PERSONA
        </Typography>

        <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, mb: 2.5 }}>
          {presetUsers.map((user) => {
            const isSelected = selectedPreset.id === user.id;
            return (
              <Paper
                key={user.id}
                onClick={() => handleSelectPreset(user)}
                sx={{
                  p: 1.2,
                  cursor: "pointer",
                  bgcolor: isSelected ? "rgba(61, 255, 174, 0.1)" : "#08140f",
                  border: `1px solid ${isSelected ? "#3dffae" : "rgba(61, 255, 174, 0.12)"}`,
                  borderRadius: "8px",
                  transition: "all 0.15s ease",
                  "&:hover": { borderColor: "#3dffae" },
                }}
              >
                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Typography variant="subtitle2" sx={{ color: isSelected ? "#3dffae" : "#eefaf4", fontWeight: 800, fontSize: 12 }}>
                    {user.name}
                  </Typography>
                  <Chip
                    size="small"
                    label={user.role}
                    sx={{
                      height: 16,
                      fontSize: 8.5,
                      fontWeight: 800,
                      fontFamily: "JetBrains Mono",
                      bgcolor: isSelected ? "#3dffae" : "#0d1e16",
                      color: isSelected ? "#020806" : "#8fa89d",
                    }}
                  />
                </Stack>
                <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10, display: "block", mt: 0.3 }}>
                  {user.badge}
                </Typography>
              </Paper>
            );
          })}
        </Box>

        {/* Credentials Form */}
        <Box component="form" onSubmit={handleLoginSubmit} sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          <TextField
            fullWidth
            size="small"
            label="EMAIL ADDRESS"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SecurityIcon sx={{ color: "#52685e", fontSize: 16 }} />
                </InputAdornment>
              ),
            }}
            sx={{
              bgcolor: "#08140f",
              borderRadius: "8px",
              "& .MuiOutlinedInput-root": {
                fontSize: 12.5,
                fontFamily: "JetBrains Mono",
                "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                "&:hover fieldset": { borderColor: "#3dffae" },
              },
            }}
          />

          <TextField
            fullWidth
            size="small"
            type={showPassword ? "text" : "password"}
            label="PASSWORD / PIN"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LockIcon sx={{ color: "#52685e", fontSize: 16 }} />
                </InputAdornment>
              ),
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setShowPassword(!showPassword)} sx={{ color: "#52685e" }}>
                    {showPassword ? <VisibilityOffIcon sx={{ fontSize: 16 }} /> : <VisibilityIcon sx={{ fontSize: 16 }} />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
            sx={{
              bgcolor: "#08140f",
              borderRadius: "8px",
              "& .MuiOutlinedInput-root": {
                fontSize: 12.5,
                fontFamily: "JetBrains Mono",
                "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                "&:hover fieldset": { borderColor: "#3dffae" },
              },
            }}
          />

          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{
              mt: 1,
              py: 1.1,
              bgcolor: "#3dffae",
              color: "#020806",
              fontWeight: 800,
              fontSize: 13,
              borderRadius: "8px",
              boxShadow: "0 0 15px rgba(61, 255, 174, 0.3)",
              "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 25px rgba(61, 255, 174, 0.5)" },
            }}
          >
            Authenticate Persona ({selectedPreset.role})
          </Button>
        </Box>

        {/* Air-Gap Notice Seal */}
        <Paper sx={{ mt: 2, p: 1.2, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "6px" }}>
          <Stack direction="row" spacing={0.8} alignItems="center">
            <LockIcon sx={{ fontSize: 12, color: "#3dffae" }} />
            <Typography variant="caption" sx={{ color: "#52685e", fontSize: 9.5 }}>
              <b style={{ color: "#8fa89d" }}>Secure DFIS Workstation:</b> Local JWT authorization boundary.
            </Typography>
          </Stack>
        </Paper>
      </DialogContent>
    </Dialog>
  );
}
