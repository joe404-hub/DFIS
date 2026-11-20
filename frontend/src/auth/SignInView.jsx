import React, { useState } from "react";
import {
  Box,
  Button,
  Chip,
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
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ShieldCheckIcon from "@mui/icons-material/VerifiedUser";
import { useAuth } from "./AuthContext.jsx";

export default function SignInView({ onNavigate }) {
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
    onNavigate("workspace");
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        bgcolor: "#020807",
        color: "#eefaf4",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Ambient background glows */}
      <Box sx={{ position: "absolute", top: "15%", right: "10%", width: 400, height: 400, borderRadius: "50%", bgcolor: "rgba(61, 255, 174, 0.04)", filter: "blur(100px)", pointerEvents: "none" }} />
      <Box sx={{ position: "absolute", bottom: "10%", left: "10%", width: 400, height: 400, borderRadius: "50%", bgcolor: "rgba(0, 200, 140, 0.03)", filter: "blur(100px)", pointerEvents: "none" }} />

      {/* Top Header */}
      <Box sx={{ p: "18px 36px", borderBottom: "1px solid rgba(61, 255, 174, 0.14)", display: "flex", justifyContent: "space-between", alignItems: "center", bgcolor: "rgba(2, 8, 7, 0.8)", backdropFilter: "blur(12px)" }}>
        <Button
          onClick={() => onNavigate("landing")}
          startIcon={<ArrowBackIcon sx={{ fontSize: 16 }} />}
          sx={{ color: "#8fa89d", fontSize: 12.5, fontWeight: 700, textTransform: "none", "&:hover": { color: "#3dffae" } }}
        >
          Return to DFIS Home
        </Button>

        <Stack direction="row" spacing={1} alignItems="center">
          <Box sx={{ width: 28, height: 28, borderRadius: "6px", bgcolor: "rgba(61, 255, 174, 0.1)", border: "1px solid rgba(61, 255, 174, 0.3)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <FingerprintIcon sx={{ color: "#3dffae", fontSize: 17 }} />
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 800, fontSize: 15, color: "#eefaf4" }}>
            DFIS
          </Typography>
        </Stack>
      </Box>

      {/* Main Form Center */}
      <Box sx={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", p: 3, zIndex: 2 }}>
        <Paper
          sx={{
            width: "100%",
            maxWidth: 480,
            p: { xs: 2.5, sm: 3.5 },
            bgcolor: "#08140f",
            border: "1px solid rgba(61, 255, 174, 0.22)",
            borderRadius: "16px",
            boxShadow: "0 25px 80px rgba(0,0,0,0.6), 0 0 40px rgba(61, 255, 174, 0.06)",
          }}
        >
          {/* Header */}
          <Box sx={{ textAlign: "center", mb: 3 }}>
            <Box
              sx={{
                width: 44,
                height: 44,
                mx: "auto",
                mb: 1.5,
                borderRadius: "12px",
                bgcolor: "rgba(61, 255, 174, 0.1)",
                border: "1px solid rgba(61, 255, 174, 0.35)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 20px rgba(61, 255, 174, 0.2)",
              }}
            >
              <ShieldCheckIcon sx={{ color: "#3dffae", fontSize: 24 }} />
            </Box>
            <Typography variant="h5" sx={{ fontWeight: 800, color: "#eefaf4", letterSpacing: "-0.02em" }}>
              Sign In to DFIS
            </Typography>
            <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12.5, mt: 0.4 }}>
              Digital Forensics Intelligence System • Secure Workstation
            </Typography>
          </Box>

          {/* Quick Persona Selector */}
          <Typography variant="caption" sx={{ color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9.5, letterSpacing: "0.08em", display: "block", mb: 1 }}>
            AUTHENTICATE FORENSIC PERSONA (RBAC)
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
                    bgcolor: isSelected ? "rgba(61, 255, 174, 0.1)" : "#050f0b",
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

          {/* Form */}
          <Box component="form" onSubmit={handleLoginSubmit} sx={{ display: "flex", flexDirection: "column", gap: 1.6 }}>
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
                bgcolor: "#050f0b",
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
              label="PASSWORD / SECURITY TOKEN"
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
                bgcolor: "#050f0b",
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
                py: 1.2,
                bgcolor: "#3dffae",
                color: "#020806",
                fontWeight: 800,
                fontSize: 13,
                borderRadius: "8px",
                boxShadow: "0 0 20px rgba(61, 255, 174, 0.3)",
                "&:hover": { bgcolor: "#6dffc7", boxShadow: "0 0 30px rgba(61, 255, 174, 0.5)" },
              }}
            >
              Sign In to Workstation ({selectedPreset.role})
            </Button>
          </Box>

          <Stack direction="row" justifyContent="center" spacing={1} sx={{ mt: 2.5, fontSize: 12, color: "#8fa89d" }}>
            <span>Need an account?</span>
            <button
              type="button"
              onClick={() => onNavigate("signup")}
              style={{ background: "none", border: "none", color: "#3dffae", fontWeight: 700, cursor: "pointer", padding: 0 }}
            >
              Create DFIS Account
            </button>
          </Stack>
        </Paper>
      </Box>
    </Box>
  );
}
