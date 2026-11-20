import React, { useState } from "react";
import {
  Box,
  Button,
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
import PersonIcon from "@mui/icons-material/Person";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ShieldCheckIcon from "@mui/icons-material/VerifiedUser";
import { useAuth } from "./AuthContext.jsx";

export default function SignUpView({ onNavigate }) {
  const { login } = useAuth();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleSignUp = (e) => {
    e?.preventDefault();
    if (!email || !name) {
      alert("Please fill in your name and email address.");
      return;
    }
    // Authenticate new account with VIEWER/ANALYST role
    login(email, password, "VIEWER");
    alert(`Account created for ${name}! Role initialized to VIEWER (Pending Admin Assignment). Launching workspace...`);
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
      {/* Background ambient lighting */}
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

      {/* Main Center */}
      <Box sx={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", p: 3, zIndex: 2 }}>
        <Paper
          sx={{
            width: "100%",
            maxWidth: 500,
            p: { xs: 2.5, sm: 3.5 },
            bgcolor: "#08140f",
            border: "1px solid rgba(61, 255, 174, 0.22)",
            borderRadius: "16px",
            boxShadow: "0 25px 80px rgba(0,0,0,0.6), 0 0 40px rgba(61, 255, 174, 0.06)",
          }}
        >
          {/* Header */}
          <Box sx={{ textAlign: "center", mb: 2.5 }}>
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
              Create DFIS Account
            </Typography>
            <Typography variant="body2" sx={{ color: "#8fa89d", fontSize: 12.5, mt: 0.4 }}>
              Register for forensic investigation access
            </Typography>
          </Box>

          {/* Registration Form */}
          <Box component="form" onSubmit={handleSignUp} sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            <TextField
              fullWidth
              size="small"
              label="FULL NAME"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Elena Rostova"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PersonIcon sx={{ color: "#52685e", fontSize: 16 }} />
                  </InputAdornment>
                ),
              }}
              sx={{
                bgcolor: "#050f0b",
                borderRadius: "8px",
                "& .MuiOutlinedInput-root": {
                  fontSize: 12.5,
                  "& fieldset": { borderColor: "rgba(61, 255, 174, 0.15)" },
                  "&:hover fieldset": { borderColor: "#3dffae" },
                },
              }}
            />

            <TextField
              fullWidth
              size="small"
              label="OFFICIAL EMAIL"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@dfis.local"
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
              label="USERNAME"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="erostova"
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
              label="PASSWORD"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
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

            <TextField
              fullWidth
              size="small"
              type={showPassword ? "text" : "password"}
              label="CONFIRM PASSWORD"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••••••"
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

            {/* Role Assignment Note */}
            <Paper sx={{ p: 1.2, bgcolor: "#020806", border: "1px solid rgba(61, 255, 174, 0.1)", borderRadius: "6px" }}>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10.5, lineHeight: 1.4, display: "block" }}>
                <b style={{ color: "#3dffae" }}>Security Governance:</b> New accounts are initialized with <code>VIEWER</code> permissions until an Administrator assigns an Examiner or Analyst role.
              </Typography>
            </Paper>

            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{
                mt: 0.5,
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
              Create Account & Launch Workstation
            </Button>
          </Box>

          <Stack direction="row" justifyContent="center" spacing={1} sx={{ mt: 2.5, fontSize: 12, color: "#8fa89d" }}>
            <span>Already registered?</span>
            <button
              type="button"
              onClick={() => onNavigate("signin")}
              style={{ background: "none", border: "none", color: "#3dffae", fontWeight: 700, cursor: "pointer", padding: 0 }}
            >
              Sign In
            </button>
          </Stack>
        </Paper>
      </Box>
    </Box>
  );
}
