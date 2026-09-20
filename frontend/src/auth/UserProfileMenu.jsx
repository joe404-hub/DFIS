import React, { useState } from "react";
import {
  Avatar,
  Box,
  Button,
  Chip,
  Divider,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  Typography,
} from "@mui/material";
import PersonIcon from "@mui/icons-material/Person";
import SecurityIcon from "@mui/icons-material/Security";
import LockIcon from "@mui/icons-material/Lock";
import LogoutIcon from "@mui/icons-material/Logout";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import HomeIcon from "@mui/icons-material/Home";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import { useAuth } from "./AuthContext.jsx";

export default function UserProfileMenu({ onNavigateHome }) {
  const { currentUser, switchUser, presetUsers, setLoginModalOpen, setAuditModalOpen, setUserMgmtModalOpen, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleSwitch = (userId) => {
    switchUser(userId);
    handleClose();
  };

  const isAdmin = currentUser?.role === "ADMIN";

  return (
    <>
      <Button
        onClick={handleClick}
        size="small"
        sx={{
          py: 0.3,
          px: 1,
          height: 28,
          bgcolor: "rgba(61, 255, 174, 0.08)",
          border: "1px solid rgba(61, 255, 174, 0.25)",
          borderRadius: "8px",
          color: "#eefaf4",
          textTransform: "none",
          display: "flex",
          alignItems: "center",
          gap: 0.8,
          "&:hover": {
            bgcolor: "rgba(61, 255, 174, 0.15)",
            borderColor: "#3dffae",
          },
        }}
      >
        <Avatar
          sx={{
            width: 18,
            height: 18,
            fontSize: 10,
            fontWeight: 800,
            bgcolor: "#3dffae",
            color: "#020806",
          }}
        >
          {currentUser.avatar || "U"}
        </Avatar>

        <Typography variant="body2" sx={{ fontSize: 11, fontWeight: 700, color: "#eefaf4" }}>
          {currentUser.name}
        </Typography>

        <Chip
          size="small"
          label={currentUser.role}
          sx={{
            height: 16,
            fontSize: 8.5,
            fontWeight: 800,
            fontFamily: "JetBrains Mono",
            bgcolor: "#08140f",
            color: "#3dffae",
            border: "1px solid rgba(61, 255, 174, 0.2)",
          }}
        />
      </Button>

      {/* Profile Dropdown Menu */}
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: {
            width: 290,
            bgcolor: "#08140f",
            border: "1px solid rgba(61, 255, 174, 0.2)",
            borderRadius: "12px",
            color: "#eefaf4",
            boxShadow: "0 10px 40px rgba(0,0,0,0.6)",
            mt: 0.8,
            p: 0.5,
          },
        }}
        transformOrigin={{ horizontal: "right", vertical: "top" }}
        anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
      >
        {/* User Card */}
        <Box sx={{ p: 1.5, bgcolor: "#050f0b", borderRadius: "8px", mb: 1, border: "1px solid rgba(61, 255, 174, 0.1)" }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Avatar sx={{ width: 28, height: 28, fontSize: 12, fontWeight: 800, bgcolor: "#3dffae", color: "#020806" }}>
              {currentUser.avatar}
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 800, color: "#eefaf4", fontSize: 12 }}>
                {currentUser.name}
              </Typography>
              <Typography variant="caption" sx={{ color: "#8fa89d", fontSize: 10, display: "block" }}>
                {currentUser.email}
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={0.5} sx={{ mt: 1 }}>
            <Chip
              size="small"
              label={`ROLE: ${currentUser.role}`}
              sx={{ height: 18, fontSize: 9, fontWeight: 800, bgcolor: "rgba(61, 255, 174, 0.1)", color: "#3dffae" }}
            />
            <Chip
              size="small"
              label={currentUser.badge}
              sx={{ height: 18, fontSize: 9, fontWeight: 600, bgcolor: "#0d1e16", color: "#8fa89d" }}
            />
          </Stack>
        </Box>

        {/* Persona Quick-Switch Section */}
        <Typography variant="caption" sx={{ px: 1, color: "#52685e", fontWeight: 800, textTransform: "uppercase", fontSize: 9, display: "block", mb: 0.5 }}>
          SWITCH PERSONA (RBAC SIMULATION)
        </Typography>

        {presetUsers.map((user) => {
          const isCurrent = user.id === currentUser.id;
          return (
            <MenuItem
              key={user.id}
              onClick={() => handleSwitch(user.id)}
              sx={{
                py: 0.6,
                px: 1,
                borderRadius: "6px",
                bgcolor: isCurrent ? "rgba(61, 255, 174, 0.08)" : "transparent",
                "&:hover": { bgcolor: "#0d1e16" },
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, color: isCurrent ? "#3dffae" : "#52685e" }}>
                {isCurrent ? <CheckCircleIcon sx={{ fontSize: 14 }} /> : <PersonIcon sx={{ fontSize: 14 }} />}
              </ListItemIcon>
              <ListItemText
                primary={user.name}
                secondary={user.role}
                primaryTypographyProps={{ fontSize: 11, fontWeight: isCurrent ? 800 : 500, color: isCurrent ? "#3dffae" : "#eefaf4" }}
                secondaryTypographyProps={{ fontSize: 9.5, color: "#8fa89d", fontFamily: "JetBrains Mono" }}
              />
            </MenuItem>
          );
        })}

        <Divider sx={{ my: 0.8, borderColor: "rgba(61, 255, 174, 0.1)" }} />

        {/* Admin Management Option */}
        {isAdmin && (
          <MenuItem
            onClick={() => {
              setUserMgmtModalOpen(true);
              handleClose();
            }}
            sx={{ py: 0.6, px: 1, borderRadius: "6px", bgcolor: "rgba(255, 101, 101, 0.08)", mb: 0.5, "&:hover": { bgcolor: "rgba(255, 101, 101, 0.15)" } }}
          >
            <ListItemIcon sx={{ minWidth: 24, color: "#ff6565" }}>
              <AdminPanelSettingsIcon sx={{ fontSize: 15 }} />
            </ListItemIcon>
            <ListItemText primary="User & Role Management" primaryTypographyProps={{ fontSize: 11.5, fontWeight: 700, color: "#ff6565" }} />
          </MenuItem>
        )}

        {/* Security Audit Trail */}
        <MenuItem
          onClick={() => {
            setAuditModalOpen(true);
            handleClose();
          }}
          sx={{ py: 0.6, px: 1, borderRadius: "6px", "&:hover": { bgcolor: "#0d1e16" } }}
        >
          <ListItemIcon sx={{ minWidth: 24, color: "#3dffae" }}>
            <SecurityIcon sx={{ fontSize: 15 }} />
          </ListItemIcon>
          <ListItemText primary="Security Audit Trail" primaryTypographyProps={{ fontSize: 11.5, fontWeight: 600, color: "#eefaf4" }} />
        </MenuItem>

        <MenuItem
          onClick={() => {
            if (onNavigateHome) onNavigateHome();
            handleClose();
          }}
          sx={{ py: 0.6, px: 1, borderRadius: "6px", "&:hover": { bgcolor: "#0d1e16" } }}
        >
          <ListItemIcon sx={{ minWidth: 24, color: "#8fa89d" }}>
            <HomeIcon sx={{ fontSize: 15 }} />
          </ListItemIcon>
          <ListItemText primary="DFIS Landing Page" primaryTypographyProps={{ fontSize: 11.5, color: "#8fa89d" }} />
        </MenuItem>

        <MenuItem
          onClick={() => {
            setLoginModalOpen(true);
            handleClose();
          }}
          sx={{ py: 0.6, px: 1, borderRadius: "6px", "&:hover": { bgcolor: "#0d1e16" } }}
        >
          <ListItemIcon sx={{ minWidth: 24, color: "#8fa89d" }}>
            <LockIcon sx={{ fontSize: 15 }} />
          </ListItemIcon>
          <ListItemText primary="Authenticate Credentials" primaryTypographyProps={{ fontSize: 11.5, color: "#8fa89d" }} />
        </MenuItem>

        <MenuItem
          onClick={() => {
            logout();
            if (onNavigateHome) onNavigateHome();
            handleClose();
          }}
          sx={{ py: 0.6, px: 1, borderRadius: "6px", color: "#ff6565", "&:hover": { bgcolor: "rgba(255, 101, 101, 0.1)" } }}
        >
          <ListItemIcon sx={{ minWidth: 24, color: "#ff6565" }}>
            <LogoutIcon sx={{ fontSize: 15 }} />
          </ListItemIcon>
          <ListItemText primary="Sign Out" primaryTypographyProps={{ fontSize: 11.5, fontWeight: 700, color: "#ff6565" }} />
        </MenuItem>
      </Menu>
    </>
  );
}
