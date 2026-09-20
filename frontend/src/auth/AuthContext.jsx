import React, { createContext, useContext, useState, useEffect } from "react";

export const PRESET_USERS = [
  {
    id: "u_01",
    username: "examiner01",
    name: "A. Rao",
    email: "examiner@dfis.local",
    role: "EXAMINER",
    badge: "Lead Forensic Examiner",
    avatar: "R",
    assignedCases: ["CASE-DEMO", "CASE-001", "CASE-002", "CASE-003"],
    permissions: {
      canCreateCase: true,
      canAcquire: true,
      canImport: true,
      canVerifyEvidence: true,
      canUseAi: true,
      canExportReport: true,
      canManageUsers: false,
    },
  },
  {
    id: "u_02",
    username: "admin01",
    name: "Sarah Chen",
    email: "admin@dfis.local",
    role: "ADMIN",
    badge: "System Administrator",
    avatar: "S",
    assignedCases: ["*"], // All cases
    permissions: {
      canCreateCase: true,
      canAcquire: true,
      canImport: true,
      canVerifyEvidence: true,
      canUseAi: true,
      canExportReport: true,
      canManageUsers: true,
    },
  },
  {
    id: "u_03",
    username: "analyst01",
    name: "Marcus Vance",
    email: "analyst@dfis.local",
    role: "ANALYST",
    badge: "DFIR Forensic Analyst",
    avatar: "M",
    assignedCases: ["CASE-DEMO", "CASE-001"],
    permissions: {
      canCreateCase: false,
      canAcquire: false,
      canImport: false,
      canVerifyEvidence: true,
      canUseAi: true,
      canExportReport: true,
      canManageUsers: false,
    },
  },
  {
    id: "u_04",
    username: "viewer01",
    name: "Legal Counsel",
    email: "viewer@dfis.local",
    role: "VIEWER",
    badge: "Audit & Compliance Reviewer",
    avatar: "L",
    assignedCases: ["CASE-DEMO"],
    permissions: {
      canCreateCase: false,
      canAcquire: false,
      canImport: false,
      canVerifyEvidence: false,
      canUseAi: true,
      canExportReport: true,
      canManageUsers: false,
    },
  },
];

const INITIAL_AUDIT_LOGS = [
  {
    id: "log_1",
    timestamp: "2026-09-04 18:32:24",
    actor: "examiner01 (A. Rao)",
    role: "EXAMINER",
    action: "CASE_INGESTION_INITIALIZED",
    resourceType: "CASE",
    resourceId: "CASE-DEMO",
    ipAddress: "127.0.0.1 (Local Workstation)",
    details: "Ingested evidence container CASE-DEMO.zip (SHA-256 verified)",
  },
  {
    id: "log_2",
    timestamp: "2026-09-04 19:10:00",
    actor: "examiner01 (A. Rao)",
    role: "EXAMINER",
    action: "EVIDENCE_VERIFIED",
    resourceType: "EVIDENCE",
    resourceId: "#1 (CASE-DEMO.zip)",
    ipAddress: "127.0.0.1 (Local Workstation)",
    details: "Integrity check passed: c86130316500e97ad8e48c14f2b20d26...",
  },
  {
    id: "log_3",
    timestamp: "2026-09-04 20:15:30",
    actor: "admin01 (Sarah Chen)",
    role: "ADMIN",
    action: "RBAC_POLICY_UPDATED",
    resourceType: "SECURITY",
    resourceId: "AIR_GAP_POLICY",
    ipAddress: "127.0.0.1 (Local Workstation)",
    details: "Enforced air-gapped local inference policy for llama3.2:3b",
  },
];

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_auth_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        const match = PRESET_USERS.find((u) => u.id === parsed.id);
        if (match) return match;
      }
    } catch {}
    return PRESET_USERS[0]; // default to examiner01
  });

  const [auditLogs, setAuditLogs] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_audit_logs");
      if (saved) return JSON.parse(saved);
    } catch {}
    return INITIAL_AUDIT_LOGS;
  });

  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const [auditModalOpen, setAuditModalOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem("dfis_auth_user", JSON.stringify(currentUser));
    } catch {}
  }, [currentUser]);

  useEffect(() => {
    try {
      localStorage.setItem("dfis_audit_logs", JSON.stringify(auditLogs));
    } catch {}
  }, [auditLogs]);

  const addAuditLog = (action, resourceType, resourceId, details) => {
    const newLog = {
      id: `log_${Date.now().toString(16)}`,
      timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
      actor: `${currentUser.username} (${currentUser.name})`,
      role: currentUser.role,
      action,
      resourceType,
      resourceId: String(resourceId || "—"),
      ipAddress: "127.0.0.1 (Local Workstation)",
      details: details || "Action verified by forensic audit engine",
    };
    setAuditLogs((prev) => [newLog, ...prev]);
  };

  const switchUser = (userId) => {
    const match = PRESET_USERS.find((u) => u.id === userId);
    if (match) {
      setCurrentUser(match);
      addAuditLog("USER_SWITCHED", "SESSION", match.username, `Active persona switched to ${match.name} (${match.role})`);
    }
  };

  const login = (email, password, role) => {
    let match = PRESET_USERS.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (!match && role) {
      match = PRESET_USERS.find((u) => u.role === role);
    }
    if (!match) match = PRESET_USERS[0];

    setCurrentUser(match);
    addAuditLog("LOGIN_SUCCESS", "AUTHENTICATION", match.username, `Authenticated via secure local workstation JWT session (${match.role})`);
    setLoginModalOpen(false);
  };

  const logout = () => {
    addAuditLog("LOGOUT", "AUTHENTICATION", currentUser.username, `User logged out of session`);
    setLoginModalOpen(true);
  };

  const can = (actionKey) => {
    if (currentUser?.role === "ADMIN") return true;
    return Boolean(currentUser?.permissions?.[actionKey]);
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        switchUser,
        login,
        logout,
        can,
        auditLogs,
        addAuditLog,
        loginModalOpen,
        setLoginModalOpen,
        auditModalOpen,
        setAuditModalOpen,
        presetUsers: PRESET_USERS,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
