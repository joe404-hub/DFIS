import React, { createContext, useContext, useState, useEffect } from "react";

export const DEFAULT_USERS = [
  {
    id: "u_01",
    username: "examiner01",
    name: "A. Rao",
    email: "examiner@dfis.local",
    role: "EXAMINER",
    status: "ACTIVE",
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
    status: "ACTIVE",
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
    status: "ACTIVE",
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
    status: "ACTIVE",
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
    timestamp: "2026-09-20 03:32:24",
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
    timestamp: "2026-09-20 03:40:00",
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
    timestamp: "2026-09-20 03:45:30",
    actor: "admin01 (Sarah Chen)",
    role: "ADMIN",
    action: "RBAC_POLICY_ENFORCED",
    resourceType: "SECURITY",
    resourceId: "AIR_GAP_POLICY",
    ipAddress: "127.0.0.1 (Local Workstation)",
    details: "Enforced role-based access control and case isolation",
  },
];

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [users, setUsers] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_users_db");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {}
    return DEFAULT_USERS;
  });

  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem("dfis_auth_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        const match = DEFAULT_USERS.find((u) => u.id === parsed.id);
        if (match) return match;
      }
    } catch {}
    return DEFAULT_USERS[0]; // default to examiner01
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
  const [userMgmtModalOpen, setUserMgmtModalOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem("dfis_users_db", JSON.stringify(users));
    } catch {}
  }, [users]);

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
    const match = users.find((u) => u.id === userId);
    if (match) {
      setCurrentUser(match);
      addAuditLog("USER_SWITCHED", "SESSION", match.username, `Active persona switched to ${match.name} (${match.role})`);
    }
  };

  const login = (email, password, role) => {
    let match = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (!match && role) {
      match = users.find((u) => u.role === role);
    }
    if (!match) match = users[0];

    setCurrentUser(match);
    addAuditLog("LOGIN_SUCCESS", "AUTHENTICATION", match.username, `Authenticated via secure local workstation session (${match.role})`);
    setLoginModalOpen(false);
  };

  const registerUser = (userData) => {
    const newUser = {
      id: `u_${Date.now().toString(16)}`,
      username: userData.username || userData.email.split("@")[0],
      name: userData.name || "Forensic User",
      email: userData.email,
      role: userData.role || "VIEWER",
      status: "ACTIVE",
      badge: userData.role === "ADMIN" ? "System Administrator" : userData.role === "EXAMINER" ? "Forensic Examiner" : userData.role === "ANALYST" ? "DFIR Analyst" : "Compliance Reviewer",
      avatar: (userData.name || "U")[0].toUpperCase(),
      assignedCases: ["CASE-DEMO"],
      permissions: {
        canCreateCase: userData.role === "ADMIN" || userData.role === "EXAMINER",
        canAcquire: userData.role === "ADMIN" || userData.role === "EXAMINER",
        canImport: userData.role === "ADMIN" || userData.role === "EXAMINER",
        canVerifyEvidence: userData.role !== "VIEWER",
        canUseAi: true,
        canExportReport: true,
        canManageUsers: userData.role === "ADMIN",
      },
    };

    setUsers((prev) => [...prev, newUser]);
    setCurrentUser(newUser);
    addAuditLog("USER_REGISTERED", "AUTHENTICATION", newUser.username, `Registered new ${newUser.role} account`);
    return newUser;
  };

  const updateUserRole = (userId, newRole) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id !== userId) return u;
        const updated = {
          ...u,
          role: newRole,
          badge: newRole === "ADMIN" ? "System Administrator" : newRole === "EXAMINER" ? "Forensic Examiner" : newRole === "ANALYST" ? "DFIR Analyst" : "Compliance Reviewer",
          permissions: {
            canCreateCase: newRole === "ADMIN" || newRole === "EXAMINER",
            canAcquire: newRole === "ADMIN" || newRole === "EXAMINER",
            canImport: newRole === "ADMIN" || newRole === "EXAMINER",
            canVerifyEvidence: newRole !== "VIEWER",
            canUseAi: true,
            canExportReport: true,
            canManageUsers: newRole === "ADMIN",
          },
        };
        if (currentUser.id === userId) setCurrentUser(updated);
        addAuditLog("USER_ROLE_CHANGED", "RBAC", u.username, `Role changed from ${u.role} to ${newRole}`);
        return updated;
      })
    );
  };

  const updateUserStatus = (userId, newStatus) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id !== userId) return u;
        const updated = { ...u, status: newStatus };
        if (currentUser.id === userId) setCurrentUser(updated);
        addAuditLog("USER_STATUS_TOGGLED", "SECURITY", u.username, `Status updated to ${newStatus}`);
        return updated;
      })
    );
  };

  const updateUserCases = (userId, assignedCases) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id !== userId) return u;
        const updated = { ...u, assignedCases };
        if (currentUser.id === userId) setCurrentUser(updated);
        addAuditLog("CASE_ACCESS_MODIFIED", "CASE_ACCESS", u.username, `Assigned cases: ${assignedCases.join(", ")}`);
        return updated;
      })
    );
  };

  const logout = () => {
    addAuditLog("LOGOUT", "AUTHENTICATION", currentUser.username, `User logged out of session`);
    setLoginModalOpen(true);
  };

  const can = (actionKey) => {
    if (currentUser?.role === "ADMIN") return true;
    return Boolean(currentUser?.permissions?.[actionKey]);
  };

  const hasCaseAccess = (caseNumber) => {
    if (!currentUser) return false;
    if (currentUser.role === "ADMIN") return true;
    if (currentUser.assignedCases?.includes("*")) return true;
    return Boolean(currentUser.assignedCases?.includes(caseNumber));
  };

  return (
    <AuthContext.Provider
      value={{
        users,
        currentUser,
        switchUser,
        login,
        logout,
        registerUser,
        updateUserRole,
        updateUserStatus,
        updateUserCases,
        can,
        hasCaseAccess,
        auditLogs,
        addAuditLog,
        loginModalOpen,
        setLoginModalOpen,
        auditModalOpen,
        setAuditModalOpen,
        userMgmtModalOpen,
        setUserMgmtModalOpen,
        presetUsers: users,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
