import React from "react";
import {
  ShieldCheck,
  Database,
  BrainCircuit,
  FileSearch,
  ArrowRight,
  Activity,
  LockKeyhole,
} from "lucide-react";
import "./Home.css";

export default function Home({ onNavigate }) {
  return (
    <div className="dfis-home">
      {/* Background ambient lighting effects */}
      <div className="home-grid" />
      <div className="home-glow home-glow-one" />
      <div className="home-glow home-glow-two" />

      {/* TOP HEADER */}
      <header className="home-header">
        <button
          type="button"
          onClick={() => onNavigate("landing")}
          className="dfis-brand-link"
        >
          <div className="brand-icon">
            <ShieldCheck size={20} />
          </div>

          <div>
            <div className="brand-name">
              DFIS <span />
            </div>
            <div className="brand-subtitle">
              Digital Forensics Intelligence System
            </div>
          </div>
        </button>

        <div className="header-actions">
          <button
            type="button"
            onClick={() => onNavigate("signin")}
            className="header-signin"
          >
            Sign in
          </button>

          <button
            type="button"
            onClick={() => onNavigate("signup")}
            className="header-signin"
          >
            Create account
          </button>

          <button
            type="button"
            onClick={() => onNavigate("workspace")}
            className="header-signup"
          >
            Launch Workstation
            <ArrowRight size={15} />
          </button>
        </div>
      </header>

      {/* MAIN HERO CONTENT */}
      <main className="home-main">
        {/* LEFT CONTENT */}
        <section className="home-content">
          <div className="system-status">
            <span className="status-dot" />
            SECURE FORENSIC WORKSTATION • AIR-GAPPED
          </div>

          <h1>
            Digital Forensics
            <br />
            <span>Intelligence System</span>
          </h1>

          <p className="home-description">
            Investigate digital evidence, correlate multi-source artifact activity, and perform grounded, evidence-backed AI analysis from a secure forensic workstation.
          </p>

          <div className="home-actions">
            <button
              type="button"
              onClick={() => onNavigate("workspace")}
              className="primary-action"
            >
              Launch Investigation Console
              <ArrowRight size={18} />
            </button>

            <button
              type="button"
              onClick={() => onNavigate("signin")}
              className="secondary-action"
            >
              Authenticate Persona (RBAC)
            </button>
          </div>

          {/* Capabilities Grid */}
          <div className="capability-list">
            <Capability
              icon={<BrainCircuit size={16} />}
              title="Local AI Copilot"
              description="100% air-gapped Ollama (llama3.2:3b) local inference"
            />

            <Capability
              icon={<FileSearch size={16} />}
              title="Evidence Grounding"
              description="Case-aware temporal artifact correlation & MITRE ATT&CK"
            />

            <Capability
              icon={<LockKeyhole size={16} />}
              title="Role-Based Access"
              description="Examiner, Admin, Analyst, and Viewer authorization"
            />

            <Capability
              icon={<Activity size={16} />}
              title="Audit Custody Trail"
              description="Cryptographically tracked action and verification logs"
            />
          </div>
        </section>

        {/* RIGHT FORENSIC VISUAL */}
        <section className="forensic-visual">
          <div className="visual-header">
            <div>
              <span className="visual-label">
                LIVE INVESTIGATION MODEL
              </span>
              <span className="visual-status">
                ● AIR-GAPPED WORKSTATION READY
              </span>
            </div>

            <span className="visual-case">
              DFIS / CASE-DEMO
            </span>
          </div>

          <div className="forensic-graph">
            <div className="graph-time">
              <span>09:00</span>
              <span>09:05</span>
              <span>09:10</span>
              <span>09:15</span>
              <span>09:20</span>
              <span>09:30</span>
            </div>

            <GraphLine
              label="WINDOWS"
              points={["a", "b", "c", "d"]}
            />

            <GraphLine
              label="NETWORK"
              points={["a", "b", "c"]}
            />

            <GraphLine
              label="FILESYSTEM"
              points={["a", "b", "c"]}
            />

            <GraphLine
              label="REGISTRY"
              points={["a", "b"]}
            />
          </div>

          <div className="visual-footer">
            <div>
              <span className="footer-value">
                100%
              </span>
              <span>
                Local Processing
              </span>
            </div>

            <div>
              <span className="footer-value">
                SHA-256
              </span>
              <span>
                Evidence Verification
              </span>
            </div>

            <div>
              <span className="footer-value">
                ISOLATED
              </span>
              <span>
                Case Context
              </span>
            </div>
          </div>
        </section>
      </main>

      {/* FOOTER */}
      <footer className="home-footer">
        <span>DFIS v2.0</span>
        <span>•</span>
        <span>Secure Investigation Environment</span>
        <span>•</span>
        <span>Air-Gapped Local LLM (llama3.2:3b)</span>
        <span>•</span>
        <span>SHA-256 Chain-of-Custody</span>
      </footer>
    </div>
  );
}

function Capability({ icon, title, description }) {
  return (
    <div className="capability">
      <div className="capability-icon">
        {icon}
      </div>

      <div>
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}

function GraphLine({ label, points }) {
  return (
    <div className="graph-line">
      <span className="graph-label">
        {label}
      </span>

      <div className="graph-track">
        {points.map((point, index) => (
          <span
            key={point + index}
            className="graph-node"
            style={{
              left: `${15 + index * 24}%`,
            }}
          />
        ))}

        <span className="graph-path" />
      </div>
    </div>
  );
}
