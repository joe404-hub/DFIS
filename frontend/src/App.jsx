import { useEffect, useMemo, useRef, useState } from "react";
import {
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  LinearProgress,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Tab,
  Tabs,
  TextField,
  Toolbar,
  Typography,
} from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import TimelineIcon from "@mui/icons-material/Timeline";
import GavelIcon from "@mui/icons-material/Gavel";
import { DataSet } from "vis-data";
import { Timeline } from "vis-timeline/standalone";
import { Network } from "vis-network/standalone";
import "vis-timeline/styles/vis-timeline-graph2d.css";

const api = (path, opts) => fetch(path, opts).then((r) => (r.ok ? r : Promise.reject(r)));

export default function App() {
  const [cases, setCases] = useState([]);
  const [active, setActive] = useState(null);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [inv, setInv] = useState(null);
  const [tab, setTab] = useState(0);
  const [q, setQ] = useState("What is the next step to be taken?");
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    case_number: "CASE-00",
    title: "New investigation",
    investigator: "Examiner",
    description: "",
  });
  const tlRef = useRef(null);
  const netRef = useRef(null);
  const tlInst = useRef(null);
  const netInst = useRef(null);

  const loadCases = async () => {
    const r = await api("/api/cases").then((x) => x.json());
    setCases(r);
    if (!active && r[0]) setActive(r[0].id);
  };

  const loadCase = async (id) => {
    setBusy(true);
    try {
      const [d, t, g, invr] = await Promise.all([
        api(`/api/cases/${id}`).then((x) => x.json()),
        api(`/api/cases/${id}/timeline`).then((x) => x.json()),
        api(`/api/cases/${id}/graph`).then((x) => x.json()),
        api(`/api/cases/${id}/investigation`).then((x) => x.json()).catch(() => null),
      ]);
      setDetail(d);
      setTimeline(t);
      setGraph(g);
      setInv(invr);
      setAnswer("");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);
  useEffect(() => {
    if (active) loadCase(active);
  }, [active]);

  useEffect(() => {
    if (!tlRef.current || tab !== 0) return;
    const items = new DataSet(
      timeline
        .filter((e) => e.timestamp)
        .map((e) => ({
          id: e.id,
          content: `<b>${e.event_type}</b><br/>${escapeHtml(e.description).slice(0, 90)}`,
          start: e.timestamp,
          group: e.source_type,
          className: e.source_type === "correlated" ? "hot" : riskClass(e),
        }))
    );
    const groups = new DataSet(
      [...new Set(timeline.map((e) => e.source_type))].map((g) => ({ id: g, content: g }))
    );
    if (tlInst.current) tlInst.current.destroy();
    tlInst.current = new Timeline(tlRef.current, items, groups, {
      stack: true,
      orientation: "top",
      margin: { item: 8 },
    });
  }, [timeline, tab]);

  useEffect(() => {
    if (!netRef.current || tab !== 1) return;
    if (netInst.current) netInst.current.destroy();
    netInst.current = new Network(
      netRef.current,
      { nodes: graph.nodes, edges: graph.edges },
      {
        nodes: { shape: "dot", size: 14, font: { color: "#d7e6ef", size: 12 } },
        edges: { color: "#3a5568", font: { color: "#8aa", size: 10 }, arrows: "to" },
        physics: { stabilization: true },
      }
    );
  }, [graph, tab]);

  const finding = detail?.findings?.[0];

  const upload = async (file) => {
    const fd = new FormData();
    fd.append("file", file);
    setBusy(true);
    await api(`/api/cases/${active}/evidence`, { method: "POST", body: fd });
    await loadCases();
    await loadCase(active);
  };

  const ask = async () => {
    setBusy(true);
    try {
      const r = await api(`/api/cases/${active}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }),
      }).then((x) => x.json());
      setAnswer(r.answer);
    } finally {
      setBusy(false);
    }
  };

  const createCase = async () => {
    await api("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    setOpen(false);
    await loadCases();
  };

  const risk = inv?.risk_score || finding?.risk_score || 0;

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <AppBar position="fixed" sx={{ zIndex: 1201, bgcolor: "#06141d", borderBottom: "1px solid #1d3344" }} elevation={0}>
        <Toolbar>
          <GavelIcon sx={{ mr: 1, color: "primary.main" }} />
          <Box>
            <Typography variant="h6">DFIS</Typography>
            <Typography variant="caption" color="text.secondary">
              AI-assisted digital forensics — evidence stays authoritative
            </Typography>
          </Box>
          <Box sx={{ flex: 1 }} />
          <Button color="inherit" onClick={() => setOpen(true)}>
            New case
          </Button>
          {active && (
            <Button color="inherit" href={`/api/cases/${active}/report`} target="_blank">
              PDF report
            </Button>
          )}
        </Toolbar>
        {busy && <LinearProgress />}
      </AppBar>
      <Drawer
        variant="permanent"
        sx={{
          width: 300,
          [`& .MuiDrawer-paper`]: { width: 300, top: 64, bgcolor: "#0a1620", borderColor: "#1d3344" },
        }}
      >
        <List>
          {cases.map((c) => (
            <ListItemButton key={c.id} selected={c.id === active} onClick={() => setActive(c.id)}>
              <ListItemText
                primary={c.case_number}
                secondary={`${c.title}\nPriority ${c.risk_score ?? 0}/100 · ${c.artifact_count} events`}
                secondaryTypographyProps={{ component: "div", whiteSpace: "pre-line" }}
              />
            </ListItemButton>
          ))}
        </List>
      </Drawer>
      <Box component="main" sx={{ flex: 1, ml: "300px", mt: 8, p: 3 }}>
        {!detail ? (
          <Typography>Select or create a case.</Typography>
        ) : (
          <Container maxWidth="xl" disableGutters>
            <Stack direction="row" spacing={2} alignItems="flex-start" sx={{ mb: 2 }}>
              <Box sx={{ flex: 1 }}>
                <Typography variant="h5">{detail.title}</Typography>
                <Typography color="text.secondary">{detail.description}</Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
                  <Chip size="small" label={detail.case_number} />
                  <Chip size="small" label={detail.investigator} variant="outlined" />
                  {finding && <Chip size="small" color="secondary" label={finding.category} />}
                  {finding && <Chip size="small" label={`MITRE ${finding.mitre_ids || "—"}`} />}
                </Stack>
              </Box>
              <Card sx={{ minWidth: 220 }}>
                <CardContent>
                  <Typography variant="caption">Investigation Priority</Typography>
                  <Typography variant="h4">{risk}/100</Typography>
                  <Typography variant="subtitle2" color="secondary">
                    {inv?.priority || inv?.risk?.priority || (risk >= 70 ? "HIGH" : "PRIORITY")}
                  </Typography>
                  <LinearProgress variant="determinate" value={risk} sx={{ mt: 1 }} />
                  <Typography variant="caption">
                    Possible {inv?.category || finding?.category || "—"} · conf {(finding?.confidence || inv?.confidence || 0).toFixed?.(2) || finding?.confidence}
                  </Typography>
                </CardContent>
              </Card>
            </Stack>

            <Stack direction="row" spacing={2} sx={{ mb: 2 }} alignItems="center">
              <Button variant="contained" component="label" startIcon={<CloudUploadIcon />}>
                Upload evidence
                <input hidden type="file" onChange={(e) => e.target.files[0] && upload(e.target.files[0])} />
              </Button>
              <Button
                variant="outlined"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await api(`/api/cases/${active}/reprocess`, { method: "POST" });
                    await loadCases();
                    await loadCase(active);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Re-parse artifacts
              </Button>
              <Typography variant="body2" color="text.secondary">
                Specialized parsers for Windows/Registry/Browser/Network/Memory/FS CSVs. README and expected_timeline are excluded from the investigative timeline.
              </Typography>
            </Stack>

            <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
              <Card sx={{ flex: 2 }}>
                <Tabs value={tab} onChange={(_, v) => setTab(v)}>
                  <Tab icon={<TimelineIcon />} iconPosition="start" label="Timeline" />
                  <Tab label="Relationship graph" />
                  <Tab label="Evidence & custody" />
                  <Tab label="Investigation" />
                  <Tab label="Report" />
                </Tabs>
                <Divider />
                {tab === 0 && <Box ref={tlRef} sx={{ height: 420, bgcolor: "#08141c" }} />}
                {tab === 1 && <Box ref={netRef} sx={{ height: 420 }} />}
                {tab === 2 && (
                  <Box sx={{ p: 2, maxHeight: 420, overflow: "auto" }}>
                    <Typography variant="subtitle2">Evidence</Typography>
                    {detail.evidence.map((e) => (
                      <Box key={e.id} sx={{ fontFamily: "IBM Plex Mono", fontSize: 12, mb: 1 }}>
                        #{e.id} {e.filename} · {e.sha256}
                        <Chip size="small" sx={{ ml: 1 }} color={e.integrity_ok ? "primary" : "error"} label={e.integrity_ok ? "hash OK" : "mismatch"} />
                      </Box>
                    ))}
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      Chain of custody
                    </Typography>
                    {detail.custody.map((c, i) => (
                      <Typography key={i} variant="body2">
                        {c.created_at} — {c.action} ({c.actor}) {c.detail}
                      </Typography>
                    ))}
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      Events
                    </Typography>
                    {timeline.map((e) => (
                      <Typography
                        key={e.id}
                        variant="body2"
                        sx={{
                          fontFamily: "IBM Plex Mono",
                          fontSize: 12,
                          color: e.source_type === "correlated" ? "#f4b942" : "inherit",
                        }}
                      >
                        [{e.id}] {e.time_kind === "observation" ? "obs " : ""}
                        {e.timestamp || "—"} · {e.source_type}/{e.event_type}
                        {e.correlation_id ? ` · link=${e.correlation_id}` : ""} · {e.description}
                      </Typography>
                    ))}
                  </Box>
                )}
                {tab === 3 && (
                  <Box sx={{ p: 2, maxHeight: 420, overflow: "auto" }}>
                    <Typography variant="subtitle1">
                      Possible {inv?.category || finding?.category} / {inv?.secondary || "review required"}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Correlation IDs are links, not evidence. ATT&amp;CK is hypothesized unless marked observed.
                    </Typography>
                    <Typography variant="subtitle2">Risk indicators (documented prototype weights)</Typography>
                    {(inv?.risk?.indicators || []).map((i) => (
                      <Typography key={i.id} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12 }}>
                        +{i.points} {i.label}
                      </Typography>
                    ))}
                    <Typography variant="caption" display="block" color="text.secondary">
                      {inv?.risk?.disclaimer}
                    </Typography>
                    <Typography variant="subtitle2" sx={{ mt: 1 }}>
                      Attack-chain hypothesis
                    </Typography>
                    {(inv?.attack_chain || []).map((s, i) => (
                      <Typography key={i} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12, mb: 0.5 }}>
                        {s.time} — {s.title} technique={s.mitre || "n/a"} status={s.status || "hypothesized"}{" "}
                        conf={s.confidence || "medium"} evidence_ids={(s.evidence_event_ids || []).join(",")}
                      </Typography>
                    ))}
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      Next investigation actions
                    </Typography>
                    {(inv?.next_actions || []).map((a) => (
                      <Typography key={a.priority} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12, mb: 0.5 }}>
                        {a.priority}. {a.action} — {a.reason} evidence_ids={(a.evidence_ids || []).join(",")}
                      </Typography>
                    ))}
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      Correlated activities
                    </Typography>
                    {(inv?.correlations || []).map((g) => (
                      <Typography key={g.correlation_id} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12 }}>
                        {g.timestamp} {g.family} {g.entity} link={g.correlation_id} evidence_ids=
                        {(g.source_event_ids || []).join(",")}
                      </Typography>
                    ))}
                  </Box>
                )}
                {tab === 4 && (
                  <Box sx={{ p: 2, maxHeight: 420, overflow: "auto" }}>
                    <Typography variant="subtitle1">Evidence-linked investigation report</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      The LLM does not treat general forensic knowledge as evidence. Every conclusion is linked to event IDs.
                    </Typography>
                    <Typography variant="subtitle2">
                      Possible {inv?.category} / {inv?.secondary}
                    </Typography>
                    <Typography variant="body2">
                      Investigation Priority: {inv?.risk_score}/100 — {inv?.priority || inv?.risk?.priority}
                    </Typography>
                    <Typography variant="caption" display="block" sx={{ mb: 1 }}>
                      {inv?.risk?.disclaimer}
                    </Typography>
                    <Button size="small" href={`/api/cases/${active}/report`} target="_blank" sx={{ mb: 1 }}>
                      Download PDF
                    </Button>
                    {(inv?.attack_chain || []).map((s, i) => (
                      <Typography key={i} variant="body2" sx={{ fontFamily: "IBM Plex Mono", fontSize: 12 }}>
                        {s.time} {s.title} [{s.mitre || "—"}] {s.status}/{s.confidence} ids=
                        {(s.evidence_event_ids || []).join(",")}
                      </Typography>
                    ))}
                  </Box>
                )}
              </Card>
              <Card sx={{ flex: 1, minWidth: 320 }}>
                <CardContent>
                  <Typography variant="h6">Forensic LLM + case RAG</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Dual retrieval: general forensic knowledge + this case’s timeline.
                  </Typography>
                  {finding && (
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {finding.body}
                      <br />
                      Stages: {finding.attack_stage || "—"}
                      <br />
                      Linked artifacts: {finding.artifact_ids?.join(", ") || "—"}
                    </Typography>
                  )}
                  <TextField
                    fullWidth
                    multiline
                    minRows={2}
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    label="Ask about this case"
                  />
                  <Button sx={{ mt: 1 }} variant="contained" onClick={ask} disabled={busy}>
                    Retrieve & analyze
                  </Button>
                  {answer && (
                    <Box sx={{ mt: 2, whiteSpace: "pre-wrap", fontSize: 14, color: "#cfe7df" }}>{answer}</Box>
                  )}
                </CardContent>
              </Card>
            </Stack>
          </Container>
        )}
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth>
        <DialogTitle>Create case</DialogTitle>
        <DialogContent>
          {["case_number", "title", "investigator", "description"].map((k) => (
            <TextField
              key={k}
              margin="dense"
              fullWidth
              label={k.replace("_", " ")}
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
            />
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={createCase} variant="contained">
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function riskClass(e) {
  const t = `${e.event_type} ${e.description}`.toLowerCase();
  if (/(usb|zip|copy|drive\.google|exfil)/.test(t)) return "hot";
  return "";
}
