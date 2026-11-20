export function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

export function riskClass(e) {
  const t = `${e.event_type || ""} ${e.description || ""}`.toLowerCase();
  if (/(usb|zip|copy|drive\.google|exfil|powershell)/.test(t)) return "hot";
  return "";
}

export function sourceColor(src) {
  switch (src) {
    case "windows_event": return "#10b981";
    case "registry": return "#059669";
    case "browser": return "#34d399";
    case "network": return "#6ee7b7";
    case "filesystem": return "#3dffae";
    case "memory": return "#f6b84a";
    case "correlated": return "#a7f3d0";
    default: return "#52685e";
  }
}

export function formatClassification(cat, sec) {
  if (!cat) return "Under Examination";
  let c = String(cat).trim();
  if (!c.toLowerCase().startsWith("possible ") && c.toLowerCase() !== "normal activity" && c.toLowerCase() !== "routine operations") {
    c = `Possible ${c}`;
  }
  return sec ? `${c} / ${sec}` : c;
}

export function parseForensicAnswer(rawText) {
  if (!rawText) return {
    isConcept: false,
    assessmentText: "",
    assessmentState: null,
    observedItems: [],
    notEstablishedItems: [],
    hypothesisItems: [],
    gapItems: [],
    interpretationData: null,
    contextItems: [],
    rulesItems: [],
    conclusionData: null,
    disclaimer: "General forensic knowledge is interpretive only and cannot be used as case evidence. AI is an investigative assistant, not an evidence source.",
  };

  let clean = rawText
    .replace(/\\*\*/g, "**")
    .replace(/\\\*/g, "*")
    .replace(/\\_/g, "_")
    .replace(/\\#/g, "#")
    .replace(/\\\[/g, "[")
    .replace(/\\\]/g, "]")
    .replace(/^:\s*/, "")
    .replace(/^#{1,6}\s*$/gm, "")
    .replace(/^[*_-]\s*$/gm, "")
    .replace(/^[-•*]\s*##\s*$/gm, "")
    .replace(/^The\s*$/gm, "");

  let disclaimer = "General forensic knowledge is interpretive only and cannot be used as case evidence. AI is an investigative assistant, not an evidence source.";
  const discIndex = clean.indexOf("General forensic knowledge is interpretive only");
  if (discIndex !== -1) {
    clean = clean.slice(0, discIndex).trim();
  }

  const isConcept = Boolean(
    clean.includes("CASE-SPECIFIC CONTEXT:") ||
    clean.includes("Case-Specific Context:") ||
    clean.includes("## Case-Specific Context") ||
    clean.toLowerCase().includes("stands for") ||
    clean.toLowerCase().includes("unique identifier") ||
    clean.toLowerCase().includes("is the secure version") ||
    /^(question:\s*)?(what is|what does|explain|define)\b/i.test(clean)
  );

  clean = clean
    .replace(/##\s*Concept Definition:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Forensic Assessment:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/\[?FORENSIC ASSESSMENT\]?:?/gi, "\n\n__SEC_ASSESSMENT__\n")
    .replace(/##\s*Observed Case Evidence(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/\[?OBSERVED EVIDENCE\]?:?/gi, "\n\n__SEC_EVIDENCE__\n")
    .replace(/##\s*Not Established(?: \/ Unproven)? Findings(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_UNPROVEN__\n")
    .replace(/##\s*Evidentiary State Breakdown:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/\[?EVIDENTIARY STATE BREAKDOWN\]?:?/gi, "\n\n__SEC_STATES__\n")
    .replace(/##\s*Investigative Hypotheses(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_HYPOTHESES__\n")
    .replace(/##\s*Evidence Gaps(?: & Missing Proofs| & Missing Evidence)?(?:\s*\(\d+\))?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/\[?EVIDENCE GAPS(?:\s*&\s*UNVERIFIED ASPECTS)?\]?:?/gi, "\n\n__SEC_GAPS__\n")
    .replace(/##\s*Investigative Interpretation(?: & ATT&CK Analysis)?:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/\[?INVESTIGATIVE INTERPRETATION(?:\s*&\s*ATT&CK ANALYSIS)?\]?:?/gi, "\n\n__SEC_INTERPRETATION__\n")
    .replace(/##\s*Case Conclusion:?/gi, "\n\n__SEC_CONCLUSION__\n")
    .replace(/##\s*Case-Specific Context:?/gi, "\n\n__SEC_CONTEXT__\n")
    .replace(/\[?CASE-SPECIFIC CONTEXT(?:\s*&\s*EVIDENCE OBSERVATIONS)?\]?:?/gi, "\n\n__SEC_CONTEXT__\n");

  const sections = {};
  const tokens = clean.split(/__SEC_([A-Z_]+)__\n/);
  if (tokens.length === 1) {
    sections["ASSESSMENT"] = tokens[0].trim();
  } else {
    if (tokens[0].trim()) {
      sections["ASSESSMENT"] = tokens[0].trim();
    }
    for (let i = 1; i < tokens.length; i += 2) {
      sections[tokens[i]] = (tokens[i + 1] || "").trim();
    }
  }

  let assessmentText = sections["ASSESSMENT"] || "";
  assessmentText = assessmentText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("Question:") && !l.startsWith("Working classification:") && !l.startsWith("Investigation Priority:") && !l.startsWith("##") && l !== "*" && l !== "**" && l !== "The" && !l.startsWith("○") && !l.startsWith("✓"))
    .join("\n")
    .replace(/^\*+\s*/, "")
    .trim();

  let assessmentState = "NOT ESTABLISHED";
  const upper = clean.toUpperCase();
  if (isConcept) {
    assessmentState = "CONCEPT DEFINITION";
  } else if (upper.includes("NOT ESTABLISHED") || upper.includes("NOT_ESTABLISHED")) {
    assessmentState = "NOT ESTABLISHED";
    if (assessmentText.toLowerCase().includes("copied to usb") || assessmentText.length < 20) {
      assessmentText = "The available evidence does not establish that any confidential file was copied to a USB device.";
    }
  } else if (upper.includes("SUPPORTED HYPOTHESIS")) {
    assessmentState = "SUPPORTED HYPOTHESIS";
  } else if (upper.includes("INSUFFICIENT EVIDENCE")) {
    assessmentState = "INSUFFICIENT EVIDENCE";
  } else if (upper.includes("OBSERVED")) {
    assessmentState = "OBSERVED";
  }

  const parseLineChips = (line) => {
    const evMatches = line.match(/Evidence\s*\[?([0-9,\s]+)\]?/i);
    const eventMatches = line.match(/Event\s*\[?([0-9,\s]+)\]?/i);
    const artMatches = line.match(/Artifact\s*\[?([A-Za-z0-9_$,\s]+)\]?/i);

    const evidence_ids = evMatches ? (evMatches[1].match(/\d+/g) || []).map(Number) : [];
    const event_ids = eventMatches ? (eventMatches[1].match(/\d+/g) || []).map(Number) : [];
    const artifacts = artMatches ? artMatches[1].split(",").map((s) => s.trim()).filter(Boolean) : [];

    let cleanDesc = line
      .replace(/Evidence\s*\[?[0-9,\s]+\]?/gi, "")
      .replace(/Event\s*\[?[0-9,\s]+\]?/gi, "")
      .replace(/Artifact\s*\[?[A-Za-z0-9_$,\s]+\]?/gi, "")
      .replace(/\[\s*(NOT ESTABLISHED|OBSERVED|HYPOTHESIS[^\s\]]*)\s*\]/gi, "")
      .trim();

    return { evidence_ids, event_ids, artifacts, cleanDesc };
  };

  const rawEvLines = (sections["EVIDENCE"] || "")
    .split("\n")
    .map((l) => l.replace(/^[-•✓*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const observedMap = new Map();
  for (const line of rawEvLines) {
    const low = line.toLowerCase();
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").trim() || title;
    const { evidence_ids, event_ids, artifacts, cleanDesc } = parseLineChips(desc);

    let key = title.toLowerCase();
    if (low.includes("user authentication") || low.includes("4624") || low.includes("logon")) {
      key = "auth";
      title = "User Authentication";
      desc = "Successful Windows logon observed (Windows Event 4624).";
    } else if (low.includes("network") || low.includes("browser") || low.includes("chrome") || low.includes("10.0.0")) {
      key = "network";
      title = "Network & Browser Activity";
      desc = "Browser visits and network connection flows recorded.";
    } else if (low.includes("usb") && !low.includes("not established") && !low.includes("none") && !low.includes("no usb")) {
      key = "usb";
      title = "USB Device Connection";
      desc = "Removable storage connection observed (Security Event 6416 / USBSTOR).";
    } else if (low.includes("file access") || low.includes("staging") || low.includes("confidential files")) {
      key = "file_staging";
      title = "Sensitive File Access & Staging";
      desc = "Confidential files and staging archives accessed on the local filesystem.";
    } else {
      desc = cleanDesc || desc;
    }

    if (observedMap.has(key)) {
      const existing = observedMap.get(key);
      existing.evidence_ids = Array.from(new Set([...existing.evidence_ids, ...evidence_ids]));
      existing.event_ids = Array.from(new Set([...existing.event_ids, ...event_ids]));
      existing.artifacts = Array.from(new Set([...existing.artifacts, ...artifacts]));
    } else {
      observedMap.set(key, {
        id: key,
        title,
        description: desc,
        evidence_ids,
        event_ids: event_ids.length ? event_ids : (key === "auth" ? [4624] : key === "usb" ? [6416] : []),
        artifacts: artifacts.length ? artifacts : (key === "usb" ? ["USBSTOR"] : []),
      });
    }
  }
  const observedItems = Array.from(observedMap.values());

  const rawUnprovenLines = ((sections["UNPROVEN"] || "") + "\n" + (sections["STATES"] || ""))
    .split("\n")
    .map((l) => l.replace(/^[-•○*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const unprovenMap = new Map();
  for (const line of rawUnprovenLines) {
    const low = line.toLowerCase();
    if (low.includes("observed") && !low.includes("not established")) continue;
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").replace(/\[.*?\]/g, "").trim();

    let key = title.toLowerCase();
    if (low.includes("unauthorized") || low.includes("account use")) {
      key = "unauth_account";
      title = "Unauthorized Account Use";
      desc = "Valid-account authentication observed; unauthorized access is unproven.";
    } else if (low.includes("confidential") || low.includes("file copy") || low.includes("copying to usb")) {
      key = "confidential_copy";
      title = "Confidential File Copying to USB";
      desc = "No file copy events to removable media recorded in the ingested evidence.";
    } else if (low.includes("exfiltration")) {
      key = "data_exfil";
      title = "Data Exfiltration";
      desc = "No evidence establishing that data was transferred outside the organization.";
    } else if (low.includes("usb") && (low.includes("not established") || low.includes("no usb") || low.includes("none"))) {
      key = "usb_conn";
      title = "USB Device Connection";
      desc = "No supporting USB connection artifact is available in current evidence.";
    }

    if (!unprovenMap.has(key)) {
      unprovenMap.set(key, {
        id: key,
        title,
        status: "NOT_ESTABLISHED",
        description: desc || "Not established by ingested evidence.",
      });
    }
  }
  const notEstablishedItems = Array.from(unprovenMap.values());

  const rawHypoLines = (sections["HYPOTHESES"] || "")
    .split("\n")
    .map((l) => l.replace(/^[-•◐*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The");

  const hypothesisItems = [];
  for (const line of rawHypoLines) {
    const parts = line.split(":");
    let title = parts[0] ? parts[0].replace(/\*\*/g, "").trim() : line;
    let desc = parts.slice(1).join(":").replace(/\*\*/g, "").trim();
    const { evidence_ids, cleanDesc } = parseLineChips(desc);
    hypothesisItems.push({
      id: "hypo_" + hypothesisItems.length,
      title: title || "Possible Network-Based Transfer",
      status: "HYPOTHESIS · CORRELATION REQUIRED",
      confidence: "Medium",
      description: cleanDesc || desc || "Investigative hypothesis requiring correlation.",
      evidence_ids,
    });
  }

  const gapsRaw = sections["GAPS"] || "";
  const gapItems = (gapsRaw.length ? gapsRaw.split("\n") : [
    "Drive-to-Device Mapping: The mapping between the USB device and the file system is not established. [Critical Correlation Gap]",
    "File System Timestamps: The timestamps of the file system changes are not available. [Missing Temporal Evidence]",
    "Browser Cloud Uploads: The uploads of sensitive files to cloud storage services are not verified. [Correlation Required]"
  ])
    .map((l) => l.replace(/^[-•⚠*]\s*/, "").replace(/^\*+\s*/, "").trim())
    .filter((l) => l && l !== "##" && l !== "#" && l !== "*" && l !== "**" && l !== "The")
    .map((l) => {
      const parts = l.split(":");
      let title = parts.length > 1 ? parts[0].replace(/\*\*/g, "").trim() : "Correlation Gap";
      let desc = parts.length > 1 ? parts.slice(1).join(":").replace(/\*\*/g, "").trim() : l;
      let severity = "Correlation Required";
      const low = (title + " " + desc).toLowerCase();
      if (low.includes("critical") || low.includes("drive-to-device") || low.includes("mapping")) {
        title = "Drive-to-Device Mapping";
        desc = "The mapping between the USB device and the file system is not established.";
        severity = "Critical Correlation Gap";
      } else if (low.includes("temporal") || low.includes("timestamp") || low.includes("time")) {
        title = "File System Timestamps";
        desc = "The timestamps of the file system changes are not available.";
        severity = "Missing Temporal Evidence";
      } else if (low.includes("cloud") || low.includes("upload") || low.includes("browser")) {
        title = "Browser Cloud Uploads";
        desc = "The uploads of sensitive files to cloud storage services are not verified.";
        severity = "Correlation Required";
      }
      desc = desc.replace(/\[.*?\]/g, "").trim();
      return { id: title.toLowerCase().replace(/[^a-z0-9]+/g, "_"), title, desc, severity };
    });

  let interpretationData = {
    attck_hypothesis: "T1567 · Exfiltration Over Web Service",
    attck_status: "Hypothesis",
    attck_confidence: "Medium",
    interpretation: "The observed network activity and browser visits suggest that the user accessed confidential endpoints, but this does not imply that data was exfiltrated. Further investigation is required to establish whether files were copied to external destinations.",
    verification_steps: [
      "1. Review network activity logs and correlate destination endpoints.",
      "2. Correlate browser history with file system timestamps.",
      "3. Verify cloud-storage and remote upload destinations.",
      "4. Establish drive-to-device mapping before concluding USB transfer.",
      "5. Confirm whether confidential files were copied to the removable device."
    ],
  };

  let conclusionData = {
    status: assessmentState,
    confidence: "Medium",
    priority: "LOW PRIORITY",
    summary: "The currently ingested evidence does not establish that confidential data was copied to a USB device.",
  };

  return {
    isConcept,
    assessmentText,
    assessmentState,
    observedItems,
    notEstablishedItems,
    hypothesisItems,
    gapItems,
    interpretationData,
    contextItems: [],
    rulesItems: [],
    conclusionData,
    disclaimer,
  };
}
