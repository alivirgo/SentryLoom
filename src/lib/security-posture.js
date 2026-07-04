const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });

export const RECOMMENDED_PROTECTION_CONFIG = Object.freeze({
  protection: {
    realtimeEnabled: true,
    monitorAllFixedDrives: true,
    networkMonitoringEnabled: true,
    dnsMonitoringEnabled: true,
    autoQuarantineConfirmed: true
  },
  monitoring: {
    processEnabled: true,
    persistenceEnabled: true,
    ransomwareEnabled: true,
    windowsEventsEnabled: true,
    removableMediaEnabled: true,
    firewallIntegrityEnabled: true
  }
});

function issue(id, severity, title, detail, fixable, action) {
  return { id, severity, title, detail, fixable, action };
}

export function calculateSecurityPosture(status, config) {
  let score = 100;
  const issues = [];

  const control = ({ id, title, enabled, running, weight, severity = "high" }) => {
    if (!enabled) {
      score -= weight;
      issues.push(issue(
        `${id}-disabled`,
        severity,
        `${title} is disabled`,
        `Enable ${title.toLowerCase()} to restore this protection layer.`,
        true,
        "Enable recommended protection"
      ));
    } else if (running === false) {
      score -= weight;
      issues.push(issue(
        `${id}-stopped`,
        severity,
        `${title} is not running`,
        "The feature is enabled in policy but its collector is not currently active.",
        true,
        "Restart protection components"
      ));
    }
  };

  control({
    id: "realtime",
    title: "Realtime file protection",
    enabled: config.protection.realtimeEnabled,
    running: status.protection.file.running,
    weight: 22,
    severity: "critical"
  });
  control({
    id: "process",
    title: "Process monitoring",
    enabled: config.monitoring.processEnabled,
    running: status.protection.advanced.running,
    weight: 12
  });
  control({
    id: "ransomware",
    title: "Ransomware monitoring",
    enabled: config.monitoring.ransomwareEnabled,
    running: status.protection.advanced.running,
    weight: 12,
    severity: "critical"
  });
  control({
    id: "network",
    title: "Network IOC monitoring",
    enabled: config.protection.networkMonitoringEnabled,
    running: status.protection.network.running,
    weight: 10
  });
  control({
    id: "dns",
    title: "DNS threat monitoring",
    enabled: config.protection.dnsMonitoringEnabled,
    running: status.protection.network.running,
    weight: 6,
    severity: "medium"
  });
  control({
    id: "windows-events",
    title: "Windows security event monitoring",
    enabled: config.monitoring.windowsEventsEnabled,
    running: status.protection.advanced.running,
    weight: 8,
    severity: "medium"
  });
  control({
    id: "removable",
    title: "Removable-media protection",
    enabled: config.monitoring.removableMediaEnabled,
    running: status.protection.advanced.running,
    weight: 6,
    severity: "medium"
  });
  control({
    id: "persistence",
    title: "Persistence monitoring",
    enabled: config.monitoring.persistenceEnabled,
    running: status.protection.advanced.running,
    weight: 6,
    severity: "medium"
  });

  if (!config.protection.autoQuarantineConfirmed) {
    score -= 10;
    issues.push(issue(
      "automatic-quarantine-disabled",
      "high",
      "Confirmed threats are not quarantined automatically",
      "Exact signature matches will be reported but left in place.",
      true,
      "Enable automatic quarantine"
    ));
  }
  if (!status.audit.valid) {
    score -= 5;
    issues.push(issue(
      "audit-integrity-failed",
      "critical",
      "Audit integrity verification failed",
      `The tamper-evident audit chain failed at record ${status.audit.failedAt ?? "unknown"}.`,
      false,
      "Review the audit log"
    ));
  } else if (status.audit.recovered) {
    score -= 2;
    issues.push(issue(
      "audit-integrity-recovered",
      "medium",
      "Audit chain recovered with evidence preserved",
      `A previous chain failure at record ${status.audit.originalFailedAt ?? "unknown"} was preserved as ${status.audit.evidenceFile || "an evidence file"}. The active chain is valid.`,
      false,
      "Review preserved audit evidence"
    ));
  }
  const signatureCount = Number(status.signatures.hashCount || 0) +
    Number(status.signatures.patternCount || 0) +
    Number(status.signatures.threatCount || 0) +
    Number(status.clamavEngine.signatureCount || 0);
  if (!signatureCount) {
    score -= 3;
    issues.push(issue(
      "signatures-unavailable",
      "high",
      "No malware signatures are available",
      "Update the local threat databases before relying on signature scans.",
      false,
      "Update threat databases"
    ));
  }

  score = Math.max(0, Math.min(100, score));
  issues.sort((left, right) => SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]);
  return {
    score,
    grade: score >= 90 ? "Excellent" : score >= 75 ? "Good" : score >= 60 ? "Needs attention" : "At risk",
    state: score >= 90 ? "good" : score >= 60 ? "warning" : "critical",
    issues,
    fixableCount: issues.filter((item) => item.fixable).length,
    evaluatedAt: new Date().toISOString()
  };
}
