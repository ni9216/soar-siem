import { lazy, Suspense, useEffect, useEffectEvent, useRef, useState } from "react";
import { io } from "socket.io-client";

const IncidentSummaryChart = lazy(() => import("./IncidentSummaryChart"));
const OperationsPanels = lazy(() => import("./OperationsPanels"));

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";
const COLORS = {
  Critical: "#ef4444",
  High: "#f59e0b",
  Medium: "#60a5fa",
  Low: "#22c55e",
};

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "incidents", label: "Incidents" },
  { id: "timeline", label: "Investigation" },
  { id: "assets", label: "Assets" },
  { id: "hunt", label: "Threat Hunt" },
  { id: "logs", label: "Live Logs" },
  { id: "threats", label: "Threat Intelligence" },
  { id: "playbooks", label: "Playbooks" },
  { id: "detections", label: "Detections" },
  { id: "soar", label: "SOAR & Automation" },
  { id: "cases", label: "Case Management" },
  { id: "users", label: "User Management", adminOnly: true },
  { id: "enterprise", label: "Security Operations", adminOnly: true },
  { id: "settings", label: "Settings" },
];

function SummaryCard({ title, value, color }) {
  return (
    <div
      style={{
        flex: 1,
        minWidth: 150,
        borderRadius: 18,
        background: "#0f172a",
        padding: 18,
        border: "1px solid #1e293b",
        marginRight: 16,
      }}
    >
      <div style={{ color: "#94a3b8", fontSize: 14, marginBottom: 8 }}>
        {title}
      </div>
      <div style={{ color, fontSize: 28, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

export default function Dashboard({ auth, onLogout }) {
  const [activeTab, setActiveTab] = useState("overview");
  const [incidents, setIncidents] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ Critical: 0, High: 0, Medium: 0, Low: 0 });
  const [users, setUsers] = useState([]);
  const [threats, setThreats] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [scanTarget, setScanTarget] = useState("");
  const [scanMessage, setScanMessage] = useState("");
  const [workflowNote, setWorkflowNote] = useState("Select a workflow to get started.");
  const [noteEdits, setNoteEdits] = useState({});
  const [tiQuery, setTiQuery] = useState("");
  const [tiResult, setTiResult] = useState(null);
  const [tiStatus, setTiStatus] = useState("");
  const socketRef = useRef(null);
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "analyst" });
  const [editingUser, setEditingUser] = useState(null);
  const [userMessage, setUserMessage] = useState("");
  const [auditLogs, setAuditLogs] = useState([]);
  const [detectionRules, setDetectionRules] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [mlEvaluation, setMlEvaluation] = useState(null);
  const [operationsHealth, setOperationsHealth] = useState(null);
  const [securityPolicy, setSecurityPolicy] = useState({ require_admin_mfa: false });
  const [dedupWindowMinutes, setDedupWindowMinutes] = useState(5);
  const [alertGroups, setAlertGroups] = useState([]);
  const [cases, setCases] = useState([]);
  const [newCase, setNewCase] = useState({ title: "", description: "", severity: "Medium", incident_ids: [] });
  const [caseNote, setCaseNote] = useState("");
  const [logSources, setLogSources] = useState([]);
  const [newSysmonSourceName, setNewSysmonSourceName] = useState("");
  const [newSysmonApiKey, setNewSysmonApiKey] = useState("");
  const [backups, setBackups] = useState([]);
  const [auditActorFilter, setAuditActorFilter] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState("");
  const [enterpriseMessage, setEnterpriseMessage] = useState("");
  const [newRule, setNewRule] = useState({ name: "", pattern: "", severity: "Medium", mitre_attack_id: "" });
  const [overviewRange, setOverviewRange] = useState(24);
  const [assets, setAssets] = useState([]);
  const [assetQuery, setAssetQuery] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState(null);
  const [newAsset, setNewAsset] = useState({ name: "", ip_address: "", hostname: "", asset_type: "server", criticality: "medium", owner: "" });
  const [huntQuery, setHuntQuery] = useState("");
  const [huntResults, setHuntResults] = useState({ incidents: [], assets: [], logs: [] });
  const [huntMessage, setHuntMessage] = useState("");
  const [selectedPlaybookIncidentId, setSelectedPlaybookIncidentId] = useState("");
  const [playbookChoice, setPlaybookChoice] = useState("investigation");
  const [playbookMessage, setPlaybookMessage] = useState("");
  const [ruleTestId, setRuleTestId] = useState(null);
  const [ruleTestLog, setRuleTestLog] = useState("");
  const [ruleMessage, setRuleMessage] = useState("");
  const [assetMessage, setAssetMessage] = useState("");
  const canManageIncidents = ["admin", "analyst"].includes(auth?.role);
  const isViewer = auth?.role === "viewer";
  const availableTabs = tabs.filter(tab => !tab.adminOnly || auth?.role === "admin");

  const fetchWithAuth = async (path, options = {}) => {
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${auth?.token}`,
    };

    const response = await fetch(`${API}${path}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      onLogout();
      return null;
    }

    return response;
  };

  const loadIncidents = async () => {
    const response = await fetchWithAuth("/api/incidents");
    if (!response) return;
    const data = await response.json();
    setIncidents(data);
  };

  const loadStats = async () => {
    const response = await fetchWithAuth("/api/stats");
    if (!response) return;
    const data = await response.json();
    setStats({ Critical: 0, High: 0, Medium: 0, Low: 0, ...data });
  };

  const loadUsers = async () => {
    const response = await fetchWithAuth("/api/users");
    if (!response) return;
    if (response.status === 403) {
      setUsers([]);
      return;
    }
    const data = await response.json();
    setUsers(data);
  };

  const loadThreats = async () => {
    const response = await fetchWithAuth("/api/threats");
    if (!response) return;
    const data = await response.json();
    setThreats(data);
  };

  const loadCases = async () => {
    const response = await fetchWithAuth("/api/cases");
    if (!response) return;
    const data = await response.json();
    setCases(data);
  };

  const loadAssets = async () => {
    const response = await fetchWithAuth("/api/assets");
    if (!response?.ok) return;
    setAssets(await response.json());
  };

  const loadPlaybookConsole = async () => {
    const response = await fetchWithAuth("/api/soar/executions");
    if (!response?.ok) return;
    setExecutions(await response.json());
  };

  const loadDetections = async () => {
    const [rulesResponse, groupsResponse] = await Promise.all([
      fetchWithAuth("/api/rules"),
      fetchWithAuth("/api/alert-groups"),
    ]);
    if (rulesResponse?.ok) setDetectionRules(await rulesResponse.json());
    if (groupsResponse?.ok) setAlertGroups(await groupsResponse.json());
    if (auth?.role === "admin") {
      const dedupResponse = await fetchWithAuth("/api/alert-deduplication");
      if (dedupResponse?.ok) setDedupWindowMinutes((await dedupResponse.json()).window_minutes);
    }
  };

  const createAsset = async () => {
    if (!newAsset.name.trim()) return setAssetMessage("An asset name is required.");
    const response = await fetchWithAuth("/api/assets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newAsset),
    });
    if (!response) return;
    const data = await response.json();
    if (!response.ok) return setAssetMessage(data.error || "Unable to create asset.");
    setAssets((current) => [data, ...current]);
    setSelectedAssetId(data.id);
    setNewAsset({ name: "", ip_address: "", hostname: "", asset_type: "server", criticality: "medium", owner: "" });
    setAssetMessage("Asset added to inventory.");
  };

  const runThreatHunt = async () => {
    const query = huntQuery.trim();
    if (query.length < 2) {
      setHuntMessage("Enter at least 2 characters to search.");
      return;
    }
    setHuntMessage("Searching incidents, assets, and recent live logs...");
    try {
      const [incidentResponse, assetResponse] = await Promise.all([
        fetchWithAuth(`/api/search?q=${encodeURIComponent(query)}`),
        fetchWithAuth(`/api/assets/search?q=${encodeURIComponent(query)}`),
      ]);
      if (!incidentResponse || !assetResponse) return;
      const incidentData = incidentResponse.ok ? await incidentResponse.json() : [];
      const assetData = assetResponse.ok ? await assetResponse.json() : [];
      const matchingLogs = logs.filter((log) => JSON.stringify(log).toLowerCase().includes(query.toLowerCase()));
      setHuntResults({ incidents: incidentData, assets: assetData, logs: matchingLogs });
      setHuntMessage(`Found ${incidentData.length} incidents, ${assetData.length} assets, and ${matchingLogs.length} recent live logs.`);
    } catch {
      setHuntMessage("Threat hunt search could not reach the API.");
    }
  };

  const requestPlaybookExecution = async (dryRun) => {
    const incidentId = Number(selectedPlaybookIncidentId);
    if (!incidentId) {
      setPlaybookMessage("Select an incident before requesting a playbook.");
      return;
    }
    const response = await fetchWithAuth("/api/soar/executions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: incidentId, playbook: playbookChoice, dry_run: dryRun }),
    });
    if (!response) return;
    const data = await response.json();
    setPlaybookMessage(response.ok
      ? dryRun ? `Dry run recorded as execution #${data.id}. No actions were performed.` : `Execution #${data.id} is awaiting administrator approval.`
      : data.error || "Unable to request playbook execution.");
    if (response.ok) await loadPlaybookConsole();
  };

  const testDetectionRuleWithSample = async (rule) => {
    if (!rule) {
      setRuleMessage("Select an available rule to test.");
      return;
    }
    if (!ruleTestLog.trim()) {
      setRuleMessage("Enter a sample event before testing the rule.");
      return;
    }
    const response = await fetchWithAuth(`/api/rules/${rule.id}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log: ruleTestLog }),
    });
    if (!response) return;
    const data = await response.json();
    setRuleMessage(response.ok
      ? `${rule.name}: ${data.matched ? `matched at ${data.severity} severity` : "no match"}.`
      : data.error || "Unable to test rule.");
  };

  const createCase = async () => {
    if (!newCase.title.trim()) {
      setWorkflowNote("A case title is required.");
      return;
    }
    const response = await fetchWithAuth("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: newCase.title.trim(),
        description: newCase.description.trim(),
        severity: newCase.severity,
        incident_ids: newCase.incident_ids,
      }),
    });
    if (!response) return;
    const data = await response.json();
    if (response.ok) {
      setCases((current) => [data, ...current]);
      setNewCase({ title: "", description: "", severity: "Medium", incident_ids: [] });
      setWorkflowNote(`Case "${data.title}" created.`);
    } else {
      setWorkflowNote(data.error || "Unable to create case.");
    }
  };

  const updateCaseStatus = async (caseId, status) => {
    const response = await fetchWithAuth(`/api/cases/${caseId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (!response) return;
    const data = await response.json();
    setCases((current) => current.map((item) => item.id === data.id ? data : item));
  };

  const addCaseNote = async (caseId) => {
    if (!caseNote.trim()) return;
    const response = await fetchWithAuth(`/api/cases/${caseId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: caseNote.trim() }),
    });
    if (!response) return;
    const data = await response.json();
    setCases((current) => current.map((item) => item.id === data.id ? data : item));
    setCaseNote("");
  };

  const deleteCase = async (caseId) => {
    const response = await fetchWithAuth(`/api/cases/${caseId}`, { method: "DELETE" });
    if (!response) return;
    setCases((current) => current.filter((item) => item.id !== caseId));
  };

  const loadEnterprise = async () => {
    const auditQuery = new URLSearchParams({ limit: "50" });
    if (auditActorFilter.trim()) auditQuery.set("actor", auditActorFilter.trim());
    if (auditActionFilter.trim()) auditQuery.set("action", auditActionFilter.trim());
    const endpoints = [
      `/api/audit-logs?${auditQuery}`,
      "/api/rules",
      "/api/soar/executions",
      "/api/operations/health",
      "/api/security-policy",
      "/api/ml/evaluation",
    ];
    try {
      const responses = await Promise.all(endpoints.map((endpoint) => fetchWithAuth(endpoint)));
      if (responses.some((response) => !response || !response.ok)) {
        setEnterpriseMessage("Unable to load one or more enterprise controls.");
        return;
      }
      const [audit, rules, workflowExecutions, health, policy, evaluation] = await Promise.all(responses.map((response) => response.json()));
      setAuditLogs(audit);
      setDetectionRules(rules);
      setExecutions(workflowExecutions);
      setOperationsHealth(health);
      setSecurityPolicy(policy);
      setMlEvaluation(evaluation);
      const optionalResponses = await Promise.all([
        fetchWithAuth("/api/alert-deduplication"),
        fetchWithAuth("/api/alert-groups"),
        fetchWithAuth("/api/ingestion/sources"),
        fetchWithAuth("/api/admin/backups"),
      ]);
      if (optionalResponses[0]?.ok) {
        setDedupWindowMinutes((await optionalResponses[0].json()).window_minutes);
      }
      if (optionalResponses[1]?.ok) setAlertGroups(await optionalResponses[1].json());
      if (optionalResponses[2]?.ok) setLogSources(await optionalResponses[2].json());
      if (optionalResponses[3]?.ok) setBackups(await optionalResponses[3].json());
      setEnterpriseMessage("");
    } catch {
      setEnterpriseMessage("Unable to connect to enterprise controls.");
    }
  };

  const createSysmonSource = async () => {
    if (!newSysmonSourceName.trim()) {
      setEnterpriseMessage("Enter a name for the Sysmon source.");
      return;
    }
    const response = await fetchWithAuth("/api/ingestion/sources", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newSysmonSourceName.trim(), source_type: "windows_event" }),
    });
    if (!response) return;
    const data = await response.json();
    if (!response.ok) {
      setEnterpriseMessage(data.error || "Unable to create Sysmon source.");
      return;
    }
    setLogSources((current) => [...current.filter((source) => source.id !== data.id), data]);
    setNewSysmonSourceName("");
    setNewSysmonApiKey(data.api_key);
    setEnterpriseMessage("Sysmon source created. Copy its API key now; it will not be shown again.");
  };

  const rotateSysmonKey = async (sourceId) => {
    const response = await fetchWithAuth(`/api/ingestion/sources/${sourceId}/rotate-key`, { method: "POST" });
    if (!response) return;
    const data = await response.json();
    if (!response.ok) {
      setEnterpriseMessage(data.error || "Unable to rotate Sysmon API key.");
      return;
    }
    setNewSysmonApiKey(data.api_key);
    setEnterpriseMessage("Sysmon key rotated. Copy the new key now; the previous key is no longer valid.");
  };

  const saveDedupWindow = async () => {
    const windowMinutes = Number(dedupWindowMinutes);
    if (!Number.isInteger(windowMinutes) || windowMinutes < 0 || windowMinutes > 1440) {
      setEnterpriseMessage("Deduplication window must be a whole number between 0 and 1440.");
      return;
    }
    const response = await fetchWithAuth("/api/alert-deduplication", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ window_minutes: windowMinutes }),
    });
    if (!response) return;
    const data = await response.json();
    setEnterpriseMessage(response.ok ? "Alert deduplication settings saved." : data.error || "Unable to save deduplication settings.");
    setRuleMessage(response.ok ? "Alert deduplication settings saved." : data.error || "Unable to save deduplication settings.");
  };

  const toggleDetectionRule = async (rule) => {
    const response = await fetchWithAuth(`/api/rules/${rule.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (!response) return;
    const data = await response.json();
    if (response.ok) {
      setDetectionRules((current) => current.map((item) => item.id === data.id ? data : item));
      setEnterpriseMessage(`Rule ${data.enabled ? "enabled" : "disabled"}.`);
      setRuleMessage(`Rule ${data.enabled ? "enabled" : "disabled"}.`);
    } else {
      setEnterpriseMessage(data.error || "Unable to update detection rule.");
      setRuleMessage(data.error || "Unable to update detection rule.");
    }
  };

  const testDetectionRule = async (rule) => {
    const sample = window.prompt("Enter a sample log to test against this rule:");
    if (!sample) return;
    const response = await fetchWithAuth(`/api/rules/${rule.id}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log: sample }),
    });
    if (!response) return;
    const data = await response.json();
    setEnterpriseMessage(response.ok
      ? `Rule ${rule.name}: ${data.matched ? `matched (${data.severity})` : "no match"}.`
      : data.error || "Unable to test detection rule.");
  };

  const createDatabaseBackup = async () => {
    const response = await fetchWithAuth("/api/admin/backups", { method: "POST" });
    if (!response) return;
    const data = await response.json();
    if (!response.ok) {
      setEnterpriseMessage(data.error || "Unable to create database backup.");
      return;
    }
    setEnterpriseMessage(`Backup created: ${data.filename}`);
    const listResponse = await fetchWithAuth("/api/admin/backups");
    if (listResponse?.ok) setBackups(await listResponse.json());
  };

  const downloadDatabaseBackup = async (filename) => {
    const response = await fetchWithAuth(`/api/admin/backups/${encodeURIComponent(filename)}`);
    if (!response) return;
    if (!response.ok) {
      const data = await response.json();
      setEnterpriseMessage(data.error || "Unable to download database backup.");
      return;
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
    setEnterpriseMessage(`Downloaded ${filename}.`);
  };

  const saveSecurityPolicy = async (requireAdminMfa) => {
    const response = await fetchWithAuth("/api/security-policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ require_admin_mfa: requireAdminMfa }),
    });
    if (!response) return;
    if (response.ok) {
      setSecurityPolicy({ require_admin_mfa: requireAdminMfa });
      setEnterpriseMessage("Security policy updated.");
    } else {
      setEnterpriseMessage("Unable to update security policy.");
    }
  };

  const createDetectionRule = async () => {
    const response = await fetchWithAuth("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newRule),
    });
    if (!response) return;
    const data = await response.json();
    if (response.ok) {
      setDetectionRules((current) => [...current, data].sort((left, right) => left.name.localeCompare(right.name)));
      setNewRule({ name: "", pattern: "", severity: "Medium", mitre_attack_id: "" });
      setEnterpriseMessage("Detection rule created.");
      setRuleMessage("Detection rule created.");
    } else {
      setEnterpriseMessage(data.error || "Unable to create detection rule.");
      setRuleMessage(data.error || "Unable to create detection rule.");
    }
  };

  const deleteDetectionRule = async (ruleId) => {
    const response = await fetchWithAuth(`/api/rules/${ruleId}`, { method: "DELETE" });
    if (!response) return;
    if (response.ok) {
      setDetectionRules((current) => current.filter((rule) => rule.id !== ruleId));
      setEnterpriseMessage("Detection rule deleted.");
      setRuleMessage("Detection rule deleted.");
    }
  };

  const approveExecution = async (executionId) => {
    const response = await fetchWithAuth(`/api/soar/executions/${executionId}/approve`, { method: "POST" });
    if (!response) return;
    if (response.ok) {
      const data = await response.json();
      await Promise.all([loadEnterprise(), loadIncidents()]);
      setEnterpriseMessage(
        data.status === "failed"
          ? data.result?.error || "The approved execution failed."
          : "SOAR execution approved."
      );
    } else {
      const data = await response.json();
      setEnterpriseMessage(data.error || "Unable to approve SOAR execution.");
    }
  };

  const rejectExecution = async (executionId) => {
    const response = await fetchWithAuth(`/api/soar/executions/${executionId}/reject`, { method: "POST" });
    if (!response) return;
    const data = await response.json();
    if (response.ok) {
      await loadEnterprise();
      setEnterpriseMessage("SOAR execution rejected; no actions were performed.");
    } else {
      setEnterpriseMessage(data.error || "Unable to reject SOAR execution.");
    }
  };

  const rollbackExecution = async (executionId) => {
    const response = await fetchWithAuth(`/api/soar/executions/${executionId}/rollback`, { method: "POST" });
    if (!response) return;
    const data = await response.json();
    if (response.ok) {
      await Promise.all([loadEnterprise(), loadIncidents()]);
      setEnterpriseMessage(data.result?.rollback?.message || "Rollback recorded.");
    } else {
      setEnterpriseMessage(data.error || "Unable to record rollback.");
    }
  };

  const lookupAbuseIPDB = async () => {
    if (!tiQuery.trim()) {
      setTiStatus("Enter an IP address to query.");
      return;
    }
    setTiStatus("Querying AbuseIPDB...");
    const response = await fetchWithAuth(`/api/threats/abuseipdb?ip=${encodeURIComponent(tiQuery)}`);
    if (!response) return;
    const data = await response.json();
    setTiResult(data);
    setTiStatus(response.ok ? "Lookup complete." : "Lookup failed.");
  };

  const updateIncident = async (incidentId, patch) => {
    const response = await fetchWithAuth(`/api/incidents/${incidentId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(patch),
    });
    if (!response) return null;
    const data = await response.json();
    setIncidents((current) => current.map((inc) => (inc.id === data.id ? data : inc)));
    return data;
  };

  const assignIncident = async (incidentId, userId) => {
    const response = await fetchWithAuth(`/api/incidents/${incidentId}/assign`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ assigned_to: userId }),
    });
    if (!response) return null;
    const data = await response.json();
    setIncidents((current) => current.map((inc) => (inc.id === data.id ? data : inc)));
    return data;
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      await loadIncidents();
      return;
    }

    const response = await fetchWithAuth(
      `/api/search?q=${encodeURIComponent(searchQuery)}`
    );
    if (!response) return;

    const data = await response.json();
    setIncidents(data);
  };

  const handleNoteChange = (incidentId, value) => {
    setNoteEdits((prev) => ({ ...prev, [incidentId]: value }));
  };

  const saveIncidentNote = async (incidentId) => {
    const notes = noteEdits[incidentId] ?? incidents.find((inc) => inc.id === incidentId)?.notes ?? "";
    await updateIncident(incidentId, { notes });
  };

  const runScan = async () => {
    if (!scanTarget.trim()) {
      setScanMessage("Enter a target host or IP to scan.");
      return;
    }

    try {
      const response = await fetchWithAuth("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target: scanTarget }),
      });
      if (!response) return;

      const data = await response.json();
      setScanMessage(data.message || "Scan started successfully.");
    } catch {
      setScanMessage("Failed to launch scan. Check backend connectivity.");
    }
  };

  const triggerPlaybook = async (playbook, dryRun = false) => {
    if (!incidents.length) {
      setWorkflowNote("No incident available to run the playbook.");
      return;
    }

    const incidentId = incidents[0].id;
    const response = await fetchWithAuth("/api/soar/run", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ incident_id: incidentId, playbook, dry_run: dryRun }),
    });

    if (!response) return;
    const data = await response.json();

    if (response.ok) {
      setWorkflowNote(data.message || `Playbook ${playbook} triggered.`);
      if (data.incident) {
        setIncidents((current) => current.map((inc) => (inc.id === data.incident.id ? data.incident : inc)));
      }
    } else {
      setWorkflowNote(data.error || `Failed to run ${playbook} playbook.`);
    }
  };

  const launchWorkflow = (workflow, dryRun = false) => {
    triggerPlaybook(workflow, dryRun);
  };

  const createUser = async () => {
    if (!newUser.username || !newUser.password) {
      setUserMessage("Username and password are required.");
      return;
    }

    try {
      const response = await fetchWithAuth("/api/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(newUser),
      });

      if (!response) return;

      if (response.ok) {
        setUserMessage("User created successfully.");
        setNewUser({ username: "", password: "", role: "analyst" });
        loadUsers();
      } else {
        const data = await response.json();
        setUserMessage(data.error || "Failed to create user.");
      }
    } catch {
      setUserMessage("Failed to create user.");
    }
  };

  const updateUser = async (userId, updates) => {
    try {
      const response = await fetchWithAuth(`/api/users/${userId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(updates),
      });

      if (!response) return;

      if (response.ok) {
        setUserMessage("User updated successfully.");
        setEditingUser(null);
        loadUsers();
      } else {
        const data = await response.json();
        setUserMessage(data.error || "Failed to update user.");
      }
    } catch {
      setUserMessage("Failed to update user.");
    }
  };

  const deleteUser = async (userId) => {
    if (!confirm("Are you sure you want to delete this user?")) return;

    try {
      const response = await fetchWithAuth(`/api/users/${userId}`, {
        method: "DELETE",
      });

      if (!response) return;

      if (response.ok) {
        setUserMessage("User deleted successfully.");
        loadUsers();
      } else {
        const data = await response.json();
        setUserMessage(data.error || "Failed to delete user.");
      }
    } catch {
      setUserMessage("Failed to delete user.");
    }
  };

  const filteredIncidents = incidents.filter((incident) => {
    const matchesSearch = !searchQuery.trim() || JSON.stringify(incident).toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === "all" || incident.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || (incident.status || "open") === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId) || null;

  const quickIncidentStatusOptions = [
    { value: "investigating", label: "Investigating" },
    { value: "contained", label: "Contain" },
    { value: "escalated", label: "Escalate" },
    { value: "resolved", label: "Resolve" },
  ];

  const getIncidentEnrichment = (incident) => {
    const incidentText = `${incident.title || ""} ${incident.details || ""}`.toLowerCase();
    const relatedThreats = threats.filter((threat) => {
      const target = `${threat.indicator || ""} ${threat.type || ""}`.toLowerCase();
      return target && incidentText.includes(target.split(" ")[0]);
    }).slice(0, 2);

    const mitreId = incident.mitre_attack_id || "T1078";
    const caseTags = [
      incident.severity || "Medium",
      mitreId,
      relatedThreats.length ? "Threat intel matched" : "Manual review",
    ];

    return {
      mitreId,
      caseTags,
      relatedThreats,
    };
  };

  const handleIncidentQuickAction = async (incidentId, status) => {
    const result = await updateIncident(incidentId, { status });
    if (result) {
      setWorkflowNote(`Incident ${result.id} moved to ${status}.`);
    }
  };

  const totalIncidents = incidents.length;
  const totalThreats = threats.length;
  const totalLogs = logs.length;
  const totalUsers = users.length;

  const refreshDashboard = useEffectEvent(() => {
    void loadIncidents();
    void loadStats();
    void loadUsers();
    void loadThreats();
    void loadCases();
  });

  useEffect(() => {
    if (!auth?.token) return undefined;

    const timeoutId = window.setTimeout(refreshDashboard, 0);
    return () => window.clearTimeout(timeoutId);
  }, [auth.token]);

  useEffect(() => {
    if (!auth?.token) return;
    if (socketRef.current) return;

    const connection = io(API, {
      auth: { token: auth.token },
    });

    connection.on("connect", () => {
      console.log("Socket connected", connection.id);
    });

    connection.on("new_incident", (incident) => {
      setIncidents((current) => [incident, ...(current || [])].slice(0, 40));
    });

    connection.on("log_stream", (message) => {
      setLogs((current) => [{ timestamp: new Date().toISOString(), ...message }, ...(current || [])].slice(0, 50));
    });

    connection.on("incident_update", (incident) => {
      setIncidents((current) => current.map((inc) => (inc.id === incident.id ? incident : inc)));
    });

    socketRef.current = connection;

    return () => {
      connection.disconnect();
      if (socketRef.current === connection) {
        socketRef.current = null;
      }
    };
  }, [auth.token]);

  return (
    <div style={{ minHeight: "100vh", background: isViewer ? "#0f1419" : "#020617", color: "#e2e8f0", fontFamily: "Inter, system-ui, sans-serif" }}>
      <div
        style={{
          maxWidth: 1400,
          margin: "0 auto",
          padding: "24px 24px 40px",
        }}
      >
        <header
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 24,
          }}
        >
          <div>
            <div style={{ color: isViewer ? "#3b82f6" : "#22c55e", fontWeight: 800, fontSize: 18 }}>
              {isViewer ? "SOC Monitoring Dashboard" : "SOC Command Center"}
            </div>
            <h1 style={{ margin: "10px 0 2px", fontSize: 32 }}>
              {isViewer ? "Security Operations Monitoring" : "Security Operations Dashboard"}
            </h1>
            <div style={{ color: "#94a3b8", fontSize: 14 }}>
              Logged in as <strong>{auth.role || "analyst"}</strong>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              onClick={onLogout}
              style={{
                padding: "12px 18px",
                borderRadius: 12,
                border: "1px solid #334155",
                background: "#111827",
                color: "#e2e8f0",
                cursor: "pointer",
              }}
            >
              Logout
            </button>
          </div>
        </header>

        {isViewer && (
          <div
            style={{
              marginBottom: 20,
              padding: 16,
              background: "#1e40af",
              color: "#dbeafe",
              borderRadius: 12,
              textAlign: "center",
              fontSize: 16,
              fontWeight: 600,
            }}
          >
            👁️ Viewer Mode: Read-only monitoring access to security operations data.
          </div>
        )}
        <nav style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 28 }}>
          {availableTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                if (tab.id === "enterprise") loadEnterprise();
                if (tab.id === "assets") loadAssets();
                if (tab.id === "playbooks") loadPlaybookConsole();
                if (tab.id === "detections") loadDetections();
              }}
              style={{
                padding: "12px 18px",
                borderRadius: 999,
                border: activeTab === tab.id ? `1px solid ${isViewer ? "#3b82f6" : "#22c55e"}` : "1px solid #334155",
                background: activeTab === tab.id ? "#111827" : "#0f172a",
                color: activeTab === tab.id ? (isViewer ? "#3b82f6" : "#22c55e") : "#94a3b8",
                cursor: "pointer",
              }}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        {activeTab === "overview" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading operations overview...</div>}>
            <OperationsPanels panel="overview" incidents={incidents} cases={cases} range={overviewRange} onRangeChange={setOverviewRange} />
          </Suspense>
        )}

        {activeTab === "timeline" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading investigation workspace...</div>}>
            <OperationsPanels panel="timeline" incidents={incidents} users={users} selectedIncidentId={selectedIncidentId} onSelectIncident={(id) => setSelectedIncidentId(Number(id) || null)} />
          </Suspense>
        )}

        {activeTab === "assets" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading asset inventory...</div>}>
            <OperationsPanels panel="assets" assets={assets} incidents={incidents} query={assetQuery} onQueryChange={setAssetQuery} selectedAssetId={selectedAssetId} onSelectAsset={setSelectedAssetId} asset={assets.find((item) => String(item.id) === String(selectedAssetId))} draft={newAsset} onDraftChange={setNewAsset} onCreate={createAsset} canManage={canManageIncidents} message={assetMessage} />
          </Suspense>
        )}

        {activeTab === "hunt" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading threat hunt...</div>}>
            <OperationsPanels panel="hunt" query={huntQuery} onQueryChange={setHuntQuery} onSearch={runThreatHunt} results={huntResults} message={huntMessage} onOpenIncident={(id) => { setSelectedIncidentId(id); setActiveTab("timeline"); }} />
          </Suspense>
        )}

        {activeTab === "playbooks" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading playbook console...</div>}>
            <OperationsPanels panel="playbooks" incidents={incidents} selectedIncidentId={selectedPlaybookIncidentId} onSelectIncident={setSelectedPlaybookIncidentId} playbook={playbookChoice} onPlaybookChange={setPlaybookChoice} onRequest={requestPlaybookExecution} message={playbookMessage} executions={executions} isViewer={isViewer} isAdmin={auth?.role === "admin"} onApprove={approveExecution} onReject={rejectExecution} onRollback={rollbackExecution} />
          </Suspense>
        )}

        {activeTab === "detections" && (
          <Suspense fallback={<div style={{ color: "#94a3a8", padding: 16 }}>Loading detection controls...</div>}>
            <OperationsPanels panel="detections" rules={detectionRules} groups={alertGroups} draft={newRule} onDraftChange={setNewRule} onCreate={createDetectionRule} onToggle={toggleDetectionRule} onDelete={deleteDetectionRule} canManage={canManageIncidents} isAdmin={auth?.role === "admin"} dedupWindow={dedupWindowMinutes} onDedupChange={setDedupWindowMinutes} onSaveDedup={saveDedupWindow} testRuleId={ruleTestId} onTestRuleIdChange={setRuleTestId} testLog={ruleTestLog} onTestLogChange={setRuleTestLog} onTest={testDetectionRuleWithSample} message={ruleMessage} />
          </Suspense>
        )}

        {activeTab === "incidents" && (
          <div>
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 24 }}>
              <SummaryCard title="Critical Alerts" value={stats.Critical} color={COLORS.Critical} />
              <SummaryCard title="High Severity" value={stats.High} color={COLORS.High} />
              <SummaryCard title="Medium Alerts" value={stats.Medium} color={COLORS.Medium} />
              <SummaryCard title="Low Priority" value={stats.Low} color={COLORS.Low} />
            </div>

            <div style={{ display: "flex", gap: 24, flexWrap: "wrap", marginBottom: 24 }}>
              <div style={{ flex: 1, minWidth: 300, background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
                  <div>
                    <div style={{ color: "#94a3b8", fontSize: 14, marginBottom: 6 }}>Incident summary</div>
                    <div style={{ fontSize: 18, fontWeight: 700 }}>Live incident totals</div>
                  </div>
                </div>

                <div style={{ width: "100%", height: 220, marginBottom: 18 }}>
                  <Suspense fallback={<div style={{ color: "#94a3b8", padding: 16 }}>Loading chart...</div>}>
                    <IncidentSummaryChart stats={stats} color={isViewer ? "#3b82f6" : "#22c55e"} />
                  </Suspense>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 16, marginTop: 14 }}>
                  <div style={{ background: "#020617", padding: 18, borderRadius: 18, border: "1px solid #1e293b" }}>
                    <div style={{ color: "#94a3b8", marginBottom: 8 }}>Total incidents</div>
                    <div style={{ fontSize: 26, fontWeight: 700 }}>{totalIncidents}</div>
                  </div>
                  <div style={{ background: "#020617", padding: 18, borderRadius: 18, border: "1px solid #1e293b" }}>
                    <div style={{ color: "#94a3b8", marginBottom: 8 }}>Active analysts</div>
                    <div style={{ fontSize: 26, fontWeight: 700 }}>{totalUsers}</div>
                  </div>
                </div>
              </div>

              <div style={{ width: 320, background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", fontSize: 14, marginBottom: 18 }}>Threat & log overview</div>
                <div style={{ color: "#e2e8f0", fontSize: 30, fontWeight: 700, marginBottom: 8 }}>{totalThreats}</div>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Threat indicators loaded</div>
                <div style={{ marginTop: 18, color: "#94a3b8", fontSize: 13 }}>
                  Live logs received: {totalLogs}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, gap: 16, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 280, display: "flex", gap: 12, flexWrap: "wrap" }}>
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search incidents by keyword"
                  style={{
                    flex: 1,
                    minWidth: 220,
                    background: "#020617",
                    border: "1px solid #334155",
                    borderRadius: 14,
                    padding: 14,
                    color: "#e2e8f0",
                  }}
                />
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={{
                    minWidth: 130,
                    background: "#020617",
                    border: "1px solid #334155",
                    borderRadius: 14,
                    padding: 14,
                    color: "#e2e8f0",
                  }}
                >
                  <option value="all">All severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  style={{
                    minWidth: 140,
                    background: "#020617",
                    border: "1px solid #334155",
                    borderRadius: 14,
                    padding: 14,
                    color: "#e2e8f0",
                  }}
                >
                  <option value="all">All statuses</option>
                  <option value="open">Open</option>
                  <option value="triage">Triage</option>
                  <option value="investigating">Investigating</option>
                  <option value="escalated">Escalated</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
                <button
                  onClick={handleSearch}
                  style={{
                    padding: "14px 18px",
                    borderRadius: 14,
                    background: isViewer ? "#3b82f6" : "#22c55e",
                    border: "none",
                    color: "#020617",
                    cursor: "pointer",
                  }}
                >
                  Search
                </button>
              </div>
              <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                {(searchQuery || severityFilter !== "all" || statusFilter !== "all") && (
                  <button
                    onClick={() => {
                      setSearchQuery("");
                      setSeverityFilter("all");
                      setStatusFilter("all");
                      void loadIncidents();
                    }}
                    style={{
                      padding: "12px 16px",
                      borderRadius: 12,
                      border: "1px solid #334155",
                      background: "#111827",
                      color: "#e2e8f0",
                      cursor: "pointer",
                    }}
                  >
                    Clear filters
                  </button>
                )}
                <button
                  onClick={loadIncidents}
                  style={{
                    padding: "14px 18px",
                    borderRadius: 14,
                    border: "1px solid #334155",
                    background: "#111827",
                    color: "#94a3b8",
                    cursor: "pointer",
                  }}
                >
                  Refresh incidents
                </button>
              </div>
            </div>

            <div style={{ marginBottom: 12, color: "#94a3b8", fontSize: 14 }}>
              Showing {filteredIncidents.length} of {incidents.length} incidents
            </div>

            {selectedIncident && (
              <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b", marginBottom: 18 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                  <div>
                    <div style={{ color: "#94a3b8", fontSize: 13 }}>Selected incident</div>
                    <div style={{ fontSize: 22, fontWeight: 700 }}>{selectedIncident.title}</div>
                  </div>
                  <button
                    onClick={() => setSelectedIncidentId(null)}
                    style={{ padding: "10px 14px", borderRadius: 12, border: "1px solid #334155", background: "#111827", color: "#e2e8f0", cursor: "pointer" }}
                  >
                    Close details
                  </button>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 16 }}>
                  <div style={{ padding: 14, background: "#020617", borderRadius: 12 }}>
                    <div style={{ color: "#94a3b8", fontSize: 12 }}>Severity</div>
                    <div style={{ fontWeight: 700, color: COLORS[selectedIncident.severity] || "#94a3b8" }}>{selectedIncident.severity || "Unknown"}</div>
                  </div>
                  <div style={{ padding: 14, background: "#020617", borderRadius: 12 }}>
                    <div style={{ color: "#94a3b8", fontSize: 12 }}>Status</div>
                    <div style={{ fontWeight: 700 }}>{selectedIncident.status || "open"}</div>
                  </div>
                  <div style={{ padding: 14, background: "#020617", borderRadius: 12 }}>
                    <div style={{ color: "#94a3b8", fontSize: 12 }}>Owner</div>
                    <div style={{ fontWeight: 700 }}>{users.find((user) => user.id === selectedIncident.assigned_to)?.username || "Unassigned"}</div>
                  </div>
                  <div style={{ padding: 14, background: "#020617", borderRadius: 12 }}>
                    <div style={{ color: "#94a3b8", fontSize: 12 }}>MITRE</div>
                    <div style={{ fontWeight: 700 }}>{selectedIncident.mitre_attack_id || "T1078"}</div>
                  </div>
                </div>

                <div style={{ marginTop: 16, lineHeight: 1.7, color: "#e2e8f0", background: "#020617", borderRadius: 12, padding: 16 }}>
                  {selectedIncident.details || selectedIncident.description || selectedIncident.log || "No details provided."}
                </div>

                {selectedIncident.timeline?.length > 0 && (
                  <div style={{ marginTop: 18 }}>
                    <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12 }}>Timeline</div>
                    <div style={{ display: "grid", gap: 10 }}>
                      {[...selectedIncident.timeline].reverse().slice(0, 6).map((entry, index) => (
                        <div key={`${entry.at || entry.ts || index}-${index}`} style={{ background: "#020617", borderRadius: 10, padding: 12, border: "1px solid #1e293b" }}>
                          <div style={{ fontWeight: 700 }}>{entry.action?.replace(/_/g, " ") || "Event"}</div>
                          <div style={{ color: "#94a3b8", fontSize: 12, marginTop: 4 }}>
                            {entry.actor || entry.by || "system"} · {entry.at || entry.ts ? new Date(entry.at || entry.ts).toLocaleString() : "Time unavailable"}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
              {filteredIncidents.length ? (
                filteredIncidents.map((incident) => {
                  const assignedLabel = users.find((u) => u.id === incident.assigned_to)?.username || "Unassigned";
                  const enrichment = getIncidentEnrichment(incident);
                  return (
                    <div
                      key={incident.id}
                      style={{
                        background: "#020617",
                        padding: 18,
                        borderRadius: 18,
                        borderLeft: `4px solid ${COLORS[incident.severity] || "#64748b"}`,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                        <strong style={{ fontSize: 16 }}>{incident.title}</strong>
                        <span style={{ color: COLORS[incident.severity] || "#94a3b8" }}>{incident.severity}</span>
                      </div>
                      <div style={{ color: "#94a3b8", marginTop: 8, fontSize: 13 }}>{incident.time || incident.timestamp || "Unknown time"}</div>
                      <p style={{ marginTop: 12, color: "#e2e8f0", lineHeight: 1.6 }}>{incident.details || incident.description || incident.log || "No details provided."}</p>

                      <div style={{ marginTop: 12 }}>
                        <button
                          onClick={() => setSelectedIncidentId(incident.id)}
                          style={{ padding: "10px 12px", borderRadius: 10, border: "1px solid #334155", background: "#111827", color: "#e2e8f0", cursor: "pointer" }}
                        >
                          View details
                        </button>
                      </div>

                      <div style={{ marginTop: 12, padding: 12, borderRadius: 12, background: "#0f172a", border: "1px solid #1e293b" }}>
                        <div style={{ color: "#94a3b8", fontSize: 12, marginBottom: 6 }}>Alert enrichment</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                          <span style={{ display: "inline-block", padding: "6px 10px", borderRadius: 999, background: "#111827", color: "#93c5fd", fontSize: 12, fontWeight: 700 }}>
                            MITRE {enrichment.mitreId}
                          </span>
                          {enrichment.caseTags.map((tag) => (
                            <span key={tag} style={{ display: "inline-block", padding: "6px 10px", borderRadius: 999, background: "#0b1220", color: "#cbd5e1", fontSize: 12 }}>
                              {tag}
                            </span>
                          ))}
                        </div>
                        {enrichment.relatedThreats.length > 0 && (
                          <div style={{ color: "#cbd5e1", marginTop: 8, fontSize: 12 }}>
                            Related intel: {enrichment.relatedThreats.map((threat) => threat.indicator).join(", ")}
                          </div>
                        )}
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginTop: 14 }}>
                        <div style={{ color: "#94a3b8", fontSize: 13 }}><strong>Status:</strong> {incident.status || "open"}</div>
                        <div style={{ color: "#94a3b8", fontSize: 13 }}><strong>Assigned:</strong> {assignedLabel}</div>
                      </div>
                      <div style={{ color: incident.sla_breached ? "#f87171" : "#94a3b8", fontSize: 13, marginTop: 8 }}>
                        <strong>SLA:</strong> {incident.sla_due_at ? `Due ${new Date(incident.sla_due_at).toLocaleString()}` : "No SLA target"}
                        {incident.sla_breached ? " · Overdue" : ""}
                      </div>

                      {canManageIncidents && (
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16 }}>
                          {quickIncidentStatusOptions.map((option) => (
                            <button
                              key={option.value}
                              onClick={() => handleIncidentQuickAction(incident.id, option.value)}
                              disabled={isViewer || (incident.status || "open") === option.value}
                              style={{
                                padding: "8px 10px",
                                borderRadius: 10,
                                border: "1px solid #334155",
                                background: (incident.status || "open") === option.value ? "#1e293b" : "#111827",
                                color: "#e2e8f0",
                                cursor: isViewer ? "not-allowed" : "pointer",
                                fontSize: 12,
                              }}
                            >
                              {option.label}
                            </button>
                          ))}
                        </div>
                      )}

                      {canManageIncidents && (
                        <div style={{ marginTop: 16, display: "grid", gap: 12 }}>
                          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                            <select
                              value={incident.status || "open"}
                              onChange={(e) => updateIncident(incident.id, { status: e.target.value })}
                              style={{ flex: 1, padding: 12, borderRadius: 12, border: "1px solid #334155", background: "#020617", color: "#e2e8f0" }}
                            >
                              <option value="open">Open</option>
                              <option value="triage">Triage</option>
                              <option value="investigating">Investigating</option>
                              <option value="escalated">Escalated</option>
                              <option value="contained">Contained</option>
                              <option value="resolved">Resolved</option>
                              <option value="closed">Closed</option>
                            </select>
                            <select
                              value={incident.assigned_to || ""}
                              onChange={(e) => assignIncident(incident.id, e.target.value || null)}
                              style={{ flex: 1, padding: 12, borderRadius: 12, border: "1px solid #334155", background: "#020617", color: "#e2e8f0" }}
                            >
                              <option value="">Unassigned</option>
                              {users.filter((user) => ["admin", "analyst"].includes(user.role)).map((user) => (
                                <option key={user.id} value={user.id}>{user.username} ({user.role})</option>
                              ))}
                            </select>
                          </div>

                          <div style={{ display: "grid", gap: 10 }}>
                            <textarea
                              rows={4}
                              value={noteEdits[incident.id] ?? incident.notes ?? ""}
                              onChange={(e) => handleNoteChange(incident.id, e.target.value)}
                              placeholder="Case notes and analyst observations"
                              style={{ width: "100%", background: "#020617", border: "1px solid #334155", borderRadius: 14, padding: 14, color: "#e2e8f0" }}
                            />
                            <button
                              onClick={() => saveIncidentNote(incident.id)}
                              style={{ alignSelf: "flex-start", padding: "10px 16px", borderRadius: 14, border: "none", background: isViewer ? "#3b82f6" : "#22c55e", color: "#020617", cursor: "pointer" }}
                            >
                              Save notes
                            </button>
                          </div>
                        </div>
                      )}
                      {incident.timeline?.length > 0 && (
                        <details style={{ marginTop: 14, color: "#94a3b8", fontSize: 13 }}>
                          <summary style={{ cursor: "pointer" }}>Activity history ({incident.timeline.length})</summary>
                          <div style={{ display: "grid", gap: 8, marginTop: 10 }}>
                            {[...incident.timeline].reverse().slice(0, 8).map((entry, index) => (
                              <div key={`${entry.at}-${index}`} style={{ borderLeft: "2px solid #334155", paddingLeft: 10 }}>
                                <strong>{entry.action.replace(/_/g, " ")}</strong>
                                <div>{entry.actor} · {new Date(entry.at).toLocaleString()}</div>
                                {entry.action === "assigned" && <div>From {entry.details.from || "unassigned"} to {entry.details.to || "unassigned"}</div>}
                                {entry.action === "status_changed" && <div>{entry.details.from} → {entry.details.to}</div>}
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  );
                })
              ) : (
                <div style={{ color: "#94a3b8", padding: 14, borderRadius: 16, background: "#111827" }}>
                  No incidents available. Use search or refresh to load the latest data.
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "logs" && (
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 24 }}>
            <div style={{ background: "#0f172a", borderRadius: 20, padding: 24, border: "1px solid #1e293b" }}>
              <div style={{ marginBottom: 18, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ color: "#94a3b8", fontSize: 14 }}>Live log stream</div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>Monitoring events</div>
                </div>
                <div style={{ color: "#94a3b8" }}>Incoming feed</div>
              </div>
              <div style={{ maxHeight: 520, overflowY: "auto", fontFamily: "monospace" }}>
                {logs.length ? (
                  logs.map((log, index) => (
                    <div key={index} style={{ marginBottom: 14, borderBottom: "1px solid #1e293b", paddingBottom: 12 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: "#64748b", fontSize: 13 }}>{log.timestamp}</span>
                        <span style={{ color: COLORS[log.severity] || "#94a3b8", fontWeight: 700 }}>{log.severity || "INFO"}</span>
                      </div>
                      <div style={{ marginTop: 8, color: "#e2e8f0" }}>{log.message || log.title || "No message provided."}</div>
                    </div>
                  ))
                ) : (
                  <div style={{ color: "#94a3b8" }}>Waiting for log stream data...</div>
                )}
              </div>
            </div>

            <div style={{ display: "grid", gap: 18 }}>
              <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", marginBottom: 10, fontSize: 14 }}>Query Scan</div>
                <input
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="Enter host, IP, or asset"
                  style={{
                    width: "100%",
                    padding: 14,
                    background: "#020617",
                    border: "1px solid #334155",
                    borderRadius: 14,
                    color: "#e2e8f0",
                    marginBottom: 14,
                  }}
                />
                <button
                  onClick={runScan}
                  style={{
                    width: "100%",
                    padding: 14,
                    borderRadius: 14,
                    background: isViewer ? "#3b82f6" : "#22c55e",
                    border: "none",
                    color: "#020617",
                    cursor: "pointer",
                  }}
                >
                  Launch scan
                </button>
                {scanMessage && (
                  <div style={{ marginTop: 14, color: "#94a3b8", fontSize: 13 }}>{scanMessage}</div>
                )}
              </div>

              <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", marginBottom: 12, fontSize: 14 }}>Active analysts</div>
                {users.length ? (
                  users.map((user) => (
                    <div key={user.id} style={{ padding: "10px 0", borderBottom: "1px solid #1e293b" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span>{user.username}</span>
                        <span style={{ color: "#94a3b8", fontSize: 13 }}>{user.role}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div style={{ color: "#94a3b8" }}>No active analysts found.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "threats" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 240, background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", marginBottom: 8 }}>Threat feed</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>Live indicators</div>
              </div>
              <div style={{ flex: 1, minWidth: 240, background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", marginBottom: 8 }}>Threat categories</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{threats.length}</div>
              </div>
            </div>

            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 18 }}>
                <div>
                  <div style={{ color: "#94a3b8", fontSize: 14 }}>Threat intelligence</div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>Latest indicators</div>
                </div>
                <button
                  onClick={loadThreats}
                  style={{
                    padding: "10px 16px",
                    borderRadius: 12,
                    border: "1px solid #334155",
                    background: "#111827",
                    color: "#94a3b8",
                    cursor: "pointer",
                  }}
                >
                  Reload
                </button>
              </div>
              <div style={{ display: "grid", gap: 12, marginBottom: 16 }}>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <input
                    value={tiQuery}
                    onChange={(e) => setTiQuery(e.target.value)}
                    placeholder="Lookup IP in AbuseIPDB"
                    style={{
                      flex: 1,
                      padding: 14,
                      borderRadius: 14,
                      background: "#020617",
                      border: "1px solid #334155",
                      color: "#e2e8f0",
                    }}
                  />
                  <button
                    onClick={lookupAbuseIPDB}
                    style={{
                      padding: "14px 18px",
                      borderRadius: 14,
                      border: "none",
                      background: isViewer ? "#3b82f6" : "#22c55e",
                      color: "#020617",
                      cursor: "pointer",
                    }}
                  >
                    AbuseIPDB lookup
                  </button>
                </div>
                {tiStatus && <div style={{ color: "#94a3b8", fontSize: 13 }}>{tiStatus}</div>}
                {tiResult && (
                  <div style={{ background: "#020617", border: "1px solid #334155", borderRadius: 16, padding: 16 }}>
                    <div style={{ color: "#94a3b8", marginBottom: 10, fontSize: 13 }}>Threat intelligence lookup result</div>
                    <div style={{ display: "grid", gap: 8, color: "#e2e8f0", fontSize: 14 }}>
                      <div><strong>IP:</strong> {tiResult.ip}</div>
                      <div><strong>Source:</strong> {tiResult.source}</div>
                      <div><strong>Score:</strong> {tiResult.abuse_confidence_score ?? "n/a"}</div>
                      <div><strong>Country:</strong> {tiResult.country || "n/a"}</div>
                      <div><strong>Reports:</strong> {tiResult.report_count ?? "n/a"}</div>
                      {tiResult.message && <div style={{ color: "#94a3b8" }}>{tiResult.message}</div>}
                    </div>
                  </div>
                )}
              </div>
              <div style={{ maxHeight: 520, overflowY: "auto" }}>
                {threats.length ? (
                  threats.map((threat) => (
                    <div key={threat.id} style={{ padding: "14px 0", borderBottom: "1px solid #1e293b" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 16 }}>
                        <div>
                          <strong>{threat.indicator}</strong>
                          <div style={{ color: "#94a3b8", fontSize: 13 }}>{threat.type}</div>
                        </div>
                        <span style={{ color: COLORS[threat.severity] || "#94a3b8", fontWeight: 700 }}>{threat.severity}</span>
                      </div>
                      <div style={{ color: "#64748b", marginTop: 8, fontSize: 13 }}>{threat.source || "Unknown source"}</div>
                    </div>
                  ))
                ) : (
                  <div style={{ color: "#94a3b8" }}>No threat indicators loaded yet.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "soar" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
              {[
                { title: "Containment", description: "Block suspicious IPs and isolate affected hosts.", action: "Containment workflow", color: "#ef4444" },
                { title: "Investigation", description: "Collect evidence and enrich with threat intel.", action: "Investigation workflow", color: "#60a5fa" },
                { title: "Escalation", description: "Escalate critical incidents to operations.", action: "Escalation workflow", color: "#f59e0b" },
              ].map((workflow) => (
                <div key={workflow.title} style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                  <div style={{ color: "#94a3b8", marginBottom: 10 }}>{workflow.title}</div>
                  <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>{workflow.description}</div>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 12 }}>
                    <button
                      onClick={() => launchWorkflow(workflow.action, true)}
                      disabled={isViewer}
                      style={{ padding: "12px 16px", borderRadius: 14, border: "1px solid #334155", background: "#111827", color: "#e2e8f0", cursor: isViewer ? "not-allowed" : "pointer" }}
                    >
                      Dry run
                    </button>
                    <button
                      onClick={() => launchWorkflow(workflow.action)}
                      disabled={isViewer}
                      style={{
                        padding: "12px 16px",
                        borderRadius: 14,
                        border: "none",
                        background: isViewer ? "#334155" : workflow.color,
                        color: "#020617",
                        cursor: isViewer ? "not-allowed" : "pointer",
                      }}
                    >
                      Request approval
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ color: "#94a3b8", fontSize: 14, marginBottom: 10 }}>Automation status</div>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Current workflow</div>
              <div style={{ color: "#e2e8f0", lineHeight: 1.7 }}>{workflowNote}</div>
            </div>
          </div>
        )}

        {activeTab === "users" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ color: "#94a3b8", marginBottom: 18, fontSize: 14 }}>Create new user</div>
              <div style={{ display: "grid", gap: 14 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
                  <input
                    type="text"
                    placeholder="Username"
                    value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                    style={{
                      padding: 14,
                      borderRadius: 14,
                      background: "#020617",
                      border: "1px solid #334155",
                      color: "#e2e8f0",
                    }}
                  />
                  <input
                    type="password"
                    placeholder="Password"
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    style={{
                      padding: 14,
                      borderRadius: 14,
                      background: "#020617",
                      border: "1px solid #334155",
                      color: "#e2e8f0",
                    }}
                  />
                  <select
                    value={newUser.role}
                    onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                    style={{
                      padding: 14,
                      borderRadius: 14,
                      background: "#020617",
                      border: "1px solid #334155",
                      color: "#e2e8f0",
                    }}
                  >
                    <option value="viewer">Viewer</option>
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                <button
                  onClick={createUser}
                  style={{
                    padding: "14px 18px",
                    borderRadius: 14,
                    background: "#22c55e",
                    border: "none",
                    color: "#020617",
                    cursor: "pointer",
                    alignSelf: "flex-start",
                  }}
                >
                  Create User
                </button>
              </div>
              {userMessage && (
                <div style={{ marginTop: 14, color: userMessage.includes("success") ? "#22c55e" : "#ef4444", fontSize: 14 }}>
                  {userMessage}
                </div>
              )}
            </div>

            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
                <div>
                  <div style={{ color: "#94a3b8", fontSize: 14 }}>User management</div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>All users ({users.length})</div>
                </div>
                <button
                  onClick={loadUsers}
                  style={{
                    padding: "10px 16px",
                    borderRadius: 12,
                    border: "1px solid #334155",
                    background: "#111827",
                    color: "#94a3b8",
                    cursor: "pointer",
                  }}
                >
                  Refresh
                </button>
              </div>
              <div style={{ display: "grid", gap: 12 }}>
                {users.length ? (
                  users.map((user) => (
                    <div
                      key={user.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr auto auto",
                        gap: 12,
                        alignItems: "center",
                        padding: 16,
                        background: "#020617",
                        borderRadius: 12,
                        border: "1px solid #1e293b",
                      }}
                    >
                      <div>
                        <div style={{ color: "#e2e8f0", fontWeight: 600 }}>{user.username}</div>
                        <div style={{ color: "#94a3b8", fontSize: 13 }}>
                          Role: {user.role}
                        </div>
                      </div>
                      <button
                        onClick={() => setEditingUser(user)}
                        style={{
                          padding: "8px 12px",
                          borderRadius: 8,
                          border: "1px solid #334155",
                          background: "#111827",
                          color: "#94a3b8",
                          cursor: "pointer",
                        }}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => deleteUser(user.id)}
                        style={{
                          padding: "8px 12px",
                          borderRadius: 8,
                          border: "1px solid #ef4444",
                          background: "#7f1d1d",
                          color: "#fee2e2",
                          cursor: "pointer",
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  ))
                ) : (
                  <div style={{ color: "#94a3b8" }}>No users found.</div>
                )}
              </div>
            </div>

            {editingUser && (
              <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", marginBottom: 18, fontSize: 14 }}>Edit user: {editingUser.username}</div>
                <div style={{ display: "grid", gap: 14 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
                    <input
                      type="text"
                      placeholder="New username"
                      value={editingUser.username}
                      onChange={(e) => setEditingUser({ ...editingUser, username: e.target.value })}
                      style={{
                        padding: 14,
                        borderRadius: 14,
                        background: "#020617",
                        border: "1px solid #334155",
                        color: "#e2e8f0",
                      }}
                    />
                    <input
                      type="password"
                      placeholder="New password (leave empty to keep current)"
                      value={editingUser.password || ""}
                      onChange={(e) => setEditingUser({ ...editingUser, password: e.target.value })}
                      style={{
                        padding: 14,
                        borderRadius: 14,
                        background: "#020617",
                        border: "1px solid #334155",
                        color: "#e2e8f0",
                      }}
                    />
                    <select
                      value={editingUser.role}
                      onChange={(e) => setEditingUser({ ...editingUser, role: e.target.value })}
                      style={{
                        padding: 14,
                        borderRadius: 14,
                        background: "#020617",
                        border: "1px solid #334155",
                        color: "#e2e8f0",
                      }}
                    >
                      <option value="viewer">Viewer</option>
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div style={{ display: "flex", gap: 12 }}>
                    <button
                      onClick={() => updateUser(editingUser.id, {
                        username: editingUser.username,
                        password: editingUser.password || undefined,
                        role: editingUser.role
                      })}
                      style={{
                        padding: "14px 18px",
                        borderRadius: 14,
                        background: "#22c55e",
                        border: "none",
                        color: "#020617",
                        cursor: "pointer",
                      }}
                    >
                      Update User
                    </button>
                    <button
                      onClick={() => setEditingUser(null)}
                      style={{
                        padding: "14px 18px",
                        borderRadius: 14,
                        border: "1px solid #334155",
                        background: "#111827",
                        color: "#94a3b8",
                        cursor: "pointer",
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "enterprise" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              <div>
                <div style={{ color: "#94a3b8", fontSize: 14 }}>Enterprise controls</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>Security operations</div>
              </div>
              <button onClick={loadEnterprise} style={{ padding: "10px 16px", borderRadius: 8, border: "1px solid #334155", background: "#111827", color: "#e2e8f0", cursor: "pointer" }}>Refresh</button>
            </div>

            {enterpriseMessage && <div style={{ padding: 14, background: "#111827", border: "1px solid #334155", color: "#cbd5e1", borderRadius: 8 }}>{enterpriseMessage}</div>}

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 18 }}>
              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Platform health</div>
                <div style={{ marginTop: 10, fontSize: 18, fontWeight: 700, color: operationsHealth?.status === "healthy" ? "#22c55e" : "#f59e0b" }}>{operationsHealth?.status || "Not loaded"}</div>
                <div style={{ marginTop: 12, color: "#94a3b8", fontSize: 13 }}>Database: {operationsHealth?.database || "n/a"}</div>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Incidents: {operationsHealth?.incidents ?? "n/a"} · Cases: {operationsHealth?.cases ?? "n/a"}</div>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Ingestion failed: {operationsHealth?.ingestion?.failed ?? "n/a"} · queued: {operationsHealth?.ingestion?.queued ?? "n/a"}</div>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Backup storage: {operationsHealth?.backup_storage || "n/a"}</div>
              </div>
              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Administrator MFA</div>
                <div style={{ margin: "10px 0", color: "#e2e8f0" }}>{securityPolicy.require_admin_mfa ? "Required for administrators" : "Optional for administrators"}</div>
                <label style={{ display: "flex", alignItems: "center", gap: 10, color: "#cbd5e1", fontSize: 14 }}>
                  <input type="checkbox" checked={securityPolicy.require_admin_mfa} onChange={(event) => saveSecurityPolicy(event.target.checked)} />
                  Require MFA for administrators
                </label>
              </div>
              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>SOAR approvals</div>
                <div style={{ marginTop: 10, fontSize: 26, fontWeight: 700 }}>{executions.filter((execution) => execution.status === "pending_approval").length}</div>
                <div style={{ color: "#94a3b8", fontSize: 13 }}>Executions awaiting an administrator</div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 18 }}>
              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ fontWeight: 700, marginBottom: 8 }}>Windows Sysmon connector</div>
                <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12 }}>
                  Create a key for a Sysmon JSON event source. The key is shown only once.
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <input value={newSysmonSourceName} onChange={(event) => setNewSysmonSourceName(event.target.value)} placeholder="Source name (e.g. workstation-01)" style={{ flex: 1, minWidth: 0, padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <button onClick={createSysmonSource} style={{ padding: "10px 12px", background: "#22c55e", color: "#020617", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 700 }}>Create</button>
                </div>
                {newSysmonApiKey && (
                  <div style={{ marginTop: 12, padding: 12, background: "#020617", borderRadius: 6, overflowWrap: "anywhere" }}>
                    <div style={{ color: "#fbbf24", fontSize: 12, marginBottom: 6 }}>Copy this key into your collector now; it cannot be retrieved later.</div>
                    <code>{newSysmonApiKey}</code>
                    <button onClick={() => {
                      if (!navigator.clipboard?.writeText) {
                        setEnterpriseMessage("Clipboard access is unavailable; select and copy the API key manually.");
                        return;
                      }
                      navigator.clipboard.writeText(newSysmonApiKey).then(
                        () => setEnterpriseMessage("Sysmon API key copied."),
                        () => setEnterpriseMessage("Could not copy the API key; select and copy it manually.")
                      );
                    }} style={{ display: "block", marginTop: 8, padding: "6px 10px", background: "#111827", color: "#e2e8f0", border: "1px solid #334155", borderRadius: 6, cursor: "pointer" }}>Copy key</button>
                  </div>
                )}
                <div style={{ marginTop: 12, color: "#94a3b8", fontSize: 12 }}>
                  Send JSON event objects to <code>{API}/api/ingest</code> with the <code>X-API-Key</code> header.
                </div>
                <div style={{ marginTop: 10, color: "#94a3b8", fontSize: 12 }}>
                  Active Windows event sources: {logSources.filter((source) => source.source_type === "windows_event" && source.enabled).length}
                </div>
                <div style={{ display: "grid", gap: 8, maxHeight: 140, overflowY: "auto", marginTop: 8 }}>
                  {logSources.filter((source) => source.source_type === "windows_event").map((source) => (
                    <div key={source.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, padding: 8, background: "#020617", borderRadius: 6 }}>
                      <div>
                        <strong style={{ fontSize: 13 }}>{source.name}</strong>
                        <div style={{ color: "#94a3b8", fontSize: 11 }}>Last event: {source.last_seen ? new Date(source.last_seen).toLocaleString() : "none"}</div>
                      </div>
                      {source.enabled && <button onClick={() => rotateSysmonKey(source.id)} style={{ padding: "6px 8px", background: "#111827", color: "#e2e8f0", border: "1px solid #334155", borderRadius: 6, cursor: "pointer" }}>Rotate key</button>}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ fontWeight: 700, marginBottom: 8 }}>Alert deduplication</div>
                <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12 }}>
                  Suppress identical open alerts received within the selected time window. Set to 0 to disable.
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <input type="number" min="0" max="1440" value={dedupWindowMinutes} onChange={(event) => setDedupWindowMinutes(event.target.value)} aria-label="Deduplication window in minutes" style={{ width: 110, padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <span style={{ alignSelf: "center", color: "#94a3b8" }}>minutes</span>
                  <button onClick={saveDedupWindow} style={{ marginLeft: "auto", padding: "10px 12px", background: "#22c55e", color: "#020617", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 700 }}>Save</button>
                </div>
                <div style={{ display: "grid", gap: 8, maxHeight: 180, overflowY: "auto", marginTop: 14 }}>
                  {alertGroups.slice(0, 10).map((group) => (
                    <div key={group.id} style={{ padding: 10, background: "#020617", borderRadius: 6 }}>
                      <strong>{group.title}</strong>
                      <div style={{ color: "#94a3b8", fontSize: 12 }}>
                        {group.incident_count} events · {group.suppressed_count} suppressed · {group.severity}
                      </div>
                    </div>
                  ))}
                  {!alertGroups.length && <div style={{ color: "#94a3b8", fontSize: 13 }}>No alert groups yet.</div>}
                </div>
              </div>

              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ fontWeight: 700, marginBottom: 8 }}>Database backups</div>
                <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12 }}>
                  Create a consistent SQLite snapshot stored in the backend backups directory.
                </div>
                <button onClick={createDatabaseBackup} style={{ padding: "10px 12px", background: "#22c55e", color: "#020617", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 700 }}>Create backup</button>
                <div style={{ display: "grid", gap: 8, maxHeight: 180, overflowY: "auto", marginTop: 14 }}>
                  {backups.map((backup) => (
                    <div key={backup.filename} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, padding: 10, background: "#020617", borderRadius: 6 }}>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ overflowWrap: "anywhere", fontSize: 12 }}>{backup.filename}</div>
                        <div style={{ color: "#94a3b8", fontSize: 11 }}>{Math.ceil(backup.size_bytes / 1024)} KB</div>
                      </div>
                      <button onClick={() => downloadDatabaseBackup(backup.filename)} style={{ padding: "6px 8px", background: "#111827", color: "#e2e8f0", border: "1px solid #334155", borderRadius: 6, cursor: "pointer" }}>Download</button>
                    </div>
                  ))}
                  {!backups.length && <div style={{ color: "#94a3b8", fontSize: 13 }}>No local backups yet.</div>}
                </div>
              </div>
            </div>

            <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
              <div style={{ fontWeight: 700 }}>Anomaly model benchmark</div>
              <div style={{ color: "#fbbf24", fontSize: 13, marginTop: 6 }}>
                Synthetic labeled examples only; these results are not production accuracy estimates.
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginTop: 14 }}>
                {Object.entries(mlEvaluation?.models || {}).map(([name, metrics]) => (
                  <div key={name} style={{ background: "#020617", borderRadius: 6, padding: 12 }}>
                    <strong>{name}</strong>
                    <div style={{ color: "#94a3b8", fontSize: 13, marginTop: 6 }}>
                      Accuracy {Math.round(metrics.accuracy * 100)}% · Precision {Math.round(metrics.precision * 100)}% · Recall {Math.round(metrics.recall * 100)}% · F1 {Math.round(metrics.f1 * 100)}%
                    </div>
                    <div style={{ color: "#64748b", fontSize: 12 }}>{metrics.training_samples} train · {metrics.evaluation_samples} evaluation</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 18 }}>
              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ fontWeight: 700, marginBottom: 16 }}>Detection rules</div>
                <div style={{ display: "grid", gap: 10 }}>
                  <input value={newRule.name} onChange={(event) => setNewRule({ ...newRule, name: event.target.value })} placeholder="Rule name" style={{ padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <input value={newRule.pattern} onChange={(event) => setNewRule({ ...newRule, pattern: event.target.value })} placeholder="Match pattern" style={{ padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    <select value={newRule.severity} onChange={(event) => setNewRule({ ...newRule, severity: event.target.value })} style={{ padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }}><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select>
                    <input value={newRule.mitre_attack_id} onChange={(event) => setNewRule({ ...newRule, mitre_attack_id: event.target.value })} placeholder="MITRE ID" style={{ padding: 10, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  </div>
                  <button onClick={createDetectionRule} style={{ padding: 10, background: "#22c55e", color: "#020617", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 700 }}>Create rule</button>
                </div>
                <div style={{ display: "grid", gap: 8, marginTop: 18, maxHeight: 240, overflowY: "auto" }}>
                  {detectionRules.map((rule) => (
                    <div key={rule.id} style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto", alignItems: "center", gap: 8, padding: 10, background: "#020617", borderRadius: 6 }}>
                      <div><strong>{rule.name}</strong><div style={{ color: "#94a3b8", fontSize: 12 }}>{rule.severity} · {rule.mitre_attack_id || "Unmapped"} · {rule.enabled ? "Enabled" : "Disabled"}</div></div>
                      <button onClick={() => testDetectionRule(rule)} style={{ border: "1px solid #334155", background: "#111827", color: "#cbd5e1", borderRadius: 6, padding: "6px 8px", cursor: "pointer" }}>Test</button>
                      <button onClick={() => toggleDetectionRule(rule)} style={{ border: "1px solid #334155", background: "#111827", color: "#cbd5e1", borderRadius: 6, padding: "6px 8px", cursor: "pointer" }}>{rule.enabled ? "Disable" : "Enable"}</button>
                      <button onClick={() => deleteDetectionRule(rule.id)} style={{ border: "none", background: "transparent", color: "#f87171", cursor: "pointer" }}>Delete</button>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: "#0f172a", borderRadius: 8, padding: 20, border: "1px solid #1e293b" }}>
                <div style={{ fontWeight: 700, marginBottom: 16 }}>Approvals and audit trail</div>
                <div style={{ display: "grid", gap: 8, marginBottom: 18 }}>
                  {executions.filter((execution) => execution.status === "pending_approval").map((execution) => <div key={execution.id} style={{ display: "grid", gridTemplateColumns: "1fr auto auto", alignItems: "center", gap: 10, padding: 10, background: "#020617", borderRadius: 6 }}><div><strong>{execution.playbook}</strong><div style={{ color: "#94a3b8", fontSize: 12 }}>Incident #{execution.incident_id} · {execution.initiated_by}</div><div style={{ color: "#94a3b8", fontSize: 12 }}>Actions: {(execution.actions || []).join(", ")}</div></div><button onClick={() => approveExecution(execution.id)} style={{ border: "none", background: "#22c55e", color: "#020617", borderRadius: 6, padding: "6px 10px", cursor: "pointer" }}>Approve</button><button onClick={() => rejectExecution(execution.id)} style={{ border: "1px solid #7f1d1d", background: "#450a0a", color: "#fecaca", borderRadius: 6, padding: "6px 10px", cursor: "pointer" }}>Reject</button></div>)}
                  {!executions.some((execution) => execution.status === "pending_approval") && <div style={{ color: "#94a3b8", fontSize: 13 }}>No approvals are pending.</div>}
                </div>
                <div style={{ display: "grid", gap: 8, maxHeight: 200, overflowY: "auto", marginBottom: 18 }}>
                  {executions.filter((execution) => ["completed", "rollback_required", "rejected", "dry_run"].includes(execution.status)).slice(0, 10).map((execution) => (
                    <div key={execution.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, padding: 10, background: "#020617", borderRadius: 6 }}>
                      <div>
                        <strong>{execution.playbook}</strong>
                        <div style={{ color: "#94a3b8", fontSize: 12 }}>Incident #{execution.incident_id} · {execution.status.replace(/_/g, " ")}</div>
                      </div>
                      {execution.status === "completed" && (
                        <button onClick={() => rollbackExecution(execution.id)} style={{ border: "1px solid #f59e0b", background: "#451a03", color: "#fde68a", borderRadius: 6, padding: "6px 10px", cursor: "pointer" }}>Record rollback</button>
                      )}
                    </div>
                  ))}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8, marginBottom: 10 }}>
                  <input value={auditActorFilter} onChange={(event) => setAuditActorFilter(event.target.value)} placeholder="Filter by actor" style={{ padding: 8, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <input value={auditActionFilter} onChange={(event) => setAuditActionFilter(event.target.value)} placeholder="Filter by exact action" style={{ padding: 8, background: "#020617", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6 }} />
                  <button onClick={loadEnterprise} style={{ padding: 8, background: "#111827", border: "1px solid #334155", color: "#e2e8f0", borderRadius: 6, cursor: "pointer" }}>Filter audit trail</button>
                </div>
                <div style={{ display: "grid", gap: 8, maxHeight: 240, overflowY: "auto" }}>
                  {auditLogs.map((entry) => <div key={entry.id} style={{ padding: 10, background: "#020617", borderRadius: 6 }}><strong style={{ fontSize: 13 }}>{entry.action}</strong><div style={{ color: "#94a3b8", fontSize: 12 }}>{entry.actor} · {entry.resource} · {new Date(entry.created_at).toLocaleString()}</div></div>)}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "settings" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ color: "#94a3b8", marginBottom: 10 }}>Account & session</div>
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", color: "#e2e8f0" }}>
                  <span>Signed in as</span>
                  <strong>{auth.role || "analyst"}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8" }}>
                  <span>API host</span>
                  <span>{API}</span>
                </div>
              </div>
            </div>

            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ color: "#94a3b8", marginBottom: 10 }}>Support</div>
              <div style={{ color: "#e2e8f0", lineHeight: 1.7 }}>
                Update backend configuration, verify tokens, or contact your SOC administrator for additional access.
              </div>
            </div>
          </div>
        )}

        {activeTab === "cases" && (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, border: "1px solid #1e293b" }}>
              <div style={{ color: "#94a3b8", marginBottom: 12 }}>Case management</div>
              <div style={{ display: "grid", gap: 14 }}>
                <input
                  value={newCase.title}
                  onChange={(event) => setNewCase({ ...newCase, title: event.target.value })}
                  placeholder="Case title"
                  style={{ padding: 14, borderRadius: 14, background: "#020617", border: "1px solid #334155", color: "#e2e8f0" }}
                />
                <textarea
                  value={newCase.description}
                  onChange={(event) => setNewCase({ ...newCase, description: event.target.value })}
                  placeholder="Summary of investigation"
                  rows={4}
                  style={{ padding: 14, borderRadius: 14, background: "#020617", border: "1px solid #334155", color: "#e2e8f0" }}
                />
                <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 12 }}>
                  <select
                    value={newCase.severity}
                    onChange={(event) => setNewCase({ ...newCase, severity: event.target.value })}
                    style={{ padding: 14, borderRadius: 14, background: "#020617", border: "1px solid #334155", color: "#e2e8f0" }}
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                  <button
                    onClick={createCase}
                    style={{ padding: "14px 18px", borderRadius: 14, border: "none", background: "#22c55e", color: "#020617", cursor: "pointer" }}
                  >
                    Create case
                  </button>
                </div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
              {cases.length ? cases.map((item) => (
                <div key={item.id} style={{ background: "#020617", borderRadius: 18, padding: 18, borderLeft: "4px solid #22c55e" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                    <strong>{item.title}</strong>
                    <span style={{ color: "#94a3b8" }}>{item.severity}</span>
                  </div>
                  <div style={{ color: "#94a3b8", fontSize: 13, marginTop: 8 }}>{item.status || "open"}</div>
                  <p style={{ color: "#e2e8f0", lineHeight: 1.6, marginTop: 12 }}>{item.description || "No summary provided."}</p>

                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                    {['open', 'investigating', 'escalated', 'resolved', 'closed'].map((status) => (
                      <button
                        key={status}
                        onClick={() => updateCaseStatus(item.id, status)}
                        disabled={(item.status || 'open') === status}
                        style={{
                          padding: "8px 10px",
                          borderRadius: 10,
                          border: "1px solid #334155",
                          background: (item.status || 'open') === status ? '#1e293b' : '#111827',
                          color: '#e2e8f0',
                          cursor: 'pointer',
                          fontSize: 12,
                        }}
                      >
                        {status}
                      </button>
                    ))}
                  </div>

                  <div style={{ marginTop: 16 }}>
                    <textarea
                      rows={3}
                      value={caseNote}
                      onChange={(event) => setCaseNote(event.target.value)}
                      placeholder="Add a case note"
                      style={{ width: "100%", background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 12, color: "#e2e8f0" }}
                    />
                    <div style={{ display: "flex", gap: 10, marginTop: 10 }}>
                      <button onClick={() => addCaseNote(item.id)} style={{ padding: "10px 14px", borderRadius: 12, border: "none", background: "#22c55e", color: "#020617", cursor: "pointer" }}>Add note</button>
                      <button onClick={() => deleteCase(item.id)} style={{ padding: "10px 14px", borderRadius: 12, border: "1px solid #7f1d1d", background: "#450a0a", color: "#fecaca", cursor: "pointer" }}>Delete</button>
                    </div>
                  </div>
                </div>
              )) : (
                <div style={{ color: "#94a3b8", padding: 14, borderRadius: 16, background: "#111827" }}>No cases created yet.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
