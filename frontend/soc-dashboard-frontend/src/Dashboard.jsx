import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";
const COLORS = {
  Critical: "#ef4444",
  High: "#f59e0b",
  Medium: "#60a5fa",
  Low: "#22c55e",
};

const tabs = [
  { id: "incidents", label: "Incidents" },
  { id: "logs", label: "Live Logs" },
  { id: "threats", label: "Threat Intelligence" },
  { id: "soar", label: "SOAR & Automation" },
  { id: "users", label: "User Management", adminOnly: true },
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
  const [activeTab, setActiveTab] = useState("incidents");
  const [incidents, setIncidents] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ Critical: 0, High: 0, Medium: 0, Low: 0 });
  const [trends, setTrends] = useState([]);
  const [users, setUsers] = useState([]);
  const [threats, setThreats] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [scanTarget, setScanTarget] = useState("");
  const [scanMessage, setScanMessage] = useState("");
  const [workflowNote, setWorkflowNote] = useState("Select a workflow to get started.");
  const [noteEdits, setNoteEdits] = useState({});
  const [tiQuery, setTiQuery] = useState("");
  const [tiResult, setTiResult] = useState(null);
  const [tiStatus, setTiStatus] = useState("");
  const [authError, setAuthError] = useState("");
  const [socket, setSocket] = useState(null);  const [newUser, setNewUser] = useState({ username: "", password: "", role: "analyst" });
  const [editingUser, setEditingUser] = useState(null);
  const [userMessage, setUserMessage] = useState("");  const canManageIncidents = ["admin", "analyst"].includes(auth?.role);
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

  const loadTrends = async () => {
    const response = await fetchWithAuth("/api/trends");
    if (!response) return;
    const data = await response.json();
    setTrends(data);
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
    } catch (error) {
      setScanMessage("Failed to launch scan. Check backend connectivity.");
    }
  };

  const triggerPlaybook = async (playbook) => {
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
      body: JSON.stringify({ incident_id: incidentId, playbook }),
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

  const launchWorkflow = (workflow) => {
    triggerPlaybook(workflow);
  };

  const createUser = async () => {
    if (!newUser.username || !newUser.password) {
      setUserMessage("Username and password are required.");
      return;
    }

    try {
      const response = await fetchWithAuth("/api/users", {
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
    } catch (error) {
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
    } catch (error) {
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
    } catch (error) {
      setUserMessage("Failed to delete user.");
    }
  };

  const totalIncidents = incidents.length;
  const totalThreats = threats.length;
  const totalLogs = logs.length;
  const totalUsers = users.length;

  useEffect(() => {
    if (!auth?.token) {
      onLogout();
      return;
    }

    loadIncidents();
    loadStats();
    loadTrends();
    loadUsers();
    loadThreats();
  }, [auth.token]);

  useEffect(() => {
    if (!auth?.token) return;
    if (socket) return;

    const connection = io(API, {
      transports: ["websocket"],
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

    setSocket(connection);

    return () => {
      connection.disconnect();
      setSocket(null);
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

        {authError && (
          <div
            style={{
              marginBottom: 20,
              padding: 16,
              background: "#7f1d1d",
              color: "#fee2e2",
              borderRadius: 16,
            }}
          >
            {authError}
          </div>
        )}

        <nav style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 28 }}>
          {availableTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
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
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={["Critical", "High", "Medium", "Low"].map((name) => ({ name, count: stats[name] || 0 }))}>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                      <XAxis dataKey="name" tick={{ fill: '#94a3b8' }} />
                      <YAxis tick={{ fill: '#94a3b8' }} />
                      <Tooltip cursor={{ fill: '#0f172a' }} />
                      <Bar dataKey="count" fill={isViewer ? "#3b82f6" : "#22c55e"} radius={[8, 8, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
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
              <div style={{ flex: 1, minWidth: 280, display: "flex", gap: 12 }}>
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search incidents by keyword"
                  style={{
                    width: "100%",
                    background: "#020617",
                    border: "1px solid #334155",
                    borderRadius: 14,
                    padding: 14,
                    color: "#e2e8f0",
                  }}
                />
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

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
              {incidents.length ? (
                incidents.map((incident) => {
                  const assignedLabel = users.find((u) => u.id === incident.assigned_to)?.username || "Unassigned";
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

                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginTop: 14 }}>
                        <div style={{ color: "#94a3b8", fontSize: 13 }}><strong>Status:</strong> {incident.status || "open"}</div>
                        <div style={{ color: "#94a3b8", fontSize: 13 }}><strong>Assigned:</strong> {assignedLabel}</div>
                      </div>

                      {canManageIncidents && (
                        <div style={{ marginTop: 16, display: "grid", gap: 12 }}>
                          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                            <select
                              value={incident.status || "open"}
                              onChange={(e) => updateIncident(incident.id, { status: e.target.value })}
                              style={{ flex: 1, padding: 12, borderRadius: 12, border: "1px solid #334155", background: "#020617", color: "#e2e8f0" }}
                            >
                              <option value="open">Open</option>
                              <option value="investigating">Investigating</option>
                              <option value="resolved">Resolved</option>
                              <option value="closed">Closed</option>
                            </select>
                            <select
                              value={incident.assigned_to || ""}
                              onChange={(e) => assignIncident(incident.id, e.target.value || null)}
                              style={{ flex: 1, padding: 12, borderRadius: 12, border: "1px solid #334155", background: "#020617", color: "#e2e8f0" }}
                            >
                              <option value="">Unassigned</option>
                              {users.map((user) => (
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
                  <button
                    onClick={() => launchWorkflow(workflow.action)}
                    disabled={isViewer}
                    style={{
                      marginTop: 12,
                      padding: "12px 16px",
                      borderRadius: 14,
                      border: "none",
                      background: isViewer ? "#334155" : workflow.color,
                      color: "#020617",
                      cursor: isViewer ? "not-allowed" : "pointer",
                    }}
                  >
                    Run {workflow.title}
                  </button>
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
      </div>
    </div>
  );
}
