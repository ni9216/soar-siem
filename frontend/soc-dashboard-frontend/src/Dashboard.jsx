import { useEffect, useState } from "react";

import { io } from "socket.io-client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Legend,
  BarChart,
  Bar,
  AreaChart,
  Area,
  ComposedChart,
} from "recharts";

const API = "http://localhost:5000";

const socket = io(API);

const COLORS = {
  Critical: "#a855f7",
  High: "#ef4444",
  Medium: "#f59e0b",
  Low: "#22c55e",
};

export default function Dashboard({ setToken }) {

  const [incidents, setIncidents] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [trends, setTrends] = useState([]);
  const [target, setTarget] = useState("");
  const [search, setSearch] = useState("");
  const [alertThreshold, setAlertThreshold] = useState(10);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [showWorkflow, setShowWorkflow] = useState(false);
  const [users, setUsers] = useState([]);
  const [currentUser, setCurrentUser] = useState({ role: 'admin' });
  const [heatmapData, setHeatmapData] = useState([]);

  // =========================
  // LOAD DASHBOARD
  // =========================
  useEffect(() => {

    loadDashboard();
    loadUsers();

    socket.on("new_incident", (data) => {

      setIncidents((prev) => [
        data,
        ...prev,
      ]);

      loadStats();

      loadTrends();
    });

    socket.on("log_stream", (log) => {

      setLogs((prev) => [
        log,
        ...prev,
      ].slice(0, 100));
    });

    return () => {

      socket.off("new_incident");

      socket.off("log_stream");
    };

  }, []);

  // =========================
  // LOAD ALL
  // =========================
  const loadDashboard = async () => {

    await loadIncidents();

    await loadStats();

    await loadTrends();
  };

  // =========================
  // LOAD INCIDENTS
  // =========================
  const loadIncidents = async () => {

    const res = await fetch(
      `${API}/api/incidents`
    );

    const data = await res.json();

    setIncidents(data);
  };

  // =========================
  // LOAD STATS
  // =========================
  const loadStats = async () => {

    const res = await fetch(
      `${API}/api/stats`
    );

    const data = await res.json();

    setStats(data);
  };

  // =========================
  // LOAD TRENDS
  // =========================
  const loadTrends = async () => {

    const res = await fetch(
      `${API}/api/trends`
    );

    const data = await res.json();

    const formatted = data.map((item) => ({
      time: item.time,

      value:
        item.severity === "Critical"
          ? 4
          : item.severity === "High"
          ? 3
          : item.severity === "Medium"
          ? 2
          : 1,
    }));

    setTrends(formatted);
  };

  // =========================
  // RUN SCAN
  // =========================
  const runScan = async () => {

    if (!target) return;

    await fetch(`${API}/api/scan`, {

      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        target,
      }),
    });

    setTarget("");

    loadDashboard();
  };

  // =========================
  // SEARCH
  // =========================
  const searchIncidents = async () => {

    const res = await fetch(
      `${API}/api/search?q=${search}`
    );

    const data = await res.json();

    setIncidents(data);
  };

  // =========================
  // LOGOUT
  // =========================
  const logout = () => {

    localStorage.removeItem("token");

    setToken(null);
  };

  // =========================
  // LOAD USERS
  // =========================
  const loadUsers = async () => {
    try {
      const res = await fetch(`${API}/api/users`);
      const data = await res.json();
      setUsers(data);
    } catch (err) {
      console.log("Users endpoint not available");
    }
  };

  // =========================
  // GENERATE HEATMAP DATA
  // =========================
  const generateHeatmapData = () => {
    const hours = Array.from({length: 24}, (_, i) => i);
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

    const heatmap = days.map(day => {
      const dayData = { day };
      hours.forEach(hour => {
        const incidentsAtTime = incidents.filter(incident => {
          const incidentDate = new Date(incident.timestamp);
          const incidentDay = incidentDate.toLocaleDateString('en-US', { weekday: 'short' });
          const incidentHour = incidentDate.getHours();
          return incidentDay === day && incidentHour === hour;
        });
        dayData[`hour_${hour}`] = incidentsAtTime.length;
      });
      return dayData;
    });

    setHeatmapData(heatmap);
  };

  // =========================
  // UPDATE INCIDENT STATUS
  // =========================
  const updateIncidentStatus = async (incidentId, status) => {
    try {
      await fetch(`${API}/api/incidents/${incidentId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      await loadIncidents();
    } catch (err) {
      console.error('Failed to update incident status');
    }
  };

  // =========================
  // ASSIGN INCIDENT
  // =========================
  const assignIncident = async (incidentId, userId) => {
    try {
      await fetch(`${API}/api/incidents/${incidentId}/assign`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: userId })
      });
      await loadIncidents();
    } catch (err) {
      console.error('Failed to assign incident');
    }
  };

  // Update heatmap when incidents change
  useEffect(() => {
    generateHeatmapData();
  }, [incidents]);

  // =========================
  // PIE DATA
  // =========================
  const pieData = [
    {
      name: "Critical",
      value: stats.Critical || 0,
    },

    {
      name: "High",
      value: stats.High || 0,
    },

    {
      name: "Medium",
      value: stats.Medium || 0,
    },

    {
      name: "Low",
      value: stats.Low || 0,
    },
  ];

  return (
    <div
      style={{
        background: "#020617",
        minHeight: "100vh",
        color: "white",
        padding: 20,
        fontFamily: "Arial",
      }}
    >

      {/* HEADER */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: 20,
        }}
      >

        <div>
          <h1
            style={{
              color: "#22c55e",
            }}
          >
            Enterprise AI SIEM/SOAR
          </h1>

          <p style={{ color: "#94a3b8" }}>
            Real-Time Threat Monitoring
          </p>
        </div>

        <button
          onClick={logout}

          style={{
            background: "#ef4444",
            border: "none",
            padding: "10px 20px",
            borderRadius: 8,
            color: "white",
            cursor: "pointer",
          }}
        >
          Logout
        </button>

      </div>

      {/* SEARCH */}
      <div
        style={{
          display: "flex",
          gap: 10,
          marginBottom: 20,
        }}
      >

        <input
          value={search}

          onChange={(e) =>
            setSearch(e.target.value)
          }

          placeholder="Search incidents..."

          style={{
            flex: 1,
            padding: 12,
            background: "#0f172a",
            border: "1px solid #334155",
            color: "white",
            borderRadius: 8,
          }}
        />

        <button
          onClick={searchIncidents}

          style={{
            padding: "12px 20px",
            background: "#3b82f6",
            border: "none",
            borderRadius: 8,
            color: "white",
            cursor: "pointer",
          }}
        >
          Search
        </button>

      </div>

      {/* SCAN */}
      <div
        style={{
          background: "#0f172a",
          padding: 20,
          borderRadius: 12,
          marginBottom: 20,
        }}
      >

        <h2
          style={{
            color: "#22c55e",
          }}
        >
          Run Nmap Scan
        </h2>

        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 10,
          }}
        >

          <input
            value={target}

            onChange={(e) =>
              setTarget(e.target.value)
            }

            placeholder="127.0.0.1"

            style={{
              flex: 1,
              padding: 12,
              background: "#020617",
              border: "1px solid #334155",
              color: "white",
              borderRadius: 8,
            }}
          />

          <button
            onClick={runScan}

            style={{
              padding: "12px 20px",
              background: "#22c55e",
              border: "none",
              borderRadius: 8,
              color: "black",
              cursor: "pointer",
              fontWeight: "bold",
            }}
          >
            Scan
          </button>

        </div>
      </div>

      {/* ALERT THRESHOLDS & SETTINGS */}
      <div
        style={{
          background: "#0f172a",
          padding: 20,
          borderRadius: 12,
          marginBottom: 20,
        }}
      >
        <h2 style={{ color: "#22c55e" }}>Alert Settings</h2>
        <div style={{ display: "flex", gap: 20, alignItems: "center", marginTop: 10 }}>
          <div>
            <label style={{ color: "#94a3b8", marginRight: 10 }}>Critical Alert Threshold:</label>
            <input
              type="number"
              value={alertThreshold}
              onChange={(e) => setAlertThreshold(parseInt(e.target.value))}
              style={{
                padding: 8,
                background: "#020617",
                border: "1px solid #334155",
                color: "white",
                borderRadius: 4,
                width: 80
              }}
            />
          </div>
          <div style={{ color: "#94a3b8" }}>
            Current Incidents: <span style={{ color: "#ef4444", fontWeight: "bold" }}>{incidents.length}</span>
            {incidents.length > alertThreshold && (
              <span style={{ color: "#ef4444", marginLeft: 10 }}>⚠️ THRESHOLD EXCEEDED!</span>
            )}
          </div>
        </div>
      </div>

      {/* INCIDENT WORKFLOW MANAGEMENT */}
      <div
        style={{
          background: "#0f172a",
          padding: 20,
          borderRadius: 12,
          marginBottom: 20,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2 style={{ color: "#22c55e" }}>Incident Management</h2>
          <button
            onClick={() => setShowWorkflow(!showWorkflow)}
            style={{
              padding: "8px 16px",
              background: "#3b82f6",
              border: "none",
              borderRadius: 6,
              color: "white",
              cursor: "pointer",
            }}
          >
            {showWorkflow ? "Hide Workflow" : "Show Workflow"}
          </button>
        </div>

        {showWorkflow && (
          <div style={{ marginTop: 20 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 15 }}>
              {incidents.slice(0, 6).map((incident) => (
                <div
                  key={incident.id}
                  style={{
                    background: "#020617",
                    padding: 15,
                    borderRadius: 8,
                    border: "1px solid #334155"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                    <div>
                      <h4 style={{ color: "#22c55e", margin: "0 0 8px 0" }}>{incident.title}</h4>
                      <p style={{ color: "#94a3b8", fontSize: "14px", margin: "0 0 10px 0" }}>
                        {incident.details.substring(0, 100)}...
                      </p>
                      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                        <span style={{
                          padding: "2px 8px",
                          borderRadius: 4,
                          fontSize: "12px",
                          background: COLORS[incident.severity] || "#666",
                          color: "white"
                        }}>
                          {incident.severity}
                        </span>
                        <span style={{ color: "#94a3b8", fontSize: "12px" }}>
                          {new Date(incident.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div style={{ marginTop: 15, display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <select
                      onChange={(e) => updateIncidentStatus(incident.id, e.target.value)}
                      defaultValue={incident.status || "open"}
                      style={{
                        padding: "4px 8px",
                        background: "#1e293b",
                        border: "1px solid #334155",
                        color: "white",
                        borderRadius: 4,
                        fontSize: "12px"
                      }}
                    >
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </select>

                    <select
                      onChange={(e) => assignIncident(incident.id, e.target.value)}
                      defaultValue=""
                      style={{
                        padding: "4px 8px",
                        background: "#1e293b",
                        border: "1px solid #334155",
                        color: "white",
                        borderRadius: 4,
                        fontSize: "12px"
                      }}
                    >
                      <option value="">Assign To...</option>
                      {users.map(user => (
                        <option key={user.id} value={user.id}>{user.username}</option>
                      ))}
                    </select>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* CHARTS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 20,
          marginBottom: 20,
        }}
      >

        {/* PIE CHART */}
        <div
          style={{
            background: "#0f172a",
            padding: 20,
            borderRadius: 12,
          }}
        >

          <h2 style={{ color: "#22c55e" }}>
            Severity Distribution
          </h2>

          <ResponsiveContainer width="100%" height={300}>

            <PieChart>

              <Pie
                data={pieData}
                dataKey="value"
                outerRadius={100}
                label
              >

                {pieData.map((entry, index) => (

                  <Cell
                    key={index}
                    fill={COLORS[entry.name]}
                  />
                ))}

              </Pie>

              <Tooltip />

              <Legend />

            </PieChart>

          </ResponsiveContainer>

        </div>

        {/* LINE CHART */}
        <div
          style={{
            background: "#0f172a",
            padding: 20,
            borderRadius: 12,
          }}
        >

          <h2 style={{ color: "#22c55e" }}>
            Threat Trends
          </h2>

          <ResponsiveContainer width="100%" height={300}>

            <LineChart data={trends}>

              <CartesianGrid stroke="#1e293b" />

              <XAxis
                dataKey="time"
                stroke="#94a3b8"
              />

              <YAxis stroke="#94a3b8" />

              <Tooltip />

              <Line
                type="monotone"
                dataKey="value"
                stroke="#22c55e"
                strokeWidth={3}
              />

            </LineChart>

          </ResponsiveContainer>

        </div>

      </div>

      {/* ADDITIONAL CHARTS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 20,
          marginBottom: 20,
        }}
      >

        {/* HEATMAP CHART */}
        <div
          style={{
            background: "#0f172a",
            padding: 20,
            borderRadius: 12,
          }}
        >
          <h2 style={{ color: "#22c55e" }}>
            Incident Heatmap (Day/Hour)
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={heatmapData}>
              <CartesianGrid stroke="#1e293b" />
              <XAxis dataKey="day" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Legend />
              {Array.from({length: 24}, (_, i) => (
                <Bar key={i} dataKey={`hour_${i}`} stackId="a" fill={`hsl(${i * 15}, 70%, 50%)`} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* TIMELINE CHART */}
        <div
          style={{
            background: "#0f172a",
            padding: 20,
            borderRadius: 12,
          }}
        >
          <h2 style={{ color: "#22c55e" }}>
            Incident Timeline
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trends}>
              <CartesianGrid stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Area
                type="monotone"
                dataKey="value"
                stroke="#22c55e"
                fill="#22c55e"
                fillOpacity={0.3}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

      </div>

      {/* INCIDENTS */}
      <div
        style={{
          background: "#0f172a",
          padding: 20,
          borderRadius: 12,
          marginBottom: 20,
        }}
      >

        <h2 style={{ color: "#22c55e" }}>
          Live Incidents
        </h2>

        {incidents.map((incident, index) => (

          <div
            key={index}

            style={{
              background: "#020617",
              padding: 15,
              marginTop: 10,
              borderRadius: 8,

              borderLeft: `5px solid ${
                COLORS[incident.severity]
              }`,
            }}
          >

            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
              }}
            >

              <strong>
                {incident.title}
              </strong>

              <span
                style={{
                  color:
                    COLORS[incident.severity],
                }}
              >
                {incident.severity}
              </span>

            </div>

            <div
              style={{
                color: "#94a3b8",
                marginTop: 5,
              }}
            >
              {incident.time}
            </div>

            <div
              style={{
                marginTop: 10,
                color: "#e2e8f0",
              }}
            >
              {incident.details}
            </div>

          </div>
        ))}

      </div>

      {/* LOGS */}
      <div
        style={{
          background: "#020617",
          padding: 20,
          borderRadius: 12,
          height: 250,
          overflowY: "auto",
          fontFamily: "monospace",
        }}
      >

        <h2 style={{ color: "#22c55e" }}>
          Live Logs
        </h2>

        {logs.map((log, index) => (

          <div
            key={index}

            style={{
              marginTop: 10,
              borderBottom:
                "1px solid #1e293b",

              paddingBottom: 8,
            }}
          >

            <span
              style={{
                color: "#64748b",
              }}
            >
              [{log.timestamp}]
            </span>

            {" "}

            <span
              style={{
                color:
                  COLORS[log.severity],
              }}
            >
              {log.severity}
            </span>

            {" → "}

            <span>
              {log.title}
            </span>

          </div>
        ))}

      </div>

    </div>
  );
}