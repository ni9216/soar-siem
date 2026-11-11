import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const colors = {
  Critical: "#fb7185",
  High: "#fb923c",
  Medium: "#facc15",
  Low: "#4ade80",
};

const panelStyle = {
  background: "#101820",
  border: "1px solid #29363e",
  borderRadius: 8,
  padding: 18,
};

const fieldStyle = {
  minWidth: 0,
  padding: "10px 12px",
  border: "1px solid #39474e",
  borderRadius: 6,
  background: "#0a1116",
  color: "#e5edf0",
};

const buttonStyle = {
  padding: "9px 12px",
  border: "1px solid #48645d",
  borderRadius: 6,
  background: "#183d34",
  color: "#d8f3e7",
  cursor: "pointer",
};

function Metric({ label, value, accent = "#d9e3e7" }) {
  return (
    <div style={{ ...panelStyle, padding: 16 }}>
      <div style={{ color: "#94a3a8", fontSize: 13 }}>{label}</div>
      <div style={{ color: accent, fontSize: 26, fontWeight: 700, marginTop: 6 }}>{value}</div>
    </div>
  );
}

function StateMessage({ children }) {
  return <div style={{ color: "#a9b8bf", fontSize: 13, padding: "12px 0" }}>{children}</div>;
}

function trendFor(incidents, range) {
  const now = new Date();
  const start = new Date(now);
  if (range === 24) start.setHours(now.getHours() - 23, 0, 0, 0);
  else {
    start.setHours(0, 0, 0, 0);
    start.setDate(start.getDate() - range + 1);
  }
  const points = Array.from({ length: range === 24 ? 24 : range }, (_, index) => {
    const time = new Date(start);
    if (range === 24) time.setHours(time.getHours() + index);
    else time.setDate(time.getDate() + index);
    return {
      key: range === 24 ? `${time.getFullYear()}-${time.getMonth()}-${time.getDate()}-${time.getHours()}` : `${time.getFullYear()}-${time.getMonth()}-${time.getDate()}`,
      label: range === 24 ? time.toLocaleTimeString([], { hour: "numeric" }) : time.toLocaleDateString([], { month: "short", day: "numeric" }),
      incidents: 0,
    };
  });
  const indexByKey = new Map(points.map((point, index) => [point.key, index]));
  incidents.forEach((incident) => {
    const timestamp = incident.timestamp || incident.time;
    if (!timestamp) return;
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime()) || date < start || date > now) return;
    const key = range === 24
      ? `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`
      : `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
    const index = indexByKey.get(key);
    if (index !== undefined) points[index].incidents += 1;
  });
  return points;
}

export function OverviewPanel({ incidents, cases, range, onRangeChange }) {
  const start = new Date();
  start.setDate(start.getDate() - (range === 24 ? 1 : range - 1));
  const periodIncidents = incidents.filter((incident) => {
    const date = new Date(incident.timestamp || incident.time || 0);
    return !Number.isNaN(date.getTime()) && date >= start;
  });
  const active = incidents.filter((incident) => !["resolved", "closed"].includes(incident.status));
  const critical = active.filter((incident) => incident.severity === "Critical").length;
  const overdue = active.filter((incident) => incident.sla_breached).length;
  const resolvedDurations = incidents
    .filter((incident) => incident.timestamp && incident.closed_at)
    .map((incident) => (new Date(incident.closed_at) - new Date(incident.timestamp)) / 3600000)
    .filter((duration) => Number.isFinite(duration) && duration >= 0);
  const meanResolution = resolvedDurations.length
    ? `${(resolvedDurations.reduce((total, duration) => total + duration, 0) / resolvedDurations.length).toFixed(1)}h`
    : "n/a";
  const trend = trendFor(incidents, range);

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <div>
          <div style={{ color: "#9baeb3", fontSize: 13 }}>Operations snapshot</div>
          <h2 style={{ margin: "4px 0", fontSize: 20 }}>Security posture</h2>
        </div>
        <div role="group" aria-label="Incident trend range" style={{ display: "flex", gap: 4 }}>
          {[24, 7, 30].map((value) => (
            <button key={value} onClick={() => onRangeChange(value)} aria-pressed={range === value} style={{ ...buttonStyle, background: range === value ? "#245444" : "#101820", borderColor: range === value ? "#4b806c" : "#39474e" }}>
              {value === 24 ? "24h" : `${value}d`}
            </button>
          ))}
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
        <Metric label="Incidents in period" value={periodIncidents.length} />
        <Metric label="Active incidents" value={active.length} accent="#facc15" />
        <Metric label="Critical active" value={critical} accent="#fb7185" />
        <Metric label="SLA breached" value={overdue} accent={overdue ? "#fb7185" : "#4ade80"} />
        <Metric label="Mean resolution" value={meanResolution} />
        <Metric label="Open cases" value={cases.filter((item) => !["resolved", "closed"].includes(item.status)).length} />
      </div>
      <section style={panelStyle}>
        <div style={{ fontWeight: 700, marginBottom: 12 }}>Incident volume</div>
        {incidents.length ? (
          <div style={{ width: "100%", height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <defs><linearGradient id="incidentVolume" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48b78a" stopOpacity={0.4} /><stop offset="100%" stopColor="#48b78a" stopOpacity={0.02} /></linearGradient></defs>
                <CartesianGrid stroke="#29363e" strokeDasharray="3 3" />
                <XAxis dataKey="label" tick={{ fill: "#94a3a8", fontSize: 11 }} interval="preserveStartEnd" />
                <YAxis allowDecimals={false} tick={{ fill: "#94a3a8", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#101820", border: "1px solid #39474e", borderRadius: 6, color: "#e5edf0" }} />
                <Area type="monotone" dataKey="incidents" name="Incidents" stroke="#48b78a" fill="url(#incidentVolume)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : <StateMessage>No incident data is available yet.</StateMessage>}
      </section>
    </div>
  );
}

export function InvestigationPanel({ incidents, users, selectedIncidentId, onSelectIncident }) {
  const incident = incidents.find((item) => String(item.id) === String(selectedIncidentId));
  const timeline = [...(incident?.timeline || [])].sort((left, right) => new Date(left.at || left.ts || 0) - new Date(right.at || right.ts || 0));
  return (
    <section style={panelStyle}>
      <div style={{ color: "#9baeb3", fontSize: 13 }}>Investigation workspace</div>
      <h2 style={{ margin: "4px 0 14px", fontSize: 20 }}>Incident activity timeline</h2>
      <select aria-label="Select incident" value={selectedIncidentId || ""} onChange={(event) => onSelectIncident(event.target.value)} style={{ ...fieldStyle, width: "100%", marginBottom: 18 }}>
        <option value="">Choose an incident</option>
        {incidents.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.title}</option>)}
      </select>
      {!incident ? <StateMessage>Select an incident to inspect its status, owner, SLA, and recorded events.</StateMessage> : (
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 8 }}>
            {[
              ["Severity", incident.severity],
              ["Status", incident.status || "open"],
              ["Owner", users.find((user) => user.id === incident.assigned_to)?.username || "Unassigned"],
              ["SLA", incident.sla_breached ? "Breached" : incident.sla_due_at ? new Date(incident.sla_due_at).toLocaleString() : "Not set"],
            ].map(([label, value]) => <div key={label} style={{ ...panelStyle, padding: 12 }}><div style={{ color: "#94a3a8", fontSize: 12 }}>{label}</div><div style={{ marginTop: 4, overflowWrap: "anywhere" }}>{value}</div></div>)}
          </div>
          <div style={{ color: "#c6d1d5", lineHeight: 1.6 }}>{incident.details || "No incident details recorded."}</div>
          <div style={{ borderLeft: "2px solid #426459", marginLeft: 6, paddingLeft: 16, display: "grid", gap: 14 }}>
            <div>
              <strong>Incident opened</strong>
              <div style={{ color: "#94a3a8", fontSize: 12 }}>{incident.timestamp ? new Date(incident.timestamp).toLocaleString() : incident.time || "Time unavailable"}</div>
            </div>
            {timeline.map((event, index) => (
              <div key={`${event.at || event.ts || "event"}-${index}`}>
                <strong>{(event.action || "Event").replace(/_/g, " ")}</strong>
                <div style={{ color: "#94a3a8", fontSize: 12 }}>{event.actor || event.by || "system"} · {event.at || event.ts ? new Date(event.at || event.ts).toLocaleString() : "Time unavailable"}</div>
                {event.details && <div style={{ color: "#b3c0c5", fontSize: 13, marginTop: 3 }}>{typeof event.details === "string" ? event.details : JSON.stringify(event.details)}</div>}
              </div>
            ))}
            {!timeline.length && <StateMessage>No timeline events have been recorded.</StateMessage>}
          </div>
        </div>
      )}
    </section>
  );
}

export function AssetsPanel({ assets, incidents, query, onQueryChange, selectedAssetId, onSelectAsset, asset, draft, onDraftChange, onCreate, canManage, message }) {
  const normalizedQuery = query.trim().toLowerCase();
  const visibleAssets = assets.filter((item) => !normalizedQuery || [item.name, item.ip_address, item.hostname, item.owner, item.asset_type].some((value) => value?.toLowerCase().includes(normalizedQuery)));
  const relatedIncidents = asset ? incidents.filter((incident) => {
    const identity = [asset.name, asset.hostname, asset.ip_address].filter(Boolean).join(" ").toLowerCase();
    return identity && `${incident.title || ""} ${incident.details || ""}`.toLowerCase().includes(identity);
  }) : [];
  return (
    <div style={{ display: "grid", gap: 14 }}>
      {canManage && <section style={panelStyle}>
        <div style={{ fontWeight: 700, marginBottom: 12 }}>Add asset</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(155px, 1fr))", gap: 8 }}>
          <input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="Asset name *" style={fieldStyle} />
          <input value={draft.ip_address} onChange={(event) => onDraftChange({ ...draft, ip_address: event.target.value })} placeholder="IP address" style={fieldStyle} />
          <input value={draft.hostname} onChange={(event) => onDraftChange({ ...draft, hostname: event.target.value })} placeholder="Hostname" style={fieldStyle} />
          <input value={draft.owner} onChange={(event) => onDraftChange({ ...draft, owner: event.target.value })} placeholder="Owner" style={fieldStyle} />
          <select value={draft.asset_type} onChange={(event) => onDraftChange({ ...draft, asset_type: event.target.value })} style={fieldStyle}><option value="server">Server</option><option value="workstation">Workstation</option><option value="network">Network</option><option value="cloud">Cloud</option></select>
          <select value={draft.criticality} onChange={(event) => onDraftChange({ ...draft, criticality: event.target.value })} style={fieldStyle}><option value="low">Low criticality</option><option value="medium">Medium criticality</option><option value="high">High criticality</option><option value="critical">Critical</option></select>
          <button onClick={onCreate} style={buttonStyle}>Add asset</button>
        </div>
        {message && <StateMessage>{message}</StateMessage>}
      </section>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 480px), 1fr))", gap: 14 }}>
        <section style={panelStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 10 }}><strong>Inventory</strong><span style={{ color: "#94a3a8", fontSize: 12 }}>{visibleAssets.length} assets</span></div>
          <input aria-label="Filter assets" value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Filter by name, host, IP..." style={{ ...fieldStyle, width: "100%", boxSizing: "border-box", marginBottom: 10 }} />
          <div style={{ display: "grid", gap: 4, maxHeight: 480, overflowY: "auto" }}>
            {visibleAssets.map((item) => <button key={item.id} onClick={() => onSelectAsset(item.id)} style={{ textAlign: "left", padding: 10, border: `1px solid ${String(selectedAssetId) === String(item.id) ? "#4b806c" : "#29363e"}`, borderRadius: 6, background: String(selectedAssetId) === String(item.id) ? "#18332d" : "#0a1116", color: "#e5edf0", cursor: "pointer" }}><div style={{ fontWeight: 700 }}>{item.name}</div><div style={{ color: "#94a3a8", fontSize: 12 }}>{item.ip_address || item.hostname || item.asset_type} · {item.criticality || "medium"}</div></button>)}
            {!visibleAssets.length && <StateMessage>No matching assets found.</StateMessage>}
          </div>
        </section>
        <section style={panelStyle}>
          {!asset ? <StateMessage>Select an inventory record to view its metadata.</StateMessage> : <>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}><h2 style={{ margin: 0, fontSize: 20 }}>{asset.name}</h2><span style={{ color: colors[asset.criticality?.[0]?.toUpperCase() + asset.criticality?.slice(1)] || "#94a3a8" }}>{asset.criticality || "medium"} criticality</span></div>
            <dl style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, margin: "18px 0" }}>
              {[["Hostname", asset.hostname], ["IP address", asset.ip_address], ["Type", asset.asset_type], ["Operating system", asset.os], ["Owner", asset.owner], ["Status", asset.status], ["Last seen", asset.last_seen ? new Date(asset.last_seen).toLocaleString() : "Not recorded"], ["Open ports", (asset.open_ports || []).join(", ") || "None recorded"]].map(([label, value]) => <div key={label}><dt style={{ color: "#94a3a8", fontSize: 12 }}>{label}</dt><dd style={{ margin: "4px 0 0", overflowWrap: "anywhere" }}>{value || "Not recorded"}</dd></div>)}
            </dl>
            <div style={{ color: "#a9b8bf", fontSize: 13 }}>Incidents mentioning this asset: {relatedIncidents.length}</div>
            {relatedIncidents.map((incident) => <div key={incident.id} style={{ borderTop: "1px solid #29363e", padding: "10px 0", marginTop: 8 }}><strong>#{incident.id} · {incident.title}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>{incident.severity} · {incident.status || "open"}</div></div>)}
          </>}
        </section>
      </div>
    </div>
  );
}

function ResultGroup({ title, items, render }) {
  return <section style={panelStyle}><div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}><strong>{title}</strong><span style={{ color: "#94a3a8", fontSize: 12 }}>{items.length}</span></div>{items.length ? items.map(render) : <StateMessage>No matches.</StateMessage>}</section>;
}

export function ThreatHuntPanel({ query, onQueryChange, onSearch, results, message, onOpenIncident }) {
  return (
    <div style={{ display: "grid", gap: 12 }}>
      <section style={panelStyle}>
        <div style={{ color: "#9baeb3", fontSize: 13 }}>Threat hunting</div>
        <h2 style={{ margin: "4px 0 12px", fontSize: 20 }}>Search operational data</h2>
        <form onSubmit={(event) => { event.preventDefault(); onSearch(); }} style={{ display: "flex", gap: 8 }}>
          <input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search incident text, MITRE ID, asset name, IP, or hostname" style={{ ...fieldStyle, flex: 1 }} />
          <button type="submit" style={buttonStyle}>Search</button>
        </form>
        {message && <StateMessage>{message}</StateMessage>}
      </section>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
        <ResultGroup title="Incidents" items={results.incidents} render={(item) => <button key={item.id} onClick={() => onOpenIncident(item.id)} style={{ display: "block", width: "100%", textAlign: "left", padding: 10, marginTop: 6, border: "1px solid #29363e", borderRadius: 6, background: "#0a1116", color: "#e5edf0", cursor: "pointer" }}><strong>#{item.id} · {item.title}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>{item.severity} · {item.status || "open"} · {item.mitre_attack_id || "No MITRE mapping"}</div></button>} />
        <ResultGroup title="Assets" items={results.assets} render={(item) => <div key={item.id} style={{ padding: 10, marginTop: 6, border: "1px solid #29363e", borderRadius: 6, background: "#0a1116" }}><strong>{item.name}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>{item.hostname || "No hostname"} · {item.ip_address || "No IP"}</div></div>} />
        <ResultGroup title="Recent live logs" items={results.logs} render={(item, index) => <pre key={`${item.timestamp || "log"}-${index}`} style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", padding: 10, margin: "6px 0 0", border: "1px solid #29363e", borderRadius: 6, background: "#0a1116", color: "#c6d1d5", fontSize: 12 }}>{JSON.stringify(item, null, 2)}</pre>} />
      </div>
      <div style={{ color: "#94a3a8", fontSize: 12 }}>Live log matches are limited to events currently held in this browser session.</div>
    </div>
  );
}

export function PlaybooksPanel({ incidents, selectedIncidentId, onSelectIncident, playbook, onPlaybookChange, onRequest, message, executions, isViewer, isAdmin, onApprove, onReject, onRollback }) {
  const pending = executions.filter((execution) => execution.status === "pending_approval");
  const history = executions.filter((execution) => execution.status !== "pending_approval");
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <section style={panelStyle}>
        <div style={{ color: "#9baeb3", fontSize: 13 }}>Automation console</div>
        <h2 style={{ margin: "4px 0 12px", fontSize: 20 }}>Preview or request a playbook</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 8 }}>
          <select aria-label="Incident for playbook" value={selectedIncidentId} onChange={(event) => onSelectIncident(event.target.value)} style={fieldStyle}><option value="">Select incident</option>{incidents.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.title}</option>)}</select>
          <select aria-label="Playbook" value={playbook} onChange={(event) => onPlaybookChange(event.target.value)} style={fieldStyle}><option value="investigation">Investigation</option><option value="containment">Containment</option><option value="escalation">Escalation</option></select>
          <button disabled={isViewer} onClick={() => onRequest(true)} style={{ ...buttonStyle, background: "#18272d", borderColor: "#39474e", opacity: isViewer ? 0.55 : 1 }}>Preview dry run</button>
          <button disabled={isViewer} onClick={() => onRequest(false)} style={{ ...buttonStyle, opacity: isViewer ? 0.55 : 1 }}>Request approval</button>
        </div>
        <div style={{ color: "#94a3a8", fontSize: 12, marginTop: 10 }}>Non-dry-run executions wait for administrator approval. A preview performs no actions.</div>
        {message && <StateMessage>{message}</StateMessage>}
      </section>
      {isAdmin && <section style={panelStyle}>
        <strong>Pending approval ({pending.length})</strong>
        <div style={{ display: "grid", gap: 8, marginTop: 10 }}>
          {pending.map((execution) => <div key={execution.id} style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap", padding: 10, border: "1px solid #29363e", borderRadius: 6 }}><div><strong>#{execution.id} · {execution.playbook}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>Incident #{execution.incident_id} · {execution.initiated_by} · {(execution.actions || []).join(", ")}</div></div><div style={{ display: "flex", gap: 6 }}><button onClick={() => onApprove(execution.id)} style={buttonStyle}>Approve</button><button onClick={() => onReject(execution.id)} style={{ ...buttonStyle, color: "#fecaca", background: "#3a1c20", borderColor: "#63343a" }}>Reject</button></div></div>)}
          {!pending.length && <StateMessage>No executions are waiting for approval.</StateMessage>}
        </div>
      </section>}
      <section style={panelStyle}>
        <strong>Execution history ({history.length})</strong>
        <div style={{ display: "grid", gap: 6, marginTop: 10, maxHeight: 360, overflowY: "auto" }}>
          {history.map((execution) => <div key={execution.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, padding: 10, borderBottom: "1px solid #29363e" }}><div><strong>#{execution.id} · {execution.playbook}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>Incident #{execution.incident_id} · {String(execution.status).replace(/_/g, " ")} · {execution.initiated_by}</div></div>{execution.status === "completed" && !isViewer && <button onClick={() => onRollback(execution.id)} style={{ ...buttonStyle, background: "#342914", borderColor: "#66522c", color: "#f6dda2" }}>Record rollback</button>}</div>)}
          {!history.length && <StateMessage>No playbook executions recorded.</StateMessage>}
        </div>
      </section>
    </div>
  );
}

export function DetectionsPanel({ rules, groups, draft, onDraftChange, onCreate, onToggle, onDelete, canManage, isAdmin, dedupWindow, onDedupChange, onSaveDedup, testRuleId, onTestRuleIdChange, testLog, onTestLogChange, onTest, message }) {
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <section style={panelStyle}>
        <div style={{ color: "#9baeb3", fontSize: 13 }}>Detection engineering</div>
        <h2 style={{ margin: "4px 0 12px", fontSize: 20 }}>Rules and alert tuning</h2>
        {canManage && <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, marginBottom: 14 }}>
          <input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="Rule name" style={fieldStyle} />
          <input value={draft.pattern} onChange={(event) => onDraftChange({ ...draft, pattern: event.target.value })} placeholder="Text match pattern" style={fieldStyle} />
          <select value={draft.severity} onChange={(event) => onDraftChange({ ...draft, severity: event.target.value })} style={fieldStyle}><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select>
          <input value={draft.mitre_attack_id} onChange={(event) => onDraftChange({ ...draft, mitre_attack_id: event.target.value })} placeholder="MITRE technique ID" style={fieldStyle} />
          <button onClick={onCreate} style={buttonStyle}>Create rule</button>
        </div>}
        {message && <StateMessage>{message}</StateMessage>}
        {canManage && testRuleId !== null && <div style={{ display: "grid", gap: 8, margin: "8px 0 14px" }}><textarea value={testLog} onChange={(event) => onTestLogChange(event.target.value)} rows={3} placeholder="Paste a sample event for the selected rule" style={{ ...fieldStyle, resize: "vertical" }} /><div style={{ display: "flex", gap: 8 }}><button onClick={() => onTest(rules.find((rule) => rule.id === testRuleId))} style={buttonStyle}>Test selected rule</button><button onClick={() => onTestRuleIdChange(null)} style={{ ...buttonStyle, background: "#101820", borderColor: "#39474e" }}>Cancel</button></div></div>}
        <div style={{ display: "grid", gap: 6 }}>
          {rules.map((rule) => <div key={rule.id} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", alignItems: "center", gap: 8, padding: 10, borderBottom: "1px solid #29363e" }}><div style={{ minWidth: 0 }}><strong>{rule.name}</strong><div style={{ color: "#94a3a8", fontSize: 12, overflowWrap: "anywhere" }}>{rule.severity} · {rule.mitre_attack_id || "Unmapped"} · {rule.enabled ? "Enabled" : "Disabled"} · {rule.pattern}</div></div>{canManage && <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "end" }}><button onClick={() => { onTestRuleIdChange(rule.id); }} style={{ ...buttonStyle, background: "#101820", borderColor: "#39474e" }}>Test</button><button onClick={() => onToggle(rule)} style={{ ...buttonStyle, background: "#101820", borderColor: "#39474e" }}>{rule.enabled ? "Disable" : "Enable"}</button><button onClick={() => onDelete(rule.id)} aria-label={`Delete ${rule.name}`} style={{ ...buttonStyle, background: "#3a1c20", borderColor: "#63343a", color: "#fecaca" }}>Delete</button></div>}</div>)}
          {!rules.length && <StateMessage>No detection rules configured.</StateMessage>}
        </div>
      </section>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 12 }}>
        {isAdmin && <section style={panelStyle}>
          <strong>Duplicate alert suppression</strong>
          <div style={{ color: "#94a3a8", fontSize: 13, margin: "8px 0 12px" }}>Deduplicate identical open alerts for a configured time window. This setting is administrator-only.</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}><input type="number" min="0" max="1440" value={dedupWindow} onChange={(event) => onDedupChange(event.target.value)} aria-label="Deduplication window in minutes" style={{ ...fieldStyle, width: 110 }} /><span style={{ color: "#94a3a8" }}>minutes</span><button onClick={onSaveDedup} style={{ ...buttonStyle, marginLeft: "auto" }}>Save</button></div>
        </section>}
        <section style={panelStyle}>
          <strong>Alert group activity</strong>
          <div style={{ display: "grid", gap: 6, marginTop: 10, maxHeight: 260, overflowY: "auto" }}>
            {groups.slice(0, 20).map((group) => <div key={group.id} style={{ padding: 9, borderBottom: "1px solid #29363e" }}><strong>{group.title}</strong><div style={{ color: "#94a3a8", fontSize: 12 }}>{group.incident_count} events · {group.suppressed_count} suppressed · {group.severity} · {group.status}</div></div>)}
            {!groups.length && <StateMessage>No alert groups yet.</StateMessage>}
          </div>
        </section>
      </div>
    </div>
  );
}

export default function OperationsPanels({ panel, ...props }) {
  const panels = {
    overview: <OverviewPanel {...props} />,
    timeline: <InvestigationPanel {...props} />,
    assets: <AssetsPanel {...props} />,
    hunt: <ThreatHuntPanel {...props} />,
    playbooks: <PlaybooksPanel {...props} />,
    detections: <DetectionsPanel {...props} />,
  };
  return panels[panel] || null;
}