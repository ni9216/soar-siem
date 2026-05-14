import { useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";
const DEFAULT_USERNAME = import.meta.env.VITE_DEFAULT_ADMIN_USERNAME || "admin";
const DEFAULT_PASSWORD = import.meta.env.VITE_DEFAULT_ADMIN_PASSWORD || "admin";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState(DEFAULT_USERNAME);
  const [password, setPassword] = useState(DEFAULT_PASSWORD);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");

  const login = async () => {
    const nextErrors = {};
    if (!username.trim()) {
      nextErrors.username = "Username is required.";
    }
    if (!password) {
      nextErrors.password = "Password is required.";
    }

    if (Object.keys(nextErrors).length) {
      setErrors(nextErrors);
      return;
    }

    setErrors({});
    setServerError("");
    setLoading(true);

    try {
      const res = await fetch(`${API}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await res.json();

      if (res.ok && data.token) {
        onLogin({ token: data.token, role: data.role || "analyst" });
      } else {
        setServerError(data.error || "Unable to sign in. Check credentials.");
      }
    } catch (err) {
      setServerError("Unable to connect to backend.");
    }

    setLoading(false);
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "linear-gradient(135deg, #020617 0%, #0f172a 100%)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        padding: 20,
        fontFamily: "Inter, system-ui, sans-serif",
      }}
    >
      <div
        style={{
          width: 400,
          background: "#0f172a",
          border: "1px solid #1e293b",
          borderRadius: 24,
          padding: 36,
          boxShadow: "0 24px 80px rgba(0, 0, 0, 0.25)",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <h1
            style={{
              color: "#22c55e",
              marginBottom: 6,
              fontSize: 32,
            }}
          >
            SOC Dashboard
          </h1>
          <p style={{ color: "#94a3b8", margin: 0 }}>
            Secure sign in to access analytics and automation.
          </p>
        </div>

        {serverError && (
          <div
            style={{
              marginBottom: 18,
              padding: 14,
              background: "#fee2e2",
              color: "#991b1b",
              borderRadius: 12,
              fontSize: 14,
            }}
          >
            {serverError}
          </div>
        )}

        <label style={{ color: "#94a3b8", fontSize: 14, marginBottom: 8, display: "block" }}>
          Username
        </label>
        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{
            width: "100%",
            padding: 14,
            marginBottom: errors.username ? 6 : 18,
            background: "#020617",
            border: `1px solid ${errors.username ? "#dc2626" : "#334155"}`,
            borderRadius: 12,
            color: "white",
            fontSize: 15,
          }}
        />
        {errors.username && (
          <div style={{ color: "#fca5a5", marginBottom: 12, fontSize: 13 }}>
            {errors.username}
          </div>
        )}

        <label style={{ color: "#94a3b8", fontSize: 14, marginBottom: 8, display: "block" }}>
          Password
        </label>
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            padding: 14,
            marginBottom: errors.password ? 6 : 20,
            background: "#020617",
            border: `1px solid ${errors.password ? "#dc2626" : "#334155"}`,
            borderRadius: 12,
            color: "white",
            fontSize: 15,
          }}
        />
        {errors.password && (
          <div style={{ color: "#fca5a5", marginBottom: 12, fontSize: 13 }}>
            {errors.password}
          </div>
        )}

        <button
          onClick={login}
          disabled={loading}
          style={{
            width: "100%",
            padding: 15,
            borderRadius: 12,
            border: "none",
            background: "#22c55e",
            color: "#020617",
            fontWeight: 700,
            fontSize: 16,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading ? 0.85 : 1,
          }}
        >
          {loading ? "Signing in..." : "Sign in"}
        </button>

        <div
          style={{
            marginTop: 20,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: 13,
            color: "#64748b",
          }}
        >
          <span>
            Default: {DEFAULT_USERNAME} / {DEFAULT_PASSWORD}
          </span>
          <a
            href="#"
            onClick={(event) => event.preventDefault()}
            style={{ color: "#60a5fa", textDecoration: "none" }}
          >
            Forgot password?
          </a>
        </div>
      </div>
    </div>
  );
}
