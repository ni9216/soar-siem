import { useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";

export default function Login({ setToken }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const login = async () => {
    if (!username || !password) {
      alert("Enter username and password");
      return;
    }

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

      if (data.token) {
        localStorage.setItem("token", data.token);
        setToken(data.token);
      } else {
        alert("Invalid credentials");
      }
    } catch (err) {
      alert("Backend not running");
    }

    setLoading(false);
  };

  return (
    <div
      style={{
        height: "100vh",
        background:
          "linear-gradient(135deg, #020617 0%, #0f172a 100%)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        fontFamily: "Arial",
      }}
    >
      <div
        style={{
          width: 380,
          background: "#0f172a",
          border: "1px solid #1e293b",
          borderRadius: 20,
          padding: 40,
          boxShadow: "0 0 40px rgba(0,255,136,0.1)",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 30 }}>
          <h1
            style={{
              color: "#22c55e",
              marginBottom: 10,
              fontSize: 32,
            }}
          >
            AI SIEM / SOAR
          </h1>

          <p style={{ color: "#94a3b8" }}>
            Enterprise Security Platform
          </p>
        </div>

        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{
            width: "100%",
            padding: 15,
            marginBottom: 15,
            background: "#020617",
            border: "1px solid #334155",
            borderRadius: 10,
            color: "white",
            fontSize: 16,
          }}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            padding: 15,
            marginBottom: 20,
            background: "#020617",
            border: "1px solid #334155",
            borderRadius: 10,
            color: "white",
            fontSize: 16,
          }}
        />

        <button
          onClick={login}
          style={{
            width: "100%",
            padding: 15,
            borderRadius: 10,
            border: "none",
            background: "#22c55e",
            color: "black",
            fontWeight: "bold",
            fontSize: 16,
            cursor: "pointer",
          }}
        >
          {loading ? "Signing in..." : "Login"}
        </button>

        <div
          style={{
            marginTop: 20,
            textAlign: "center",
            color: "#64748b",
            fontSize: 14,
          }}
        >
          admin / admin
        </div>
      </div>
    </div>
  );
}