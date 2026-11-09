import { useState } from "react";
import Dashboard from "./Dashboard";
import Login from "./Login";
import ErrorBoundary from "./ErrorBoundary";

export default function App() {
  const [auth, setAuth] = useState(() => {
    const token = localStorage.getItem("token");
    const role = localStorage.getItem("role");
    return { token, role };
  });

  const handleLogin = ({ token, role }) => {
    localStorage.setItem("token", token);
    localStorage.setItem("role", role || "analyst");
    setAuth({ token, role: role || "analyst" });
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    setAuth({ token: null, role: null });
  };

  return (
    <ErrorBoundary>
      {!auth.token ? (
        <Login onLogin={handleLogin} />
      ) : (
        <Dashboard auth={auth} onLogout={handleLogout} />
      )}
    </ErrorBoundary>
  );
}