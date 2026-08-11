import { useEffect, useState } from "react";
import Dashboard from "./Dashboard";
import Login from "./Login";
import ErrorBoundary from "./ErrorBoundary";

export default function App() {
  const [auth, setAuth] = useState({ token: null, role: null });
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const role = localStorage.getItem("role");
    setAuth({ token, role });
    setInitialized(true);
  }, []);

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

  if (!initialized) {
    return null;
  }

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