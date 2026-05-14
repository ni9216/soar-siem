import { useEffect, useState } from "react";
import Dashboard from "./Dashboard";
import Login from "./Login";

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

  if (!auth.token) {
    return <Login onLogin={handleLogin} />;
  }

  return <Dashboard auth={auth} onLogout={handleLogout} />;
}