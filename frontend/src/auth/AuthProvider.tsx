import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Alert, Box, Button, CircularProgress } from "@mui/material";
import { API_BASE_URL, authJson, setSession } from "../api/http";
import LoginPage from "../pages/LoginPage";

export type Role = "ADMIN" | "AUDITOR" | "REVIEWER";
export interface SessionUser { user_id: string; username: string; display_name: string; role: Role; offline?: boolean }
interface AuthState { user: SessionUser; logout: () => Promise<void> }
const AuthContext = createContext<AuthState | null>(null);
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("Authenticated workspace required");
  return value;
}

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let current = true;
    setLoading(true);
    authJson<SessionUser>("/api/auth/me").then(value => { if (current) { setUser(value); setError(null); } })
      .catch(() => { if (current) setError("Sign in to continue, or retry if the server is unavailable."); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [reload]);
  useEffect(() => {
    const expired = () => { setUser(null); setNotice("Your session ended. Please sign in again."); };
    const forbidden = () => setNotice("Your role does not permit that action.");
    window.addEventListener("auth-expired", expired);
    window.addEventListener("auth-forbidden", forbidden);
    return () => { window.removeEventListener("auth-expired", expired); window.removeEventListener("auth-forbidden", forbidden); };
  }, []);
  // Revalidate long-lived tabs without granting authority from cached role data.
  useEffect(() => {
    if (!user || user.offline) return;
    let current = true;
    const timer = window.setInterval(() => { void authJson<SessionUser>("/api/auth/me").then(value => { if (current) setUser(value); }).catch(() => undefined); }, 60000);
    return () => { current = false; window.clearInterval(timer); };
  }, [user?.user_id, user?.offline]);
  async function login(username: string, password: string) {
    const response = await fetch(`${API_BASE_URL}/api/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }), cache: "no-store" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail ?? "Sign in failed.");
    setSession(body.access_token);
    setUser({ ...body.user, offline: false }); setError(null); setNotice(null);
  }
  async function logout() {
    if (!user?.offline) await authJson("/api/auth/logout", { method: "POST" });
    setSession(null); setUser(null); setNotice(null);
  }
  if (loading) return <Box sx={{ p: 6 }}><CircularProgress aria-label="Checking session" /></Box>;
  if (!user) return <LoginPage onLogin={login} message={notice ?? error} onRetry={() => setReload(n => n + 1)} />;
  return <AuthContext.Provider value={{ user, logout }}>
    {notice && <Alert sx={{ position: "fixed", bottom: 16, right: 16, zIndex: 2000 }} severity="warning" onClose={() => setNotice(null)}>{notice}</Alert>}
    {user.offline && <Alert sx={{ position: "fixed", bottom: 0, left: 0, zIndex: 1900 }} severity="warning" action={<Button onClick={() => void logout()}>Sign in</Button>}>Local demo: authentication is disabled. This is not a secured session.</Alert>}
    {children}
  </AuthContext.Provider>;
}
