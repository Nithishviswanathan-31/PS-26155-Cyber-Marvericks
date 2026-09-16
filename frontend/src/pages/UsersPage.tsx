import { useEffect, useState, type FormEvent } from "react";
import { Alert, Button, Card, CardContent, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from "@mui/material";
import { authJson } from "../api/http";
import { type Role, type SessionUser } from "../auth/AuthProvider";
type ManagedUser = SessionUser & { active: boolean };
const roles: Role[] = ["ADMIN", "AUDITOR", "REVIEWER"];
const json = (method: string, body: object) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
export default function UsersPage() {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [selected, setSelected] = useState("");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("AUDITOR");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { setUsers(await authJson<ManagedUser[]>("/api/users")); }
  useEffect(() => { void refresh().catch(() => setError("Unable to load users.")); }, []);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(null); setMessage("");
    try {
      if (selected) await authJson(`/api/users/${encodeURIComponent(selected)}`, json("PATCH", { role, ...(password ? { password } : {}) }));
      else await authJson("/api/users", json("POST", { username, display_name: displayName, role, password }));
      setPassword(""); await refresh(); setMessage("User saved. Changed accounts must sign in again.");
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Could not save user."); }
    finally { setPassword(""); setBusy(false); }
  }
  async function toggle(user: ManagedUser) {
    setBusy(true); setError(null);
    try { await authJson(`/api/users/${encodeURIComponent(user.user_id)}`, json("PATCH", { active: !user.active })); await refresh(); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "Could not update user."); }
    finally { setBusy(false); }
  }
  return <Stack spacing={3}><Typography variant="h4">User administration</Typography>
    <Alert severity="info">Role, password and enabled-state changes revoke the account’s sessions. The final enabled administrator is protected.</Alert>
    {error && <Alert severity="error">{error}</Alert>}{message && <Alert severity="success">{message}</Alert>}
    <Card><CardContent sx={{ overflowX: "auto" }}><Table size="small"><TableHead><TableRow>{["Username", "Name", "Role", "Status", "Actions"].map(label => <TableCell key={label}>{label}</TableCell>)}</TableRow></TableHead>
      <TableBody>{users.map(user => <TableRow key={user.user_id}><TableCell>{user.username}</TableCell><TableCell>{user.display_name}</TableCell><TableCell>{user.role}</TableCell><TableCell>{user.active ? "Enabled" : "Disabled"}</TableCell><TableCell>
        <Button disabled={busy} onClick={() => { setSelected(user.user_id); setRole(user.role); setPassword(""); }}>Edit</Button>
        <Button disabled={busy} onClick={() => void toggle(user)}>{user.active ? "Disable" : "Enable"}</Button>
      </TableCell></TableRow>)}</TableBody></Table></CardContent></Card>
    <Card><CardContent><Stack spacing={2} component="form" onSubmit={submit}>
      <Typography variant="h6">{selected ? `Edit ${users.find(user => user.user_id === selected)?.username ?? "user"}` : "Create user"}</Typography>
      {!selected && <><TextField label="Username" required value={username} onChange={e => setUsername(e.target.value)} /><TextField label="Display name" required value={displayName} onChange={e => setDisplayName(e.target.value)} /></>}
      <TextField label="Role" select value={role} onChange={e => setRole(e.target.value as Role)}>{roles.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
      <TextField label={selected ? "New password (optional)" : "Password (at least 12 characters)"} type="password" autoComplete="new-password" required={!selected} value={password} onChange={e => setPassword(e.target.value)} />
      <Stack direction="row" spacing={2}><Button type="submit" variant="contained" disabled={busy}>{busy ? "Saving…" : "Save user"}</Button><Button onClick={() => { setSelected(""); setPassword(""); }} disabled={busy}>New user</Button></Stack>
    </Stack></CardContent></Card>
  </Stack>;
}
