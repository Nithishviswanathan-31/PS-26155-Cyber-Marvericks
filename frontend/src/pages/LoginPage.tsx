import { useState, type FormEvent } from "react";
import { Alert, Button, Card, CardContent, Container, Stack, TextField, Typography } from "@mui/material";

export default function LoginPage({ onLogin, onRetry, message }: {
  onLogin: (username: string, password: string) => Promise<void>; onRetry: () => void; message: string | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(null);
    try { await onLogin(username, password); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "Sign in failed."); }
    finally { setPassword(""); setBusy(false); }
  }
  return <Container maxWidth="sm" sx={{ py: 10 }}><Card><CardContent>
    <Stack component="form" spacing={3} onSubmit={submit}>
      <Typography variant="overline" color="secondary.main">PS 26155 AUDITOR</Typography>
      <Typography variant="h4">Sign in</Typography>
      {message && <Alert severity="info">{message}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
      <TextField label="Username" autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} />
      <TextField label="Password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
      <Button type="submit" variant="contained" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</Button>
      <Button onClick={onRetry} disabled={busy}>Retry server connection</Button>
    </Stack>
  </CardContent></Card></Container>;
}
