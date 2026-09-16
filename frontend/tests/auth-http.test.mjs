import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

function layer(responder) {
  const values = new Map();
  const events = [];
  const source = readFileSync(new URL('../src/api/http.ts', import.meta.url), 'utf8')
    .replace('import.meta.env.VITE_API_URL', 'undefined');
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const context = { exports: {}, URL, Headers, Event,
    sessionStorage: { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
    window: { location: { origin: 'http://localhost:5173' }, dispatchEvent: event => events.push(event.type) },
    fetch: responder,
  };
  vm.runInNewContext(compiled, context);
  return { ...context.exports, events, values };
}

test('shared clients attach bearer only to configured audit API', async () => {
  const calls = [];
  const auth = layer(async (url, init) => { calls.push([url, init]); return new Response('{}'); });
  auth.setSession('test-session');
  await auth.authFetch('http://127.0.0.1:8000/api/analyses');
  await auth.authFetch('https://unrelated.example/api/analyses');
  assert.equal(calls[0][1].headers.get('Authorization'), 'Bearer test-session');
  assert.equal(calls[1][1].headers.get('Authorization'), null);
  assert.equal(calls[0][1].cache, 'no-store');
});

test('401 clears tab session and announces expiration', async () => {
  const auth = layer(async () => new Response('{}', { status: 401 }));
  auth.setSession('expired');
  await auth.authFetch('http://127.0.0.1:8000/api/auth/me');
  assert.equal(auth.values.size, 0);
  assert.deepEqual(auth.events, ['auth-expired']);
});

test('403 preserves session and announces insufficient permission', async () => {
  const auth = layer(async () => new Response('{}', { status: 403 }));
  auth.setSession('auditor');
  await auth.authFetch('http://127.0.0.1:8000/api/users');
  assert.equal(auth.values.size, 1);
  assert.deepEqual(auth.events, ['auth-forbidden']);
});

test('an old request cannot clear a newly signed-in session', async () => {
  let finish;
  const auth = layer(() => new Promise(resolve => { finish = resolve; }));
  auth.setSession('old');
  const pending = auth.authFetch('http://127.0.0.1:8000/api/auth/me');
  auth.setSession('new');
  finish(new Response('{}', { status: 401 }));
  await pending;
  assert.equal([...auth.values.values()][0], 'new');
  assert.deepEqual(auth.events, []);
});

test('external errors cannot invalidate the audit session', async () => {
  const auth = layer(async () => new Response('{}', { status: 401 }));
  auth.setSession('current');
  await auth.authFetch('https://unrelated.example/api/auth/me');
  assert.equal(auth.values.size, 1);
  assert.deepEqual(auth.events, []);
});
