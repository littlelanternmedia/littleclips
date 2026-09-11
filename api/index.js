import crypto from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

const MCP_URL = 'https://api.krea.ai/mcp';
const API_BASE = 'https://api.krea.ai';
const META_URL = 'https://www.krea.ai/.well-known/oauth-authorization-server';
const FLOW_COOKIE = '__Host-krea_flow';
const TOKEN_COOKIE = '__Host-krea_tokens';
const MAX_UPLOAD_BYTES = 4_000_000;

const send = (res, status, body, headers = {}) => {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
};

const originFor = req => `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers['x-forwarded-host'] || req.headers.host}`;
const parseCookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim()).filter(Boolean).map(part => {
  const i = part.indexOf('=');
  return i < 0 ? [part, ''] : [part.slice(0, i), decodeURIComponent(part.slice(i + 1))];
}));
const encode = v => Buffer.from(JSON.stringify(v)).toString('base64url');
const decode = v => { try { return v ? JSON.parse(Buffer.from(v, 'base64url').toString('utf8')) : null; } catch { return null; } };
const cookie = (name, value, maxAge = 1800) => `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Lax; Secure; HttpOnly`;
const clearCookie = name => `${name}=; Path=/; Max-Age=0; SameSite=Lax; Secure; HttpOnly`;
const rand = n => crypto.randomBytes(n).toString('base64url');
const pkceChallenge = v => crypto.createHash('sha256').update(v).digest('base64url');

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

async function oauthMeta() {
  const r = await fetch(META_URL, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`Krea OAuth discovery failed (${r.status})`);
  return r.json();
}

async function registerClient(meta, redirectUri) {
  const r = await fetch(meta.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      client_name: 'Chatty Creator Studio — Krea Potato',
      client_uri: redirectUri.replace('/api?action=callback', '/'),
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    })
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.client_id) throw new Error(`Krea client registration failed (${r.status})`);
  return body;
}

async function startAuth(req, res) {
  const redirectUri = `${originFor(req)}/api?action=callback`;
  const meta = await oauthMeta();
  const client = await registerClient(meta, redirectUri);
  const verifier = rand(48), state = rand(24);
  const u = new URL(meta.authorization_endpoint);
  for (const [k, v] of Object.entries({
    response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri, state,
    code_challenge: pkceChallenge(verifier), code_challenge_method: 'S256', resource: MCP_URL
  })) u.searchParams.set(k, v);
  res.statusCode = 302;
  res.setHeader('set-cookie', cookie(FLOW_COOKIE, encode({ state, verifier, clientId: client.client_id, redirectUri }), 600));
  res.setHeader('location', u.toString());
  res.end();
}

async function callback(req, res, url) {
  const flow = decode(parseCookies(req)[FLOW_COOKIE]);
  const code = url.searchParams.get('code'), state = url.searchParams.get('state');
  if (url.searchParams.get('error')) throw new Error(url.searchParams.get('error_description') || url.searchParams.get('error'));
  if (!flow || !code || state !== flow.state) throw new Error('OAuth state validation failed');
  const meta = await oauthMeta();
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, client_id: flow.clientId, redirect_uri: flow.redirectUri, code_verifier: flow.verifier, resource: MCP_URL });
  const r = await fetch(meta.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body });
  const tokens = await r.json().catch(() => ({}));
  if (!r.ok || !tokens.access_token) throw new Error(`Krea token exchange failed (${r.status})`);
  const now = Math.floor(Date.now() / 1000);
  const stored = { ...tokens, client_id: flow.clientId, expires_at: tokens.expires_in ? now + Number(tokens.expires_in) : null };
  res.statusCode = 302;
  res.setHeader('set-cookie', [cookie(TOKEN_COOKIE, encode(stored), 60 * 60 * 24 * 30), clearCookie(FLOW_COOKIE)]);
  res.setHeader('location', '/?connected=1');
  res.end();
}

function tokenState(req) {
  const s = decode(parseCookies(req)[TOKEN_COOKIE]);
  return s?.access_token ? s : null;
}

async function accessToken(req) {
  const stored = tokenState(req);
  if (!stored) return { token: null, cookie: null };
  const now = Math.floor(Date.now() / 1000);
  if (!stored.expires_at || stored.expires_at - now > 90 || !stored.refresh_token) return { token: stored.access_token, cookie: null };
  const meta = await oauthMeta();
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: stored.refresh_token, client_id: stored.client_id, resource: MCP_URL });
  const r = await fetch(meta.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body });
  const next = await r.json().catch(() => ({}));
  if (!r.ok || !next.access_token) return { token: null, cookie: null };
  const merged = { ...stored, ...next, refresh_token: next.refresh_token || stored.refresh_token, expires_at: next.expires_in ? now + Number(next.expires_in) : stored.expires_at };
  return { token: merged.access_token, cookie: cookie(TOKEN_COOKIE, encode(merged), 60 * 60 * 24 * 30) };
}

async function withKrea(token, fn) {
  const client = new Client({ name: 'chatty-creator-studio-krea', version: '0.7.0' }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await client.connect(transport);
  try { return await fn(client); } finally { await client.close().catch(() => {}); }
}

function payload(result) {
  if (result?.structuredContent != null) return result.structuredContent;
  const text = result?.content?.find?.(x => x.type === 'text')?.text;
  if (text) { try { return JSON.parse(text); } catch { return { text }; } }
  return result ?? {};
}
async function rawCallTool(client, name, args = {}) { return client.request({ method: 'tools/call', params: { name, arguments: args } }, CallToolResultSchema); }
function toolErrorMessage(result) {
  const text = result?.content?.find?.(x => x.type === 'text')?.text;
  if (text) return text;
  const p = result?.structuredContent;
  if (typeof p?.error === 'string') return p.error;
  if (typeof p?.error?.message === 'string') return p.error.message;
  if (typeof p?.message === 'string') return p.message;
  return 'Krea tool returned an error';
}
function requireToolSuccess(result) { if (result?.isError) throw new Error(toolErrorMessage(result)); return result; }

function deepValue(o, keys, seen = new Set()) {
  if (!o || typeof o !== 'object' || seen.has(o)) return null;
  seen.add(o);
  for (const k of keys) if (o[k] != null) return o[k];
  for (const v of Object.values(o)) { const x = deepValue(v, keys, seen); if (x != null) return x; }
  return null;
}
function pickUrl(o) {
  let u = deepValue(o, ['image_url', 'original_url', 'output_url', 'asset_url']);
  if (typeof u === 'string' && /^https?:/i.test(u)) return u;
  const urls = deepValue(o, ['urls']);
  if (Array.isArray(urls)) {
    const x = urls.find(v => typeof v === 'string' && /^https?:/i.test(v));
    if (x) return x;
  }
  u = deepValue(o, ['url']);
  return typeof u === 'string' && /^https?:/i.test(u) ? u : null;
}

function chooseGenerateTool(tools, kind) {
  for (const n of (kind === 'video' ? ['generate_video', 'generate'] : ['generate_image', 'generate'])) {
    const t = tools.find(x => x.name === n); if (t) return t;
  }
  return tools.find(t => /generate/i.test(t.name) && new RegExp(kind, 'i').test(`${t.name} ${t.description || ''}`));
}
function findSchemaProperty(node, key, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return null;
  seen.add(node);
  if (node.properties && typeof node.properties === 'object' && node.properties[key] && typeof node.properties[key] === 'object') return node.properties[key];
  if (node[key] && typeof node[key] === 'object' && (Array.isArray(node[key].enum) || node[key].type || node[key].anyOf || node[key].oneOf || node[key].properties)) return node[key];
  for (const value of Object.values(node)) { const found = findSchemaProperty(value, key, seen); if (found) return found; }
  return null;
}
function enumValues(spec) {
  if (!spec || typeof spec !== 'object') return [];
  if (Array.isArray(spec.enum)) return spec.enum.filter(v => typeof v === 'string' || typeof v === 'number');
  const branches = [...(Array.isArray(spec.anyOf) ? spec.anyOf : []), ...(Array.isArray(spec.oneOf) ? spec.oneOf : [])];
  return branches.flatMap(b => Array.isArray(b?.enum) ? b.enum : (Object.prototype.hasOwnProperty.call(b || {}, 'const') ? [b.const] : [])).filter(v => typeof v === 'string' || typeof v === 'number');
}
function refShape(spec, url) {
  const type = spec?.type;
  const item = spec?.items;
  if (type === 'array' || item) {
    if (item?.type === 'object' || item?.properties?.url) return [{ url }];
    return [url];
  }
  if (type === 'object' || spec?.properties?.url) return { url };
  return url;
}
function referenceField(schema) {
  const candidates = ['start_image', 'startImage', 'image_url', 'imageUrl', 'input_image', 'inputImage', 'image', 'reference_image', 'referenceImage', 'reference_images', 'referenceImages', 'images'];
  for (const name of candidates) {
    const spec = findSchemaProperty(schema, name);
    if (spec) return { name, spec };
  }
  return null;
}

async function enrichModelOptions(client, body) {
  const requested = { ...(body.options || {}) };
  let schema = null;
  try {
    const schemaResult = requireToolSuccess(await rawCallTool(client, 'get_model_schema', { model: body.model }));
    schema = payload(schemaResult);
  } catch {}
  const options = {};
  if (schema) {
    for (const [k, v] of Object.entries(requested)) if (findSchemaProperty(schema, k)) options[k] = v;
  } else Object.assign(options, requested);

  if (body.kind === 'image' && schema && !options.resolution) {
    const values = enumValues(findSchemaProperty(schema, 'resolution'));
    if (values.length) options.resolution = values.includes('1K') ? '1K' : values[0];
  }
  if (body.kind === 'image' && !options.resolution && /sunburst|flare|gpt-image-2/i.test(body.model)) options.resolution = '1K';

  let ref = null;
  if (body.referenceUrl) {
    ref = schema ? referenceField(schema) : { name: 'start_image', spec: { type: 'string' } };
    if (!ref) throw new Error('This selected model does not expose a start/reference image input. Choose another video model.');
    options[ref.name] = refShape(ref.spec, body.referenceUrl);
  }
  return { ...body, options, referenceField: ref?.name || null };
}

function buildArgs(tool, body) {
  const props = tool?.inputSchema?.properties || {}, args = {};
  if ('model' in props) args.model = body.model;
  else if ('model_id' in props) args.model_id = body.model;
  else if ('modelId' in props) args.modelId = body.model;
  const input = { prompt: body.prompt, ...(body.options || {}) };
  if ('input' in props) args.input = input; else Object.assign(args, input);
  if ('sync' in props) args.sync = false;
  if ('media_type' in props) args.media_type = body.kind;
  if ('type' in props && !('type' in input)) args.type = body.kind;
  return args;
}
function jobArg(tool, id) {
  const props = tool?.inputSchema?.properties || {};
  if ('jobId' in props) return { jobId: id };
  if ('job_id' in props) return { job_id: id };
  if ('id' in props) return { id };
  return { jobId: id };
}

async function uploadAsset(token, body) {
  if (!body?.data || !body?.name) throw new Error('image_data_required');
  const match = String(body.data).match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) throw new Error('invalid_image_data');
  const type = match[1] || 'image/jpeg';
  if (!type.startsWith('image/')) throw new Error('image_file_required');
  const bytes = Buffer.from(match[2], 'base64');
  if (!bytes.length) throw new Error('empty_image');
  if (bytes.length > MAX_UPLOAD_BYTES) throw new Error('Prepared image is still too large. Please choose a smaller image.');

  const form = new FormData();
  form.append('file', new Blob([bytes], { type }), String(body.name).slice(0, 120));
  form.append('description', 'Chatty Creator Studio start/reference image');
  const r = await fetch(`${API_BASE}/assets`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form });
  const raw = await r.text();
  let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw }; }
  if (!r.ok) throw new Error(`Krea image upload failed (${r.status}): ${data?.message || data?.error || raw || 'unknown error'}`);
  const url = pickUrl(data);
  if (!url) throw new Error('Krea uploaded the image but did not return a reusable asset URL.');
  return { url, asset: data };
}

export default async function handler(req, res) {
  const url = new URL(req.url, 'https://local.invalid');
  const action = url.searchParams.get('action') || 'status';
  try {
    if (action === 'start') return startAuth(req, res);
    if (action === 'callback') return callback(req, res, url);
    if (action === 'disconnect') { res.setHeader('set-cookie', [clearCookie(TOKEN_COOKIE), clearCookie(FLOW_COOKIE)]); return send(res, 200, { ok: true }); }
    if (action === 'status') { const s = tokenState(req); return send(res, 200, { connected: Boolean(s), expiresAt: s?.expires_at || null }); }

    const auth = await accessToken(req);
    if (!auth.token) return send(res, 401, { error: 'not_connected' });
    if (auth.cookie) res.setHeader('set-cookie', auth.cookie);

    if (action === 'models') {
      const result = await withKrea(auth.token, c => rawCallTool(c, 'list_models', {}));
      return send(res, 200, payload(result));
    }
    if (action === 'schema') {
      const model = url.searchParams.get('model');
      if (!model) return send(res, 400, { error: 'model_required' });
      const result = await withKrea(auth.token, c => rawCallTool(c, 'get_model_schema', { model }));
      return send(res, 200, payload(result));
    }
    if (action === 'upload') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
      return send(res, 200, await uploadAsset(auth.token, await readBody(req)));
    }
    if (action === 'job') {
      const id = url.searchParams.get('id');
      if (!id) return send(res, 400, { error: 'id_required' });
      const result = await withKrea(auth.token, async c => {
        const listed = await c.listTools();
        const tool = (listed.tools || []).find(t => t.name === 'get_job');
        if (!tool) throw new Error('Krea get_job tool is unavailable');
        return rawCallTool(c, 'get_job', jobArg(tool, id));
      });
      return send(res, 200, payload(result));
    }
    if (action === 'generate') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
      const body = await readBody(req);
      if (!['image', 'video'].includes(body.kind) || !body.model || !body.prompt) return send(res, 400, { error: 'kind_model_prompt_required' });
      if (body.kind === 'video' && /topaz|upscale|enhanc|interpol/i.test(body.model)) throw new Error('That entry is a video utility, not a generator. Choose a video generation model.');
      const data = await withKrea(auth.token, async c => {
        const listed = await c.listTools();
        const tool = chooseGenerateTool(listed.tools || [], body.kind);
        if (!tool) throw new Error(`No ${body.kind} generation tool is exposed by Krea right now`);
        const enriched = await enrichModelOptions(c, body);
        const args = buildArgs(tool, enriched);
        const result = requireToolSuccess(await rawCallTool(c, tool.name, args));
        return { tool: tool.name, options: enriched.options, referenceField: enriched.referenceField, result: payload(result) };
      });
      return send(res, 200, data);
    }
    return send(res, 404, { error: 'unknown_action' });
  } catch (e) {
    if (action === 'start' || action === 'callback') {
      res.statusCode = 302;
      res.setHeader('location', `/?auth_error=${encodeURIComponent(e.message)}`);
      return res.end();
    }
    return send(res, 502, { error: e.message });
  }
}
