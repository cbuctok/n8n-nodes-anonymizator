/**
 * Drives the built node through a real n8n in Docker over n8n's REST API.
 *
 * `scripts/smoke.mjs` calls the node with a fake context, so it cannot see n8n's parameter
 * resolution (expressions in json parameters, collections, credentials hidden by displayOptions,
 * the CUSTOM. type prefix). This script imports `e2e/anonymizator-e2e.workflow.json` into the
 * Docker n8n, runs it and checks every node's output, so those failures are reproducible without a
 * browser. The workflow's Code nodes assert each branch and throw when a branch is wrong.
 *
 * Usage:
 *   npm run build
 *   npm run n8n:reset             a fresh volume; reuse only for debugging
 *   npm run e2e
 *   docker compose logs n8n | grep 'Running node'
 *
 * Environment:
 *   ANON_API_KEY      the gateway key; falls back to ANON_API_KEY=... in .env.dev. Never printed.
 *   N8N_BASE_URL      default http://localhost:5678
 *   N8N_EMAIL / N8N_PASSWORD   owner account, created on a fresh instance
 *   KEEP_WORKFLOW=1   keep the imported workflow (and its execution) for inspection in the editor
 *
 * Exit status is 0 only when every node in the workflow ran, produced items and none failed. Still
 * confirm with the container log: a node that is never reached leaves no trace in the API either.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.N8N_BASE_URL ?? 'http://localhost:5678';
const EMAIL = process.env.N8N_EMAIL ?? 'admin@example.com';
const PASSWORD = process.env.N8N_PASSWORD ?? 'AnonymizatorTest123!';
const NODE_TYPE = 'CUSTOM.anonymizator';
const CREDENTIAL_TYPE = 'anonymizatorApi';
const CREDENTIAL_NAME = 'Anonymizator API';
const WORKFLOW_FILE = resolve(here, '../e2e/anonymizator-e2e.workflow.json');

function loadApiKey() {
	if (process.env.ANON_API_KEY) return process.env.ANON_API_KEY.trim();
	try {
		const line = readFileSync(resolve(here, '../.env.dev'), 'utf8')
			.split('\n')
			.find((entry) => entry.startsWith('ANON_API_KEY='));
		if (!line) return undefined;
		return line
			.slice('ANON_API_KEY='.length)
			.trim()
			.replace(/^(['"])(.*)\1$/, '$2');
	} catch {
		return undefined;
	}
}

const apiKey = loadApiKey();
if (!apiKey) {
	console.error('Set ANON_API_KEY, or put ANON_API_KEY=... in .env.dev');
	process.exit(1);
}

/** Never let the key reach the console, whatever a response contains. */
function redact(value) {
	const text = typeof value === 'string' ? value : JSON.stringify(value);
	return (text === undefined ? String(value) : text).split(apiKey).join('<redacted>');
}
const log = (...parts) => console.log(parts.map((p) => redact(p)).join(' '));

let failures = 0;
function check(ok, label, detail = '') {
	if (!ok) failures++;
	log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  ${detail}` : ''}`);
	return ok;
}

async function req(path, { method = 'GET', body, cookie, raw = false } = {}) {
	const res = await fetch(`${BASE}${path}`, {
		method,
		headers: {
			'Content-Type': 'application/json',
			...(cookie ? { Cookie: cookie } : {}),
		},
		...(body === undefined ? {} : { body: JSON.stringify(body) }),
	});
	if (raw) {
		return {
			status: res.status,
			type: res.headers.get('content-type') ?? '',
			text: await res.text(),
		};
	}
	const text = await res.text();
	let data;
	try {
		data = JSON.parse(text);
	} catch {
		data = text;
	}
	return { status: res.status, data, setCookie: res.headers.getSetCookie?.() ?? [] };
}

/** Creates the first owner account, or logs in when one already exists. */
async function authenticate() {
	const login = await req('/rest/login', {
		method: 'POST',
		body: { emailOrLdapLoginId: EMAIL, password: PASSWORD },
	});
	if (login.status === 200 && login.setCookie.length) {
		return login.setCookie.map((c) => c.split(';')[0]).join('; ');
	}

	const setup = await req('/rest/owner/setup', {
		method: 'POST',
		body: { email: EMAIL, firstName: 'Test', lastName: 'Owner', password: PASSWORD },
	});
	if (setup.status === 200 && setup.setCookie.length) {
		return setup.setCookie.map((c) => c.split(';')[0]).join('; ');
	}

	throw new Error(`Could not authenticate: login ${login.status}, setup ${setup.status}`);
}

/**
 * n8n stores execution data with `flatted`: one array where every object and string lives at an
 * index and references are index strings. Resolves it back into a plain tree.
 */
function unflatten(serialized) {
	const table = JSON.parse(serialized);
	const done = new Map();
	const resolveAt = (index) => {
		const value = table[index];
		if (typeof value !== 'object' || value === null) return value;
		if (done.has(index)) return done.get(index);
		const out = Array.isArray(value) ? [] : {};
		done.set(index, out);
		for (const [k, v] of Object.entries(value)) {
			out[k] = typeof v === 'string' ? resolveAt(Number(v)) : v;
		}
		return out;
	};
	return resolveAt(0);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const cookie = await authenticate();
log('authenticated as', EMAIL);

// --- The node as n8n loaded it -------------------------------------------------------------
// The editor reads node descriptions from /types/nodes.json; checking it proves the package loaded
// from the custom folder, that Reveal shows no credential, and that both icons are served.
{
	const types = await req('/types/nodes.json', { cookie });
	const all = Array.isArray(types.data) ? types.data : [];
	const node = all.find((t) => t.name === NODE_TYPE);
	if (!check(Boolean(node), `node type ${NODE_TYPE} is loaded`, `(${all.length} types listed)`)) {
		log(
			'Is dist/ built, and was n8n started after the build? Try npm run build && npm run n8n:reset.',
		);
		process.exit(1);
	}
	const toolVariant = all.find((t) => t.name === `${NODE_TYPE}Tool`);
	check(Boolean(toolVariant), `AI tool variant ${NODE_TYPE}Tool is loaded`);

	const creds = node.credentials ?? [];
	const anonCred = creds.find((c) => c.name === CREDENTIAL_TYPE);
	const shownFor = anonCred?.displayOptions?.show?.operation;
	check(
		creds.length === 1 && JSON.stringify(shownFor) === '["protect"]',
		'credential is shown only for Protect (Reveal needs none)',
		JSON.stringify(creds.map((c) => ({ name: c.name, show: c.displayOptions?.show }))),
	);

	const icons = node.iconUrl ?? {};
	for (const theme of ['light', 'dark']) {
		const url = typeof icons === 'string' ? icons : icons[theme];
		if (!check(typeof url === 'string', `node ${theme} iconUrl present`, String(url))) continue;
		const icon = await req(`/${url.replace(/^\//, '')}`, { cookie, raw: true });
		check(
			icon.status === 200 && icon.text.includes('<svg'),
			`node ${theme} icon is served`,
			`${icon.status} ${icon.type}`,
		);
	}
	check(
		typeof icons === 'object' && icons.light !== icons.dark,
		'light and dark node icons differ',
	);

	const credTypes = await req('/types/credentials.json', { cookie });
	const credType = (Array.isArray(credTypes.data) ? credTypes.data : []).find(
		(t) => t.name === CREDENTIAL_TYPE,
	);
	check(Boolean(credType), `credential type ${CREDENTIAL_TYPE} is loaded`);
	const credIcon = credType?.iconUrl;
	const credIconUrl = typeof credIcon === 'string' ? credIcon : credIcon?.light;
	if (check(typeof credIconUrl === 'string', 'credential iconUrl present', String(credIconUrl))) {
		const icon = await req(`/${credIconUrl.replace(/^\//, '')}`, { cookie, raw: true });
		check(
			icon.status === 200 && icon.text.includes('<svg'),
			'credential icon is served',
			`${icon.status}`,
		);
	}
}

// --- Ensure the credential exists ----------------------------------------------------------
let credentialId;
{
	const list = await req('/rest/credentials', { cookie });
	credentialId = (list.data?.data ?? []).find((c) => c.type === CREDENTIAL_TYPE)?.id;
	if (!credentialId) {
		const created = await req('/rest/credentials', {
			method: 'POST',
			cookie,
			body: { name: CREDENTIAL_NAME, type: CREDENTIAL_TYPE, data: { apiKey } },
		});
		if (created.status !== 200) {
			throw new Error(
				`credential create failed: ${created.status} ${redact(created.data).slice(0, 300)}`,
			);
		}
		credentialId = created.data.data.id;
		log('credential created:', credentialId);
	} else {
		log('credential reused:', credentialId);
	}

	// The credential test the editor's "Test" button runs, sent the way the editor sends it: with
	// the redacted data from GET ?includeData=true. n8n only restores stored values for fields that
	// carry the blanking sentinel, so sending `data: {}` would test an empty key and fail.
	const stored = await req(`/rest/credentials/${credentialId}?includeData=true`, { cookie });
	const tested = await req('/rest/credentials/test', {
		method: 'POST',
		cookie,
		body: {
			credentials: {
				id: credentialId,
				name: CREDENTIAL_NAME,
				type: CREDENTIAL_TYPE,
				data: stored.data?.data?.data ?? {},
			},
		},
	});
	const result = tested.data?.data ?? tested.data;
	check(
		result?.status === 'OK',
		'credential test (editor Test button) passes',
		redact(result).slice(0, 200),
	);
}

// --- Import and run the workflow -------------------------------------------------------------
const workflow = JSON.parse(readFileSync(WORKFLOW_FILE, 'utf8'));
for (const node of workflow.nodes) {
	if (node.credentials?.[CREDENTIAL_TYPE]) {
		node.credentials[CREDENTIAL_TYPE] = { id: credentialId, name: CREDENTIAL_NAME };
	}
}
const expectedNodes = workflow.nodes.map((n) => n.name);

const created = await req('/rest/workflows', { method: 'POST', cookie, body: workflow });
if (created.status !== 200) {
	throw new Error(
		`workflow create failed: ${created.status} ${redact(created.data).slice(0, 400)}`,
	);
}
const saved = created.data.data;
log('workflow created:', saved.id);

const run = await req(`/rest/workflows/${saved.id}/run`, {
	method: 'POST',
	cookie,
	body: { workflowData: saved, triggerToStartFrom: { name: 'Start' } },
});
const executionId = run.data?.data?.executionId ?? run.data?.data?.id;
if (!executionId) {
	log('run response:', run.status, redact(run.data).slice(0, 400));
	process.exit(1);
}
log('execution started:', executionId);

let execution;
for (let attempt = 0; attempt < 80; attempt++) {
	const got = await req(`/rest/executions/${executionId}`, { cookie });
	execution = got.data?.data;
	if (execution?.status && !['running', 'new', 'waiting'].includes(execution.status)) break;
	await sleep(1500);
}
const data = typeof execution?.data === 'string' ? unflatten(execution.data) : execution?.data;
const runData = data?.resultData?.runData ?? {};
const topError = data?.resultData?.error;

check(
	execution?.status === 'success',
	`execution ${executionId} status`,
	String(execution?.status),
);
if (topError) log('  workflow error:', topError.message, topError.node?.name ?? '');

// Every node must have run once, without error, and produced at least one item. A node that returns
// no items ends its branch silently, so a missing downstream node is the signal to look for.
for (const name of expectedNodes) {
	const runs = runData[name];
	if (!runs) {
		check(false, `node ran: ${name}`, 'never executed');
		continue;
	}
	const last = runs[runs.length - 1];
	const items = last?.data?.main?.[0] ?? [];
	if (last?.error) {
		check(
			false,
			`node ran: ${name}`,
			`error: ${last.error.message} ${last.error.description ?? ''}`,
		);
		continue;
	}
	check(items.length > 0, `node ran: ${name}`, `${items.length} item(s)`);
	if (name.startsWith('Check')) log(`      ${redact(items[0]?.json ?? {}).slice(0, 300)}`);
}

if (process.env.KEEP_WORKFLOW === '1') {
	log(`kept workflow ${saved.id}: ${BASE}/workflow/${saved.id}`);
} else {
	// n8n 2.x only deletes archived workflows.
	await req(`/rest/workflows/${saved.id}/archive`, { method: 'POST', cookie });
	const removed = await req(`/rest/workflows/${saved.id}`, { method: 'DELETE', cookie });
	log(`workflow ${saved.id} deleted: HTTP ${removed.status} (KEEP_WORKFLOW=1 keeps it)`);
	// The credential holds the real API key; do not leave it in the volume between runs.
	const dropped = await req(`/rest/credentials/${credentialId}`, { method: 'DELETE', cookie });
	log(`credential ${credentialId} deleted: HTTP ${dropped.status} (KEEP_WORKFLOW=1 keeps it)`);
}

log('');
log('Confirm node coverage in the container log:');
log("  docker compose logs n8n | grep 'Running node'");
log(failures === 0 ? 'E2E PASS' : `E2E FAIL (${failures} check(s) failed)`);
process.exit(failures === 0 ? 0 : 1);
