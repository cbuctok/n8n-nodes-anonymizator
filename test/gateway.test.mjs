// gateway.ts against a fake n8n context whose httpRequestWithAuthentication is a fake HPKE
// recipient gateway (keyconfig signed by an in-test Ed25519 root + sealed /v1/analyze).
// The recipient below is an independent RFC 9180 open written with node:crypto for this test.
import assert from 'node:assert/strict';
import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	sign,
} from 'node:crypto';
import { createRequire } from 'node:module';
import { beforeEach, describe, it } from 'node:test';

const require = createRequire(import.meta.url);
const G = require('../dist/nodes/Anonymizator/shared/gateway.js');
const { GatewayError } = require('../dist/nodes/Anonymizator/shared/errors.js');

// ── Minimal HPKE recipient (Base mode, X25519/HKDF-SHA256/AES-256-GCM) ─────────────────────
const SUITE_ID = Buffer.from('48504b45002000010002', 'hex');
const KEM_ID = Buffer.from('4b454d0020', 'hex');
const V1 = Buffer.from('HPKE-v1');
const hmac = (k, d) =>
	createHmac('sha256', k.length ? k : Buffer.alloc(32))
		.update(d)
		.digest();
function expand(prk, info, L) {
	const out = Buffer.alloc(L);
	let t = Buffer.alloc(0);
	for (let i = 1, done = 0; done < L; i++, done += 32) {
		t = hmac(prk, Buffer.concat([t, info, Buffer.from([i])]));
		t.copy(out, done, 0, Math.min(32, L - done));
	}
	return out;
}
const lExtract = (sid, salt, label, ikm) =>
	hmac(salt, Buffer.concat([V1, sid, Buffer.from(label), ikm]));
const lExpand = (sid, prk, label, info, L) =>
	expand(
		prk,
		Buffer.concat([Buffer.from([L >> 8, L & 255]), V1, sid, Buffer.from(label), info]),
		L,
	);
const empty = Buffer.alloc(0);

function x25519Pair() {
	const pair = generateKeyPairSync('x25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	return { pk: Buffer.from(spki.subarray(spki.length - 32)), privateKey: pair.privateKey };
}

function openRequest(server, frame) {
	if (frame[0] !== 1) throw new Error('bad version');
	const prefix = frame.subarray(0, 13);
	const keyId = frame.readUInt32BE(1);
	const enc = frame.subarray(13, 45);
	const ct = frame.subarray(45);
	const encKey = createPublicKey({
		key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), enc]),
		format: 'der',
		type: 'spki',
	});
	const dh = diffieHellman({ privateKey: server.privateKey, publicKey: encKey });
	const ss = lExpand(
		KEM_ID,
		lExtract(KEM_ID, empty, 'eae_prk', dh),
		'shared_secret',
		Buffer.concat([enc, server.pk]),
		32,
	);
	const ksc = Buffer.concat([
		Buffer.from([0]),
		lExtract(SUITE_ID, empty, 'psk_id_hash', empty),
		lExtract(SUITE_ID, empty, 'info_hash', empty),
	]);
	const secret = lExtract(SUITE_ID, ss, 'secret', empty);
	const key = lExpand(SUITE_ID, secret, 'key', ksc, 32);
	const nonce = lExpand(SUITE_ID, secret, 'base_nonce', ksc, 12);
	const exp = lExpand(SUITE_ID, secret, 'exp', ksc, 32);
	const d = createDecipheriv('aes-256-gcm', key, nonce);
	d.setAAD(prefix);
	d.setAuthTag(ct.subarray(ct.length - 16));
	const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
	return {
		keyId,
		ptLength: pt.length,
		payload: JSON.parse(pt.toString('utf8').trimEnd()),
		sealResponse(obj) {
			const kn = lExpand(SUITE_ID, exp, 'sec', Buffer.from('pgw response v1'), 44);
			const c = createCipheriv('aes-256-gcm', kn.subarray(0, 32), kn.subarray(32));
			c.setAAD(empty);
			const json = JSON.stringify(obj);
			const body = Buffer.concat([
				c.update(json + ' '.repeat(256 - (json.length % 256))),
				c.final(),
				c.getAuthTag(),
			]);
			return Buffer.concat([Buffer.from([1]), body]);
		},
	};
}

// ── Fake gateway ───────────────────────────────────────────────────────────────────────────
function ed25519Root() {
	const pair = generateKeyPairSync('ed25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	return {
		root: Buffer.from(spki.subarray(spki.length - 32)).toString('base64url'),
		privateKey: pair.privateKey,
	};
}
const ROOT = ed25519Root();
const OTHER_ROOT = ed25519Root();

const json = (obj, statusCode = 200) => ({
	statusCode,
	headers: { 'content-type': 'application/json; charset=utf-8' },
	body: Buffer.from(JSON.stringify(obj)),
});
const sealedBody = (buf, statusCode = 200) => ({
	statusCode,
	headers: { 'Content-Type': 'application/octet-stream' },
	body: buf,
});

// Production reports code-point offsets (Python); emulate that so the R7 sanitising is exercised.
const PII = { 'Janez Novak': 'PERSON', 'ana.kovac@example.com': 'EMAIL_ADDRESS' };
function detect(text) {
	const out = [];
	for (const [real, type] of Object.entries(PII)) {
		for (let at = text.indexOf(real); at !== -1; at = text.indexOf(real, at + real.length)) {
			const start = [...text.slice(0, at)].length;
			out.push({ entity_type: type, start, end: start + [...real].length, score: 0.85 });
		}
	}
	// Production does not sort; return reversed to prove the client copes.
	return out.sort((a, b) => b.start - a.start);
}

function makeGateway({ keyId = 7, signer = ROOT.privateKey, rejectEntities = false } = {}) {
	const gw = {
		server: { ...x25519Pair(), keyId },
		signer,
		rejectEntities, // false | 'sealed' | 'plain'
		overrides: [], // FIFO of { path, respond(opts) }
		calls: [],
		payloads: [],
		unknownKeyAlways: false,
		responseSpans: undefined,
		rotate(newKeyId) {
			this.server = { ...x25519Pair(), keyId: newKeyId };
		},
		keyconfig() {
			const keys = [
				{
					key_id: this.server.keyId,
					public_key: this.server.pk.toString('base64url'),
					suite: { kem: 32, kdf: 1, aead: 2 },
					not_after: '2030-01-01T00:00:00Z',
				},
			];
			const msg = 'pgw-keyconfig-v1\n' + keys.map((k) => `${k.key_id}:${k.public_key}\n`).join('');
			return {
				version: 1,
				keys,
				sig_alg: 'ed25519-v1',
				signature: sign(null, Buffer.from(msg), this.signer).toString('base64url'),
			};
		},
		handle(opts) {
			const path = new URL(opts.url).pathname;
			const i = this.overrides.findIndex((o) => o.path === path);
			if (i !== -1) {
				const [o] = this.overrides.splice(i, 1);
				return o.respond(opts);
			}
			if (path === '/v1/keyconfig' && opts.method === 'GET') return json(this.keyconfig());
			if (path === '/v1/analyze' && opts.method === 'POST') {
				if (!Buffer.isBuffer(opts.body)) return json({ error: 'hpke_required' }, 415);
				// Like the real gateway: look the key_id up before trying to open the frame.
				if (opts.body.readUInt32BE(1) !== this.server.keyId || this.unknownKeyAlways) {
					return json({ error: 'hpke_unknown_key' }, 400);
				}
				let opened;
				try {
					opened = openRequest(this.server, opts.body);
				} catch {
					return json({ error: 'hpke_open_failed' }, 400);
				}
				this.payloads.push(opened.payload);
				if (this.rejectEntities && opened.payload.entities !== undefined) {
					const err = { error: 'invalid_entities', detail: 'unknown entities: NOT_A_TYPE' };
					return this.rejectEntities === 'sealed'
						? sealedBody(opened.sealResponse(err), 400)
						: json(err, 400);
				}
				const entities = this.responseSpans ?? detect(opened.payload.text);
				return sealedBody(opened.sealResponse({ entities }));
			}
			return json({}, 404);
		},
	};
	gw.ctx = {
		getNode: () => ({ name: 'Anonymizator' }),
		helpers: {
			async httpRequestWithAuthentication(credentialName, opts) {
				assert.equal(this, gw.ctx, 'helper must be called with ctx as this');
				gw.calls.push({ credentialName, ...opts, path: new URL(opts.url).pathname });
				return gw.handle(opts);
			},
		},
	};
	gw.count = (path) => gw.calls.filter((c) => c.path === path).length;
	return gw;
}

const OPTS = { trustRootB64url: ROOT.root, retryDelayMs: 0 };
const TEXT = '😀😀 Janez Novak, ana.kovac@example.com';

async function rejectsWith(promise, code, httpCode) {
	await assert.rejects(promise, (error) => {
		assert.ok(error instanceof GatewayError, `expected GatewayError, got ${error}`);
		assert.equal(error.code, code);
		if (httpCode !== undefined) assert.equal(error.httpCode, httpCode);
		assert.ok(error.message.length > 0);
		return true;
	});
}

beforeEach(() => G.clearKeyconfigCache());

describe('sanitizeForOffsets', () => {
	it('replaces each surrogate code unit with one space', () => {
		const out = G.sanitizeForOffsets(TEXT);
		assert.equal(out.length, TEXT.length);
		assert.equal([...out].length, TEXT.length);
		assert.equal(/[\uD800-\uDFFF]/.test(out), false);
		assert.equal(out.slice(0, 5), '     ');
		assert.equal(G.sanitizeForOffsets('a\uD800b'), 'a b');
		assert.equal(G.sanitizeForOffsets('Janez Novak'), 'Janez Novak');
	});
});

describe('analyze: happy path', () => {
	it('returns spans that index the original text (emoji before a name)', async () => {
		const gw = makeGateway();
		const result = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(result.entityFilterIgnored, false);
		assert.deepEqual(
			result.spans.map((s) => [s.entity_type, TEXT.slice(s.start, s.end), s.score]),
			[
				['PERSON', 'Janez Novak', 0.85],
				['EMAIL_ADDRESS', 'ana.kovac@example.com', 0.85],
			],
		);
	});

	it('sends what the extension sends, through the n8n helper with the right options', async () => {
		const gw = makeGateway();
		await G.analyze(gw.ctx, TEXT, undefined, { ...OPTS, nowSeconds: 1_700_000_000 });
		assert.deepEqual(
			gw.calls.map((c) => `${c.method} ${c.url}`),
			[
				'GET https://anon.prosecco37.com/v1/keyconfig',
				'POST https://anon.prosecco37.com/v1/analyze',
			],
		);
		for (const call of gw.calls) {
			assert.equal(call.credentialName, 'anonymizatorApi');
			assert.equal(call.disableFollowRedirect, true);
			assert.equal(call.ignoreHttpStatusErrors, true);
			assert.equal(call.returnFullResponse, true);
			assert.equal(call.encoding, 'arraybuffer');
			assert.equal(call.json, false);
			assert.ok(call.timeout > 0);
		}
		assert.equal(gw.calls[0].body, undefined);
		// Accept: application/json is what makes the BFF answer a bad key with 401 instead of a
		// 302 to its login page.
		assert.equal(gw.calls[0].headers.Accept, 'application/json');
		const post = gw.calls[1];
		assert.ok(Buffer.isBuffer(post.body));
		assert.equal(post.headers['Content-Type'], 'application/octet-stream');
		assert.match(post.headers.Accept, /application\/octet-stream/);
		assert.match(post.headers.Accept, /application\/json/);
		assert.equal(post.body.readUInt32BE(1), 7);
		assert.equal(post.body.readBigUInt64BE(5), BigInt(1_700_000_000));
		const latin1 = post.body.toString('latin1');
		assert.equal(latin1.includes('Janez'), false);
		assert.equal(latin1.includes('example.com'), false);
		// payload: { text } only, sanitised, padded to a bucket
		assert.deepEqual(Object.keys(gw.payloads[0]), ['text']);
		assert.equal(gw.payloads[0].text, G.sanitizeForOffsets(TEXT));
	});

	it('omits entities when undefined or empty, sends them when given', async () => {
		const gw = makeGateway();
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		await G.analyze(gw.ctx, TEXT, [], OPTS);
		await G.analyze(gw.ctx, TEXT, ['PERSON', 'IBAN', 'IBAN_CODE'], OPTS);
		assert.equal('entities' in gw.payloads[0], false);
		assert.equal('entities' in gw.payloads[1], false);
		assert.deepEqual(gw.payloads[2].entities, ['PERSON', 'IBAN', 'IBAN_CODE']);
	});

	it('caches the keyconfig between calls; clearKeyconfigCache refetches', async () => {
		const gw = makeGateway();
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(gw.count('/v1/keyconfig'), 1);
		G.clearKeyconfigCache();
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});

	it('the keyconfig cache expires after KEYCONFIG_TTL_MS', async (t) => {
		const gw = makeGateway();
		const realNow = Date.now();
		t.mock.method(Date, 'now', () => realNow);
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		Date.now.mock.mockImplementation(() => realNow + G.KEYCONFIG_TTL_MS - 1);
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(gw.count('/v1/keyconfig'), 1);
		Date.now.mock.mockImplementation(() => realNow + G.KEYCONFIG_TTL_MS + 1);
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});

	it('the keyconfig cache is keyed by trust root', async () => {
		const gw = makeGateway();
		await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		// A keyconfig cached under ROOT must not be used, unverified, under another root.
		await rejectsWith(
			G.analyze(gw.ctx, TEXT, undefined, { ...OPTS, trustRootB64url: OTHER_ROOT.root }),
			'hpke_unverified_keyconfig',
		);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});

	it('fetchKeyconfig returns the verified document and honours force', async () => {
		const gw = makeGateway();
		const cfg = await G.fetchKeyconfig(gw.ctx, false, OPTS);
		assert.equal(cfg.keys[0].key_id, 7);
		await G.fetchKeyconfig(gw.ctx, false, OPTS);
		await G.fetchKeyconfig(gw.ctx, true, OPTS);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});

	it('drops malformed and out-of-range spans, sorts by start', async () => {
		const gw = makeGateway();
		gw.responseSpans = [
			{ entity_type: 'EMAIL_ADDRESS', start: 18, end: 39 },
			{ entity_type: 'PERSON', start: 5, end: 16, score: 0.5 },
			{ entity_type: 'PERSON', start: 5, end: 999 },
			{ entity_type: 'PERSON', start: -1, end: 3 },
			{ entity_type: 'PERSON', start: 4, end: 4 },
			{ entity_type: '', start: 1, end: 3 },
			{ entity_type: 'PERSON', start: '1', end: 3 },
			{ entity_type: 'PERSON', start: 1.5, end: 3 },
			null,
		];
		const { spans } = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.deepEqual(spans, [
			{ entity_type: 'PERSON', start: 5, end: 16, score: 0.5 },
			{ entity_type: 'EMAIL_ADDRESS', start: 18, end: 39 },
		]);
	});
});

describe('analyze: span edges', () => {
	it('trims whitespace and surrogate stand-ins so a span never splits an emoji', async () => {
		const gw = makeGateway();
		// TEXT = '😀😀 Janez Novak, ...': code units 0-3 are surrogates, 4 is a space.
		gw.responseSpans = [
			{ entity_type: 'PERSON', start: 1, end: 16 },
			{ entity_type: 'PERSON', start: 0, end: 4 },
			{ entity_type: 'EMAIL_ADDRESS', start: 17, end: 39 },
		];
		const { spans } = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.deepEqual(
			spans.map((s) => TEXT.slice(s.start, s.end)),
			['Janez Novak', 'ana.kovac@example.com'],
		);
	});
});

describe('analyze: retries', () => {
	it('after a key rotation, a filter retry reuses the fresh keyconfig', async () => {
		const gw = makeGateway({ keyId: 7, rejectEntities: 'sealed' });
		await G.fetchKeyconfig(gw.ctx, false, OPTS); // cache key 7
		gw.rotate(8);
		const result = await G.analyze(gw.ctx, TEXT, ['PERSON'], OPTS);
		assert.equal(result.entityFilterIgnored, true);
		assert.deepEqual(
			gw.calls.map((c) => c.path),
			['/v1/keyconfig', '/v1/analyze', '/v1/keyconfig', '/v1/analyze', '/v1/analyze'],
		);
	});

	it('hpke_unknown_key: refetches the keyconfig and reseals exactly once', async () => {
		const gw = makeGateway({ keyId: 7 });
		await G.fetchKeyconfig(gw.ctx, false, OPTS); // cache key 7
		gw.rotate(8);
		const result = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(result.spans.length, 2);
		assert.deepEqual(
			gw.calls.map((c) => c.path),
			['/v1/keyconfig', '/v1/analyze', '/v1/keyconfig', '/v1/analyze'],
		);
		assert.equal(gw.calls[3].body.readUInt32BE(1), 8);
	});

	it('hpke_unknown_key twice: gives up after one reseal', async () => {
		const gw = makeGateway();
		gw.unknownKeyAlways = true;
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_unknown_key', 400);
		assert.equal(gw.count('/v1/analyze'), 2);
	});

	for (const mode of ['sealed', 'plain']) {
		it(`${mode} invalid_entities with a filter: retries once without it`, async () => {
			const gw = makeGateway({ rejectEntities: mode });
			const result = await G.analyze(gw.ctx, TEXT, ['NOT_A_TYPE'], OPTS);
			assert.equal(result.entityFilterIgnored, true);
			assert.equal(result.spans.length, 2);
			assert.equal(gw.count('/v1/analyze'), 2);
			assert.deepEqual(gw.payloads[0].entities, ['NOT_A_TYPE']);
			assert.equal('entities' in gw.payloads[1], false);
		});
	}

	it('invalid_entities without a filter is an error, no retry', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => json({ error: 'invalid_entities' }, 400),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'invalid_entities', 400);
		assert.equal(gw.count('/v1/analyze'), 1);
	});

	it('5xx on analyze: retried once with a fresh seal', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => ({
				statusCode: 502,
				headers: { 'content-type': 'text/plain' },
				body: Buffer.from('upstream error'),
			}),
		});
		const result = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(result.spans.length, 2);
		const posts = gw.calls.filter((c) => c.path === '/v1/analyze');
		assert.equal(posts.length, 2);
		assert.notDeepEqual(posts[0].body, posts[1].body);
	});

	it('5xx twice on analyze: server_error', async () => {
		const gw = makeGateway();
		const fail = { path: '/v1/analyze', respond: () => json({}, 503) };
		gw.overrides.push(fail, { ...fail });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'server_error', 503);
		assert.equal(gw.count('/v1/analyze'), 2);
	});

	it('5xx on a very large text: no retry, text_too_large that suggests splitting', async () => {
		const gw = makeGateway();
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({}, 502) });
		const big = 'Lorem ipsum. '.repeat(25000);
		await assert.rejects(G.analyze(gw.ctx, big, undefined, OPTS), (error) => {
			assert.equal(error.code, 'text_too_large');
			assert.equal(error.httpCode, 502);
			assert.match(error.message, /split/);
			return true;
		});
		assert.equal(gw.count('/v1/analyze'), 1);
	});

	it('5xx once on keyconfig: retried', async () => {
		const gw = makeGateway();
		gw.overrides.push({ path: '/v1/keyconfig', respond: () => json({}, 500) });
		const result = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(result.spans.length, 2);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});
});

describe('analyze: status mapping', () => {
	const redirect = () => ({
		statusCode: 302,
		headers: {
			location: '/auth/login?return_to=/v1/keyconfig',
			'content-type': 'text/html; charset=utf-8',
		},
		body: Buffer.from('<a href="/auth/login">Found</a>.'),
	});

	it('302 on keyconfig: rejected key', async () => {
		const gw = makeGateway();
		gw.overrides.push({ path: '/v1/keyconfig', respond: redirect });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'auth_required', 302);
		assert.equal(gw.count('/v1/analyze'), 0);
	});

	it('302 on analyze and 401: rejected key', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => ({ statusCode: 302, headers: {}, body: Buffer.alloc(0) }),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'auth_required', 302);
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({}, 401) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'auth_required', 401);
	});

	it('403 missing_role: no access; other 403: http_403', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/keyconfig',
			respond: () => json({ error: 'missing_role' }, 403),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'no_access', 403);
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({ error: 'missing_role' }, 403) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'no_access', 403);
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => ({
				statusCode: 403,
				headers: { 'content-type': 'text/html' },
				body: Buffer.from('<html>WAF</html>'),
			}),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'http_403', 403);
	});

	it('429: rate_limited, no retry; 413: text_too_large', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => ({ statusCode: 429, headers: { 'retry-after': '30' }, body: Buffer.alloc(0) }),
		});
		await assert.rejects(G.analyze(gw.ctx, TEXT, undefined, OPTS), (error) => {
			assert.equal(error.code, 'rate_limited');
			assert.match(error.message, /30 seconds/);
			return true;
		});
		assert.equal(gw.count('/v1/analyze'), 1);
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({}, 413) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'text_too_large', 413);
	});

	it('pre-open JSON errors keep their code (hpke_stale mentions the clock)', async () => {
		const gw = makeGateway();
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({ error: 'hpke_stale' }, 400) });
		await assert.rejects(G.analyze(gw.ctx, TEXT, undefined, OPTS), (error) => {
			assert.equal(error.code, 'hpke_stale');
			assert.match(error.message, /clock/);
			return true;
		});
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => json({ error: 'hpke_open_failed' }, 400),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_open_failed', 400);
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => json({ error: 'something_new' }, 400),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'http_400', 400);
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({}, 404) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'http_404', 404);
	});

	it('an unopenable sealed error falls back to http_<status>', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => sealedBody(Buffer.from([1, 2, 3, 4]), 400),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'http_400', 400);
	});
});

describe('analyze: keyconfig trust (fail closed)', () => {
	it('a keyconfig signed by another root is refused and never cached', async () => {
		const gw = makeGateway({ signer: OTHER_ROOT.privateKey });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_unverified_keyconfig');
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_unverified_keyconfig');
		assert.equal(gw.count('/v1/analyze'), 0);
		assert.equal(gw.count('/v1/keyconfig'), 2);
	});

	it('the production root refuses a test-signed keyconfig by default', async () => {
		const gw = makeGateway();
		await rejectsWith(G.analyze(gw.ctx, TEXT), 'hpke_unverified_keyconfig');
	});

	it('a swapped public key is refused', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/keyconfig',
			respond: () => {
				const cfg = gw.keyconfig();
				cfg.keys[0].public_key = x25519Pair().pk.toString('base64url');
				return json(cfg);
			},
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_unverified_keyconfig');
	});

	it('an HTML or malformed keyconfig is hpke_bad_keyconfig', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/keyconfig',
			respond: () => ({
				statusCode: 200,
				headers: { 'content-type': 'text/html' },
				body: Buffer.from('<html>login</html>'),
			}),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_bad_keyconfig');
		gw.overrides.push({ path: '/v1/keyconfig', respond: () => json({ keys: [] }) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_bad_keyconfig');
	});

	it('a signed keyconfig with the wrong suite is hpke_bad_keyconfig', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/keyconfig',
			respond: () => {
				const cfg = gw.keyconfig();
				cfg.keys[0].suite = { kem: 32, kdf: 1, aead: 1 }; // not covered by the signature
				return json(cfg);
			},
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_bad_keyconfig');
	});
});

describe('analyze: bad responses and transport failures', () => {
	it('a 200 that does not open is hpke_bad_response', async () => {
		const gw = makeGateway();
		gw.overrides.push({
			path: '/v1/analyze',
			respond: () => sealedBody(Buffer.concat([Buffer.from([1]), Buffer.alloc(64)])),
		});
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_bad_response', 200);
		gw.overrides.push({ path: '/v1/analyze', respond: () => json({ entities: [] }) });
		await rejectsWith(G.analyze(gw.ctx, TEXT, undefined, OPTS), 'hpke_bad_response', 200);
	});

	it('an ArrayBuffer response body is accepted', async () => {
		const gw = makeGateway();
		const original = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, opts) {
			const res = await original.call(this, name, opts);
			const ab = new ArrayBuffer(res.body.length);
			new Uint8Array(ab).set(res.body);
			return { ...res, body: ab };
		};
		const result = await G.analyze(gw.ctx, TEXT, undefined, OPTS);
		assert.equal(result.spans.length, 2);
	});

	const throwing = (error) => ({
		getNode: () => ({ name: 'Anonymizator' }),
		helpers: {
			httpRequestWithAuthentication: async () => {
				throw error;
			},
		},
	});

	it('timeouts and network errors map to timeout and offline', async () => {
		await rejectsWith(
			G.analyze(
				throwing(Object.assign(new Error('timeout of 30000ms exceeded'), { code: 'ECONNABORTED' })),
				TEXT,
				undefined,
				OPTS,
			),
			'timeout',
		);
		const wrapped = new Error('The service refused the connection - perhaps it is offline', {
			cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
		});
		wrapped.name = 'NodeApiError';
		await rejectsWith(G.analyze(throwing(wrapped), TEXT, undefined, OPTS), 'offline');
	});

	it("n8n's own NodeOperationError (e.g. missing credentials) passes through", async () => {
		const error = new Error(
			'Node "Anonymizator" does not have any credentials of type "anonymizatorApi" set',
		);
		error.name = 'NodeOperationError';
		await assert.rejects(
			G.analyze(throwing(error), TEXT, undefined, OPTS),
			(thrown) => thrown === error,
		);
	});
});
