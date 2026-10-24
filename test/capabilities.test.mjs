// Capabilities v1 tests against the compiled dist/ output: every case of the gateway's vectors
// (test/fixtures/pgw-capabilities-v1.json), the generated oversize documents, domain separation,
// fetchCapabilities through a fake gateway (cache, passive failures, serial floor read only) and a
// differential run against the extension's real lib/hpke.js verifyCapabilitiesV1.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { beforeEach, describe, it } from 'node:test';

import {
	CAPS_VECTORS as FILE,
	EXT_SKIP,
	VECTORS,
	ascii,
	b64url,
	capabilitiesText,
	ed25519Signer,
	json,
	loadExtHpke,
	makeFakeGateway,
	makeTrustChain,
} from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const C = require('../dist/nodes/Anonymizator/shared/capabilities.js');
const K = require('../dist/nodes/Anonymizator/shared/keyconfig.js');
const G = require('../dist/nodes/Anonymizator/shared/gateway.js');
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

const NODE = {
	name: 'Anonymizator',
	type: 'test',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

const PRIMARY = FILE.roots.primary.public_key;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** The parse in the vectors' `expected_parse` shape (labels flattened). */
function asJson(doc) {
	const labels = [];
	for (const [ref, byLang] of doc.labels)
		for (const [lang, text] of byLang) labels.push({ ref, lang, text });
	return {
		version: doc.version,
		issued_at: doc.issuedAt,
		server_version: doc.serverVersion,
		languages: doc.languages,
		label_languages: doc.labelLanguages,
		max_text_chars: doc.maxTextChars,
		max_body_bytes: doc.maxBodyBytes,
		features: doc.features,
		groups: doc.groups,
		entities: doc.entities,
		possible: doc.possible,
		labels,
	};
}

const verify = (response) =>
	C.verifyCapabilitiesV1(response, [PRIMARY], FILE.now, FILE.expected_audience);

describe('capabilities vectors (pgw-capabilities-v1.json)', () => {
	it('has the expected format and constants', () => {
		assert.equal(FILE.format, 'pgw-capabilities-v1-test-vectors-1');
		const c = FILE.constants;
		const L = C.CAPABILITIES_LIMITS;
		assert.equal(c.capabilities_max_age_s, L.MAX_AGE_S);
		assert.equal(c.client_skew_s, K.V2_LIMITS.CLIENT_SKEW_S);
		assert.equal(c.max_capabilities_bytes, L.MAX_BYTES);
		assert.equal(c.max_capabilities_b64, L.MAX_B64);
		assert.equal(c.max_document_b64, K.V2_LIMITS.MAX_DOCUMENT_B64);
		assert.equal(c.max_lines, L.MAX_LINES);
		assert.equal(c.max_groups, L.MAX_GROUPS);
		assert.equal(c.max_entities, L.MAX_ENTITIES);
		assert.equal(c.max_possible, L.MAX_POSSIBLE);
		assert.equal(c.max_languages, L.MAX_LANGUAGES);
		assert.equal(c.max_label_languages, L.MAX_LABEL_LANGUAGES);
		assert.equal(c.max_features, L.MAX_FEATURES);
		assert.equal(c.max_label_scalars, L.MAX_LABEL_SCALARS);
	});

	it('the documents are the b64 of their text and the signatures reproduce from the seeds', () => {
		const root = ed25519Signer(FILE.roots.primary.seed_hex);
		const delegated = ed25519Signer(FILE.delegated.seed_hex);
		assert.equal(root.publicKey, PRIMARY);
		assert.equal(delegated.publicKey, FILE.delegated.public_key);
		assert.equal(b64url(ascii(FILE.delegation.text)), FILE.delegation.b64);
		assert.equal(sha256(ascii(FILE.document.text)), FILE.document.sha256);
		assert.equal(b64url(delegated.sign(ascii(FILE.document.text))), FILE.document.signature);
		assert.equal(FILE.capabilities_json.v1.capabilities, b64url(ascii(FILE.document.text)));
	});

	it('the valid response parses to expected_parse', () => {
		const r = verify(FILE.capabilities_json);
		assert.equal(r.ok, true);
		assert.deepEqual(asJson(r.capabilities), FILE.expected_parse);
		assert.ok(r.capabilities.labels instanceof Map);
		assert.equal(r.serial, 1767139200);
		assert.equal(r.issuedAt, FILE.expected_parse.issued_at);
	});

	it(`runs all ${FILE.cases.length} cases`, () => {
		assert.ok(FILE.cases.length >= 75);
	});

	for (const c of FILE.cases) {
		it(`case ${c.name}`, () => {
			const r = C.verifyCapabilitiesV1(
				c.capabilities_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			if (c.expect.ok) {
				assert.equal(r.ok, true, JSON.stringify(r));
				assert.equal(r.serial, c.expect.ok.serial);
				assert.equal(r.issuedAt, c.expect.ok.issued_at);
				assert.deepEqual(
					r.capabilities.entities.map((e) => e.type),
					c.expect.ok.entity_types,
				);
				assert.deepEqual(
					r.capabilities.possible.map((p) => p.type),
					c.expect.ok.possible_types,
				);
				assert.deepEqual(r.capabilities.features, c.expect.ok.features);
				assert.deepEqual(
					r.capabilities.groups.map((g) => g.id),
					c.expect.ok.group_ids,
				);
			} else {
				assert.deepEqual(r, { ok: false, error: c.expect.error });
			}
		});
	}

	describe('generated oversize documents', () => {
		const delegated = ed25519Signer(FILE.delegated.seed_hex);
		const signed = (text) => {
			const bytes = ascii(text);
			return {
				v1: {
					...FILE.capabilities_json.v1,
					capabilities: b64url(bytes),
					capabilities_sig: b64url(delegated.sign(bytes)),
				},
			};
		};
		const ext = (n) => Array.from({ length: n }, (_, i) => `x${i}=1\n`).join('');
		const base = FILE.document.text;
		const lines = base.split('\n').length - 1;

		it('a 4096-line document with extension lines still verifies (the cap is inclusive)', () => {
			assert.equal(verify(signed(base + ext(4096 - lines))).ok, true);
		});

		it('4097 lines -> capabilities_unverified', () => {
			assert.deepEqual(verify(signed(base + ext(4097 - lines))), {
				ok: false,
				error: 'capabilities_unverified',
			});
		});

		it('a document over 49 152 bytes -> capabilities_unverified', () => {
			const filler = `zz=${'a'.repeat(200)}\n`;
			let text = base;
			while (ascii(text).length <= C.CAPABILITIES_LIMITS.MAX_BYTES) text += filler;
			assert.ok(text.split('\n').length - 1 <= 4096);
			assert.deepEqual(verify(signed(text)), { ok: false, error: 'capabilities_unverified' });
		});
	});

	it('domain separation: a keyconfig verifier refuses the capabilities response, and vice versa', () => {
		const v1 = FILE.capabilities_json.v1;
		const asKeyconfig = {
			v2: {
				delegation: v1.delegation,
				delegation_sig: v1.delegation_sig,
				keyconfig: v1.capabilities,
				keyconfig_sig: v1.capabilities_sig,
			},
		};
		assert.deepEqual(
			K.verifyKeyconfigV2(asKeyconfig, [PRIMARY], FILE.now, FILE.expected_audience),
			{
				ok: false,
				error: 'hpke_unverified_keyconfig',
			},
		);
		const kc = VECTORS.keyconfig_json.v2;
		const asCapabilities = {
			v1: {
				delegation: kc.delegation,
				delegation_sig: kc.delegation_sig,
				capabilities: kc.keyconfig,
				capabilities_sig: kc.keyconfig_sig,
			},
		};
		assert.deepEqual(verify(asCapabilities), { ok: false, error: 'capabilities_unverified' });
	});

	it('isCapabilitiesType refuses reserved shapes', () => {
		for (const t of ['PERSON', 'IBAN_CODE', 'IT_FISCAL_CODE'])
			assert.equal(C.isCapabilitiesType(t), true);
		for (const t of [
			'PII',
			'CUSTOM',
			'REDACTED',
			'TYPE',
			'X_NAME',
			'X_SURNAME',
			'PERSON_1',
			'person',
			1,
		]) {
			assert.equal(C.isCapabilitiesType(t), false, String(t));
		}
	});
});

describe('effectiveMaxTextChars', () => {
	it('bundled 10 000 (the floor) without a document, the plausible server value otherwise', () => {
		assert.equal(G.MAX_TEXT_CHARS, 10000);
		assert.equal(G.MAX_TEXT_CHARS, G.MIN_TEXT_CHARS, 'never above a cap the node accepts');
		assert.equal(G.effectiveMaxTextChars(null), 10000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 14000, maxBodyBytes: 1048576 }), 14000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 10000, maxBodyBytes: 1048576 }), 10000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 120000, maxBodyBytes: 1048576 }), 120000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 50000, maxBodyBytes: 1048576 }), 50000);
		// Body cap binds: floor((200000 - 8192) / 6) = 31968.
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 120000, maxBodyBytes: 200000 }), 31968);
		// Out of [10 000, 1 000 000]: the bundled value.
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 9999, maxBodyBytes: 1048576 }), 10000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 2e6, maxBodyBytes: 2e7 }), 10000);
		assert.equal(G.effectiveMaxTextChars({ maxTextChars: 1.5, maxBodyBytes: 1048576 }), 10000);
	});
});

describe('fetchCapabilities (fake gateway)', () => {
	const now = 1_800_000_000;
	beforeEach(() => G.clearGatewayCaches());

	function setup({
		capabilities,
		text = capabilitiesText(now - 60),
		chain = makeTrustChain(),
		...rest
	} = {}) {
		const doc = chain.capabilities({ now, text });
		const gw = makeFakeGateway({
			now,
			chain,
			capabilities: capabilities ?? (() => json(200, doc)),
			...rest,
		});
		const options = { trustRootsB64url: chain.roots, nowSeconds: now };
		return { gw, chain, doc, options };
	}

	it('returns the verified document in the extension shape', async () => {
		const { gw, options } = setup();
		const caps = await G.fetchCapabilities(gw.ctx, options);
		assert.equal(caps.version, 1);
		assert.equal(caps.serverVersion, '2026.10.8');
		assert.equal(caps.issuedAt, now - 60);
		assert.deepEqual(caps.languages, ['de', 'en', 'hr', 'sl']);
		assert.deepEqual(caps.labelLanguages, ['en', 'sl']);
		assert.equal(caps.maxTextChars, 120000);
		assert.equal(caps.maxBodyBytes, 1048576);
		assert.ok(caps.entities.some((e) => e.type === 'PERSON' && e.default === 'on'));
		assert.deepEqual(caps.groups[0], { id: 'general', kind: 'category' });
		assert.equal(caps.labels.get('type:PERSON').get('en').length > 0, true);
		assert.equal(G.effectiveMaxTextChars(caps), 120000);
		const [get] = gw.gets('/v1/capabilities');
		assert.equal(get.headers.Accept, 'application/json');
		assert.equal(get.body, undefined);
	});

	it('is cached for 5 minutes, then refetched', async () => {
		const { gw, options } = setup();
		await G.fetchCapabilities(gw.ctx, options);
		await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 299 });
		assert.equal(gw.gets('/v1/capabilities').length, 1);
		await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 301 });
		assert.equal(gw.gets('/v1/capabilities').length, 2);
	});

	for (const [name, response] of [
		// 3xx, 401 and 403 are null too but start no backoff (see the per-credential tests below).
		['404 from an older gateway', () => json(404, { detail: 'Not Found' })],
		['503 capabilities_not_configured', () => json(503, { error: 'capabilities_not_configured' })],
		[
			'an HTML 200',
			() => ({
				statusCode: 200,
				headers: { 'content-type': 'text/html' },
				body: Buffer.from('<html>'),
			}),
		],
		[
			'a sealed body',
			() => ({
				statusCode: 200,
				headers: { 'content-type': 'application/octet-stream' },
				body: Buffer.alloc(80),
			}),
		],
	]) {
		it(`null on ${name}, and the next attempt waits 5 minutes`, async () => {
			const { gw, options } = setup({ capabilities: response });
			assert.equal(await G.fetchCapabilities(gw.ctx, options), null);
			assert.equal(await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 200 }), null);
			assert.equal(gw.gets('/v1/capabilities').length, 1);
			await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 301 });
			assert.equal(gw.gets('/v1/capabilities').length, 2);
		});
	}

	it('null on a transport failure or an n8n error, never a throw', async () => {
		const { options } = setup();
		for (const thrown of [
			Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
			Object.assign(new Error('no credentials'), { name: 'NodeOperationError' }),
		]) {
			G.clearGatewayCaches();
			const ctx = {
				helpers: {
					async httpRequestWithAuthentication() {
						throw thrown;
					},
				},
			};
			assert.equal(await G.fetchCapabilities(ctx, options), null);
		}
	});

	it('null when signed by an unpinned root or stale', async () => {
		const { gw } = setup();
		assert.equal(
			await G.fetchCapabilities(gw.ctx, {
				trustRootsB64url: [ed25519Signer().publicKey],
				nowSeconds: now,
			}),
			null,
		);
		G.clearGatewayCaches();
		const { gw: gw2, options } = setup({ text: capabilitiesText(now - 7200 - 301) });
		assert.equal(await G.fetchCapabilities(gw2.ctx, options), null);
	});

	it('a cached document past its window is not returned', async () => {
		const { gw, options } = setup();
		assert.ok(await G.fetchCapabilities(gw.ctx, options));
		// The refetch after the TTL fails (gateway now answers 404): the cached one is used only
		// while its own window holds.
		const later = { ...options, nowSeconds: now + 400 };
		gw.requests.length = 0;
		const failing = makeFakeGateway({ now, chain: gw.chain, capabilities: () => json(404, {}) });
		assert.ok(await G.fetchCapabilities(failing.ctx, later));
		G.clearGatewayCaches();
		assert.ok(await G.fetchCapabilities(gw.ctx, options));
		const expired = { ...options, nowSeconds: now - 60 + 7200 + 301 };
		assert.equal(await G.fetchCapabilities(failing.ctx, expired), null);
	});

	it('a failed refresh keeps the cached document for the 5-minute backoff', async () => {
		const { gw, options } = setup();
		const first = await G.fetchCapabilities(gw.ctx, options);
		assert.ok(first);
		const failing = makeFakeGateway({ now, chain: gw.chain, capabilities: () => json(503, {}) });
		// Past the TTL: the refetch fails, the cached document still verifies and is returned.
		assert.equal(
			await G.fetchCapabilities(failing.ctx, { ...options, nowSeconds: now + 400 }),
			first,
		);
		assert.equal(failing.gets('/v1/capabilities').length, 1);
		// Inside the retry window: still the cached document, and no new request.
		assert.equal(
			await G.fetchCapabilities(failing.ctx, { ...options, nowSeconds: now + 500 }),
			first,
		);
		assert.equal(failing.gets('/v1/capabilities').length, 1);
	});

	it('a cached document is refused once a keyconfig raises the serial floor above it', async () => {
		const chain = makeTrustChain();
		const options = { trustRootsB64url: chain.roots, nowSeconds: now };
		let capabilitiesUp = true;
		const gw = makeFakeGateway({
			now,
			chain,
			capabilities: () =>
				capabilitiesUp
					? json(
							200,
							chain.capabilities({ now, text: capabilitiesText(now - 60), serial: now - 86400 }),
						)
					: json(503, {}),
		});
		assert.ok(await G.fetchCapabilities(gw.ctx, options));
		// A renewed delegation (newer serial) is seen through the keyconfig: the floor rises.
		gw.config = chain.keyconfig({
			now,
			serial: now - 3600,
			keys: [{ keyId: gw.keyId, pkR: gw.recipient.pkR, notAfter: now + 9999 }],
		});
		await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(G.delegationFloor(options), now - 3600);
		// Within the 5-minute TTL, with the endpoint failing: the superseded document is not used.
		capabilitiesUp = false;
		assert.equal(await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 10 }), null);
		assert.equal(gw.gets('/v1/capabilities').length, 2, 'refetched, not served from the cache');
	});

	for (const [name, response] of [
		['401', () => json(401, { error: 'unauthenticated' })],
		[
			'302 to the login page',
			() => ({ statusCode: 302, headers: { location: '/auth/login' }, body: Buffer.alloc(0) }),
		],
		['403', () => json(403, { error: 'missing_role' })],
	]) {
		it(`one credential's ${name} does not start the backoff for the others`, async () => {
			const { gw, options } = setup();
			const bad = makeFakeGateway({ now, chain: gw.chain, capabilities: response });
			assert.equal(await G.fetchCapabilities(bad.ctx, options), null);
			const caps = await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 10 });
			assert.ok(caps, 'a good credential right after still gets the document');
			assert.equal(gw.gets('/v1/capabilities').length, 1);
		});
	}

	it('a missing credential (n8n error, nothing sent) does not start the backoff', async () => {
		const { gw, options } = setup();
		const noCredential = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw new NodeOperationError(NODE, 'Node does not have any credentials set');
				},
			},
		};
		assert.equal(await G.fetchCapabilities(noCredential, options), null);
		// n8n-core rewraps it as a NodeApiError around the NodeOperationError.
		const wrapped = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw new NodeApiError(
						NODE,
						new NodeOperationError(NODE, 'Node does not have any credentials set'),
					);
				},
			},
		};
		assert.equal(await G.fetchCapabilities(wrapped, options), null);
		assert.ok(await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 10 }));
	});

	it('a transport failure still starts the backoff', async () => {
		const { gw, options } = setup();
		const offline = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw new NodeApiError(
						NODE,
						Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
					);
				},
			},
		};
		assert.equal(await G.fetchCapabilities(offline, options), null);
		assert.equal(await G.fetchCapabilities(gw.ctx, { ...options, nowSeconds: now + 10 }), null);
		assert.equal(gw.gets('/v1/capabilities').length, 0);
	});

	for (const audience of ['app.anonymizator.com', 'staging.example.net']) {
		it(`null for a delegation issued for another deployment (audience=${audience})`, async () => {
			const chain = makeTrustChain();
			const { gw, options } = setup({
				chain,
				capabilities: () =>
					json(200, chain.capabilities({ now, text: capabilitiesText(now - 60), audience })),
			});
			assert.equal(await G.fetchCapabilities(gw.ctx, options), null);
			assert.equal(gw.gets('/v1/capabilities').length, 1);
		});
	}

	it('a delegation for this deployment alone (anon.prosecco37.com) verifies', async () => {
		const chain = makeTrustChain();
		const { gw, options } = setup({
			chain,
			capabilities: () =>
				json(
					200,
					chain.capabilities({
						now,
						text: capabilitiesText(now - 60),
						audience: 'anon.prosecco37.com',
					}),
				),
		});
		assert.ok(await G.fetchCapabilities(gw.ctx, options));
	});

	it('the serial floor is read only: below it -> null; it never raises the floor', async () => {
		const chain = makeTrustChain();
		const options = { trustRootsB64url: chain.roots, nowSeconds: now };
		// A keyconfig with a newer delegation raises the floor.
		const gw = makeFakeGateway({
			now,
			chain,
			capabilities: () =>
				json(
					200,
					chain.capabilities({ now, text: capabilitiesText(now - 60), serial: now - 86400 }),
				),
		});
		gw.config = chain.keyconfig({
			now,
			serial: now - 3600,
			keys: [{ keyId: gw.keyId, pkR: gw.recipient.pkR, notAfter: now + 9999 }],
		});
		await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(G.delegationFloor(options), now - 3600);
		assert.equal(await G.fetchCapabilities(gw.ctx, options), null);
		G.clearGatewayCaches();
		assert.ok(await G.fetchCapabilities(gw.ctx, options));
		assert.equal(G.delegationFloor(options), 0, 'capabilities never raise the floor');
	});
});

describe('differential: the extension verifyCapabilitiesV1', { skip: EXT_SKIP }, () => {
	it('agrees on every vector case and on the parse', async () => {
		const ext = loadExtHpke();
		for (const c of FILE.cases) {
			const ours = C.verifyCapabilitiesV1(
				c.capabilities_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			const theirs = await ext.verifyCapabilitiesV1(
				c.capabilities_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			assert.equal(ours.ok, theirs.ok, c.name);
			if (ours.ok) {
				assert.deepEqual(
					asJson(ours.capabilities),
					JSON.parse(JSON.stringify(asJson(theirs.capabilities))),
					c.name,
				);
				assert.equal(ours.serial, theirs.serial);
				assert.equal(ours.notAfter, theirs.notAfter);
			} else {
				assert.equal(ours.error, theirs.error, c.name);
			}
		}
	});
});
