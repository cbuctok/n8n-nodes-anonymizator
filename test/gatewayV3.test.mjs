// EXPERIMENTAL protocol v3 through gateway.ts (compiled dist/), against a fake gateway that serves
// v2 and v3: off by default and v2 unchanged, v3 only with the reader on, fail closed without a
// verifiable `v3` member, the bad-version budget, retries, the monotonic rule (the setting is read
// at every send), and the delegation serial floor shared by v2, v3 and capabilities.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { beforeEach, describe, it } from 'node:test';

import { capabilitiesText, json, octet } from './helpers/pgw.mjs';
import { keyconfigV3Member, makeFakeGatewayV3 } from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const G = require('../dist/nodes/Anonymizator/shared/gateway.js');
const { GatewayError } = require('../dist/nodes/Anonymizator/shared/errors.js');

const NOW = 1_800_000_000;

beforeEach(() => G.clearGatewayCaches());

async function rejects(promise, code) {
	let error;
	try {
		await promise;
	} catch (e) {
		error = e;
	}
	assert.ok(error instanceof GatewayError, `expected GatewayError(${code}), got ${error}`);
	assert.equal(error.code, code, error.message);
	return error;
}

function setup(overrides = {}) {
	const gw = makeFakeGatewayV3({ now: NOW, ...overrides });
	const options = {
		trustRootsB64url: gw.chain.roots,
		nowSeconds: NOW,
		retryDelayMs: 1,
		keyconfigRetryDelayMs: 1,
	};
	return { gw, options };
}

const ON = () => true;

describe('post-quantum off (the default): v2 exactly as before', () => {
	it('no reader: a v2 frame, even when the keyconfig offers v3', async () => {
		const { gw, options } = setup();
		const r = await G.analyze(gw.ctx, 'my name is Ana', undefined, options);
		assert.deepEqual(r.spans, []);
		assert.deepEqual(gw.versions(), [2]);
		assert.equal(gw.v3.frames.length, 0);
		assert.equal(gw.posts()[0].body.length, 13 + 32 + 256 + 16);
	});

	it('a reader that answers anything but true is off', async () => {
		for (const value of [false, undefined, null, 'true', 1, {}]) {
			G.clearGatewayCaches();
			const { gw, options } = setup();
			await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: () => value });
			assert.deepEqual(gw.versions(), [2], String(value));
		}
	});

	it('off with a gateway that has no v3 at all (v3 off on the server): v2 works', async () => {
		const { gw, options } = setup({ offerV3: false, v3Enabled: false });
		await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: () => false });
		assert.deepEqual(gw.versions(), [2]);
	});

	it('the v2 acquisition ignores a broken v3 member', async () => {
		const { gw, options } = setup({ v3Member: () => ({ delegation: 1, keyconfig: [] }) });
		const kc = await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(kc.keyId, 101);
	});
});

describe('post-quantum on', () => {
	it('seals every request as v3 to the verified v3 key and opens the v3 answer', async () => {
		const { gw, options } = setup({
			analyzeV3: (opened) => {
				assert.deepEqual(opened.payload, { text: 'my name is Ana Kovač' });
				return octet(
					200,
					opened.seal({ entities: [{ entity_type: 'PERSON', start: 11, end: 20, score: 0.9 }] }),
				);
			},
		});
		const r = await G.analyze(gw.ctx, 'my name is Ana Kovač', undefined, {
			...options,
			postQuantum: ON,
		});
		assert.deepEqual(r.spans, [{ entity_type: 'PERSON', start: 11, end: 20, score: 0.9 }]);
		assert.deepEqual(gw.versions(), [3]);
		assert.equal(gw.posts()[0].body.readUInt32BE(1), 1000001);
		assert.equal(gw.posts()[0].body.length, 1149 + 256);
	});

	it('an async reader works too, and the payload keeps entities and possible', async () => {
		const { gw, options } = setup({
			analyzeV3: (opened) => {
				assert.deepEqual(opened.payload, { text: 'abc', entities: ['PERSON'], possible: true });
				return octet(200, opened.seal({ entities: [], possible: [] }));
			},
		});
		const r = await G.analyze(gw.ctx, 'abc', ['PERSON'], {
			...options,
			possible: true,
			postQuantum: async () => true,
		});
		assert.deepEqual(r.possible, []);
		assert.deepEqual(gw.versions(), [3]);
	});

	it('no v3 member: hpke_pq_unavailable, nothing sent (no fallback to v2)', async () => {
		const { gw, options } = setup({ offerV3: false });
		const error = await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_pq_unavailable',
		);
		assert.equal(error.httpCode, 200);
		assert.equal(gw.posts().length, 0);
	});

	it('a v3 member that does not verify: hpke_unverified_keyconfig, nothing sent', async () => {
		const { gw, options } = setup({
			v3Member: (state) => {
				const m = keyconfigV3Member(state.chain, {
					now: NOW,
					keys: [
						{
							keyId: 1000001,
							pk: gw.v3.recipient.keys.get(1000001).expanded.pk,
							notAfter: NOW + 3600,
						},
					],
				});
				return { ...m, keyconfig_sig: m.delegation_sig };
			},
		});
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_unverified_keyconfig',
		);
		assert.equal(gw.posts().length, 0);
	});

	it('a stale or expiring v3 key: the verifier codes, nothing sent', async () => {
		{
			const { gw, options } = setup({
				v3Member: (state) =>
					keyconfigV3Member(state.chain, {
						now: NOW,
						issuedAt: NOW - 3600,
						keys: [
							{
								keyId: 1000001,
								pk: gw.v3.recipient.keys.get(1000001).expanded.pk,
								notAfter: NOW + 3600,
							},
						],
					}),
			});
			await rejects(
				G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
				'hpke_stale_keyconfig',
			);
			assert.equal(gw.posts().length, 0);
		}
		G.clearGatewayCaches();
		{
			const { gw, options } = setup({
				v3Member: (state) =>
					keyconfigV3Member(state.chain, {
						now: NOW,
						keys: [
							{
								keyId: 1000001,
								pk: gw.v3.recipient.keys.get(1000001).expanded.pk,
								notAfter: NOW + 200,
							},
						],
					}),
			});
			await rejects(
				G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
				'hpke_no_usable_key',
			);
			assert.equal(gw.posts().length, 0);
		}
	});

	it('a low-order pk_X in a verified key: hpke_seal_failed, nothing sent', async () => {
		const { gw, options } = setup({
			v3Member: (state) => {
				const pk = Buffer.from(gw.v3.recipient.keys.get(1000001).expanded.pk);
				pk.fill(0, 1184);
				return keyconfigV3Member(state.chain, {
					now: NOW,
					keys: [{ keyId: 1000001, pk, notAfter: NOW + 3600 }],
				});
			},
		});
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_seal_failed',
		);
		assert.equal(gw.posts().length, 0);
	});

	it('the keyconfig 503 hpke_not_configured is passed on unchanged', async () => {
		const { gw, options } = setup({ keyconfig: () => json(503, { error: 'hpke_not_configured' }) });
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_not_configured',
		);
		assert.equal(gw.posts().length, 0);
	});

	it('a 0x02 answer to a v3 request is hpke_bad_response', async () => {
		const { gw, options } = setup({
			analyzeV3: (opened) => {
				const body = opened.seal({ entities: [] });
				body[0] = 2;
				return octet(200, body);
			},
		});
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_bad_response',
		);
	});

	it('sealed v3 errors come back as their codes (HTTP 200)', async () => {
		const { gw, options } = setup({
			analyzeV3: (opened) => octet(200, opened.seal({ error: 'invalid_payload' })),
		});
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'invalid_payload',
		);
		assert.deepEqual(gw.versions(), [3]);
	});

	it('invalid_entities with a filter: the whole text once more without it, still v3', async () => {
		const { gw, options } = setup({
			analyzeV3: (opened) =>
				octet(
					200,
					opened.seal(opened.payload.entities ? { error: 'invalid_entities' } : { entities: [] }),
				),
		});
		const r = await G.analyze(gw.ctx, 'text', ['PERSON'], { ...options, postQuantum: ON });
		assert.equal(r.entityFilterIgnored, true);
		assert.deepEqual(gw.versions(), [3, 3]);
	});
});

describe('post-quantum on: retries and the bad-version budget', () => {
	it('bad version, refetch with v3, reseal, bad version again: hpke_pq_unavailable after exactly two POSTs', async () => {
		const { gw, options } = setup({ v3Enabled: false });
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_pq_unavailable',
		);
		assert.deepEqual(gw.versions(), [3, 3]);
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
	});

	it('bad version, and the refetched keyconfig has no v3: hpke_pq_unavailable after one POST', async () => {
		const { gw, options } = setup({ v3Enabled: false });
		gw.ctx.helpers.httpRequestWithAuthentication = ((original) =>
			async function (name, request) {
				if (request.method === 'POST') gw.v3.offer = false;
				return await original.call(this, name, request);
			})(gw.ctx.helpers.httpRequestWithAuthentication);
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
			'hpke_pq_unavailable',
		);
		assert.deepEqual(gw.versions(), [3]);
	});

	it('bad version once (a replica restarting), then the reseal goes through', async () => {
		const { gw, options } = setup();
		let first = true;
		gw.v3.enabled = false;
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			const response = await helper.call(this, name, request);
			if (request.method === 'POST' && first) {
				first = false;
				gw.v3.enabled = true;
			}
			return response;
		};
		const r = await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON });
		assert.deepEqual(r.spans, []);
		assert.deepEqual(gw.versions(), [3, 3]);
	});

	it('the bad-version budget is separate: unknown key, retry, bad version, reseal: three POSTs, all v3', async () => {
		const { gw, options } = setup();
		let posts = 0;
		gw.v3.enabled = true;
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'POST') {
				posts += 1;
				if (posts === 1) {
					gw.requests.push(request);
					return json(400, { error: 'hpke_unknown_key' });
				}
				if (posts === 2) {
					gw.requests.push(request);
					return json(400, { error: 'hpke_bad_version' });
				}
			}
			return await helper.call(this, name, request);
		};
		const r = await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON });
		assert.deepEqual(r.spans, []);
		assert.deepEqual(gw.versions(), [3, 3, 3]);
		assert.equal(gw.gets('/v1/keyconfig').length, 3);
	});

	it('a server error is retried once with a fresh v3 seal; hpke_replay never', async () => {
		{
			const { gw, options } = setup();
			let n = 0;
			gw.ctx.helpers.httpRequestWithAuthentication = ((helper) =>
				async function (name, request) {
					if (request.method === 'POST' && n++ === 0) {
						gw.requests.push(request);
						return json(503, { error: 'busy' });
					}
					return await helper.call(this, name, request);
				})(gw.ctx.helpers.httpRequestWithAuthentication);
			await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON });
			const [a, b] = gw.posts();
			assert.deepEqual(gw.versions(), [3, 3]);
			assert.notEqual(
				a.body.subarray(13, 1133).toString('hex'),
				b.body.subarray(13, 1133).toString('hex'),
			);
		}
		G.clearGatewayCaches();
		{
			const { gw, options } = setup({ analyzeV3: () => json(409, { error: 'hpke_replay' }) });
			await rejects(
				G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: ON }),
				'hpke_replay',
			);
			assert.deepEqual(gw.versions(), [3]);
		}
	});

	it('a v2 frame answered with hpke_bad_version is not resealed (v2 unchanged)', async () => {
		const { gw, options } = setup({ analyzeV2: () => json(400, { error: 'hpke_bad_version' }) });
		await rejects(G.analyze(gw.ctx, 'text', undefined, options), 'hpke_bad_version');
		assert.deepEqual(gw.versions(), [2]);
	});
});

describe('post-quantum on: the setting is read at every send (monotonic rule)', () => {
	it('switched on mid-run: no part sent after the switch is v2', async () => {
		const { gw, options } = setup();
		let sends = 0;
		const reader = () => sends >= 1;
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'POST') sends += 1;
			return await helper.call(this, name, request);
		};
		// Three parts of a text over the bundled cap (parts of 8000 code points).
		const text = ['a'.repeat(7000), 'b'.repeat(7000), 'c'.repeat(7000)].join('\n');
		await G.analyze(gw.ctx, text, undefined, { ...options, postQuantum: reader });
		assert.deepEqual(gw.versions(), [2, 3, 3]);
	});

	it('a retry after switching on is v3', async () => {
		const { gw, options } = setup({ analyzeV2: () => json(503, { error: 'busy' }) });
		let on = false;
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			const response = await helper.call(this, name, request);
			if (request.method === 'POST') on = true;
			return response;
		};
		await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: () => on });
		assert.deepEqual(gw.versions(), [2, 3]);
	});

	// The credential is saved with post-quantum on while the v2 keyconfig fetch is in flight.
	function switchOnDuringKeyconfigFetch(gw) {
		const state = { on: false, reads: 0 };
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			const response = await helper.call(this, name, request);
			if (request.method === 'GET' && request.url.endsWith('/v1/keyconfig')) state.on = true;
			return response;
		};
		const reader = () => {
			state.reads += 1;
			return state.on;
		};
		return { state, reader };
	}

	it('switched on during the v2 keyconfig fetch: the part is sealed as v3, never v2', async () => {
		const { gw, options } = setup();
		const { state, reader } = switchOnDuringKeyconfigFetch(gw);
		await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: reader });
		assert.deepEqual(gw.versions(), [3]);
		assert.equal(gw.posts().length, 1);
		assert.ok(state.reads >= 2, 'the setting is read again after the v2 acquisition');
	});

	it('switched on during the v2 keyconfig fetch, server without v3: hpke_pq_unavailable, nothing sent', async () => {
		const { gw, options } = setup({ offerV3: false });
		const { reader } = switchOnDuringKeyconfigFetch(gw);
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: reader }),
			'hpke_pq_unavailable',
		);
		assert.equal(gw.posts().length, 0);
	});

	it('switched on during the v2 keyconfig fetch: the restart as v3 spends no retry budget', async () => {
		// A plain 5xx on the first (v3) send is still retried once.
		let failV3 = 1;
		const { gw, options } = setup();
		const { reader } = switchOnDuringKeyconfigFetch(gw);
		const helper = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'POST' && failV3 > 0) {
				failV3 -= 1;
				gw.requests.push(request);
				return json(503, { error: 'busy' });
			}
			return await helper.call(this, name, request);
		};
		const r = await G.analyze(gw.ctx, 'text', undefined, { ...options, postQuantum: reader });
		assert.deepEqual(r.spans, []);
		assert.deepEqual(gw.versions(), [3, 3]);
	});

	it('a reader that throws fails the text and sends nothing (no silent fallback)', async () => {
		const { gw, options } = setup();
		await assert.rejects(
			G.analyze(gw.ctx, 'text', undefined, {
				...options,
				postQuantum: () => {
					throw new Error('credentials unreadable');
				},
			}),
			/credentials unreadable/,
		);
		assert.equal(gw.posts().length, 0);
	});
});

describe('the delegation serial floor, shared by v2, v3 and capabilities', () => {
	const at = (gw, serial) => (state) =>
		keyconfigV3Member(state.chain, {
			now: NOW,
			serial,
			keys: [
				{ keyId: 1000001, pk: gw.v3.recipient.keys.get(1000001).expanded.pk, notAfter: NOW + 3600 },
			],
		});

	it('v3: serial N+1, then a correctly signed config with serial N is refused', async () => {
		const N = NOW - 86400;
		const { gw, options } = setup();
		const ref = { serial: N + 1, now: NOW };
		const original = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'GET' && request.url.endsWith('/v1/keyconfig')) {
				gw.requests.push(request);
				const v3 = keyconfigV3Member(gw.chain, {
					now: ref.now,
					serial: ref.serial,
					notBefore: ref.serial,
					keys: [
						{
							keyId: 1000001,
							pk: gw.v3.recipient.keys.get(1000001).expanded.pk,
							notAfter: NOW + 7200,
						},
					],
				});
				return json(200, { ...gw.config, v3 });
			}
			return await original.call(this, name, request);
		};
		const first = await G.acquireKeyconfigV3(gw.ctx, { ...options, postQuantum: ON });
		assert.equal(first.serial, N + 1);
		assert.equal(G.delegationFloor(options), N + 1);

		// The renewal race: an older replica answers with serial N while the previous v3 config
		// still verifies, so that one is kept.
		ref.serial = N;
		const kept = await G.acquireKeyconfigV3(gw.ctx, { ...options, force: true });
		assert.equal(kept.serial, N + 1);

		// Later, when the previous config is stale: refetched once after the pause, still serial
		// N -> hpke_unverified_keyconfig, and nothing is sealed.
		ref.now = NOW + 1300;
		const later = { ...options, nowSeconds: ref.now };
		const before = gw.gets('/v1/keyconfig').length;
		await rejects(
			G.analyze(gw.ctx, 'text', undefined, { ...later, postQuantum: ON }),
			'hpke_unverified_keyconfig',
		);
		assert.equal(gw.gets('/v1/keyconfig').length, before + 2);
		assert.equal(gw.posts().length, 0);
		assert.equal(G.delegationFloor(options), N + 1);
	});

	it('a floor raised by v3 is seen by the v2 acquisition and by capabilities', async () => {
		const N = NOW - 86400;
		const { gw, options } = setup({
			capabilities: (request, state) =>
				json(
					200,
					state.chain.capabilities({ now: NOW, text: capabilitiesText(NOW - 60), serial: N }),
				),
		});
		const original = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'GET' && request.url.endsWith('/v1/keyconfig')) {
				gw.requests.push(request);
				// v2 at serial N, v3 under a renewed delegation at N + 5.
				return json(200, { ...gw.config, v3: at(gw, N + 5)(gw) });
			}
			return await original.call(this, name, request);
		};
		assert.equal(G.delegationFloor(options), 0);
		const v3 = await G.acquireKeyconfigV3(gw.ctx, options);
		assert.equal(v3.serial, N + 5);
		assert.equal(G.delegationFloor(options), N + 5);
		// The v2 member's delegation (serial N) is now below the floor.
		await rejects(G.acquireKeyconfig(gw.ctx, options), 'hpke_unverified_keyconfig');
		// Capabilities signed under serial N are below the floor too: the bundled catalog (null).
		assert.equal(await G.fetchCapabilities(gw.ctx, options), null);
	});

	it('a floor raised by v2 is seen by v3', async () => {
		const N = NOW - 86400;
		const { gw, options } = setup();
		const original = gw.ctx.helpers.httpRequestWithAuthentication;
		gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
			if (request.method === 'GET' && request.url.endsWith('/v1/keyconfig')) {
				gw.requests.push(request);
				return json(200, { ...gw.config, v3: at(gw, N - 10)(gw) });
			}
			return await original.call(this, name, request);
		};
		await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(G.delegationFloor(options), N);
		await rejects(G.acquireKeyconfigV3(gw.ctx, options), 'hpke_unverified_keyconfig');
	});
});
