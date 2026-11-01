// EXPERIMENTAL protocol v3 at the node level (compiled dist/): the credential's buried option
// (default off, last, behind Show Experimental Options), the reader (on only when both booleans are
// true), and Protect / Detect end to end through the real gateway.ts against a fake v2 + v3
// gateway: v3 frames with the option on, v2 frames otherwise, and the fail-closed message.
// Only synthetic data is used.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { after, beforeEach, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { ed25519Signer, makeTrustChain, octet } from './helpers/pgw.mjs';
import { makeFakeGatewayV3 } from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const { Anonymizator } = require(`${DIST}nodes/Anonymizator/Anonymizator.node.js`);
const { AnonymizatorApi } = require(`${DIST}credentials/AnonymizatorApi.credentials.js`);
const gateway = require(`${DIST}nodes/Anonymizator/shared/gateway.js`);
const { postQuantumEnabled } = require(`${DIST}nodes/Anonymizator/actions/protect.js`);
const { NodeOperationError } = require('n8n-workflow');

const realAnalyze = gateway.analyze;
const realFetchCapabilities = gateway.fetchCapabilities;
after(() => {
	gateway.analyze = realAnalyze;
	gateway.fetchCapabilities = realFetchCapabilities;
});

const NOW = Math.floor(Date.now() / 1000);
const NODE = {
	id: 'node-1',
	name: 'Anonymizator',
	type: 'n8n-nodes-anonymizator.anonymizator',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};
const PQ_ON = { apiKey: 'test', showExperimental: true, postQuantum: true };

describe('credential: Post-Quantum Encryption (Experimental)', () => {
	const c = new AnonymizatorApi();
	const names = c.properties.map((p) => p.name);

	test('is the last property, behind Show Experimental Options, both off by default', () => {
		assert.deepEqual(names, ['apiKey', 'showExperimental', 'postQuantum']);
		const gate = c.properties[1];
		const pq = c.properties[2];
		assert.equal(gate.type, 'boolean');
		assert.equal(gate.default, false);
		assert.equal(gate.displayOptions, undefined);
		assert.equal(pq.type, 'boolean');
		assert.equal(pq.default, false);
		assert.deepEqual(pq.displayOptions, { show: { showExperimental: [true] } });
		assert.equal(pq.displayName, 'Post-Quantum Encryption (Experimental)');
	});

	test('says what it does honestly: experimental, fails closed, the test checks v2 only', () => {
		const pq = c.properties[2];
		assert.match(pq.description, /experimental post-quantum protocol \(X-Wing\)/);
		assert.match(pq.description, /fail instead of using standard encryption/);
		assert.match(pq.description, /connection test checks standard encryption only/);
		assert.match(c.properties[1].description, /^Whether /);
	});

	test('the credential test request is unchanged (standard encryption only)', () => {
		assert.equal(c.test.request.url, '/v1/keyconfig');
		assert.deepEqual(
			c.test.rules.map((r) => r.properties.value),
			[302, 401, 403],
		);
	});
});

describe('postQuantumEnabled', () => {
	const read = (credentials) => postQuantumEnabled({ getCredentials: async () => credentials });

	test('on only when both booleans are exactly true', async () => {
		assert.equal(await read(PQ_ON), true);
		for (const credentials of [
			{ apiKey: 'test' },
			{ apiKey: 'test', postQuantum: true },
			{ apiKey: 'test', showExperimental: true },
			{ apiKey: 'test', showExperimental: false, postQuantum: true },
			{ apiKey: 'test', showExperimental: true, postQuantum: false },
			{ apiKey: 'test', showExperimental: 'true', postQuantum: 'true' },
			{ apiKey: 'test', showExperimental: 1, postQuantum: 1 },
		]) {
			assert.equal(await read(credentials), false, JSON.stringify(credentials));
		}
	});

	test('a credential read that throws is passed on, never read as off', async () => {
		await assert.rejects(
			postQuantumEnabled({
				getCredentials: async () => {
					throw new Error('Node does not have any credentials set');
				},
			}),
			/does not have any credentials/,
		);
	});
});

describe('Protect and Detect through the real gateway with a v2 + v3 fake', () => {
	const root = ed25519Signer();
	const delegated = ed25519Signer();
	const seams = { trustRootsB64url: [root.publicKey], retryDelayMs: 1, keyconfigRetryDelayMs: 1 };

	beforeEach(() => {
		gateway.analyze = (ctx, text, entityTypes, options) =>
			realAnalyze(ctx, text, entityTypes, { ...options, ...seams });
		gateway.fetchCapabilities = (ctx) => realFetchCapabilities(ctx, seams);
		gateway.clearGatewayCaches();
	});

	/** A fake gateway that finds "Janez Novak", and an execute context with `credentials`. */
	function setup({ credentials, offerV3 = true } = {}) {
		const find = (payload) => {
			const at = payload.text.indexOf('Janez Novak');
			return {
				entities: at < 0 ? [] : [{ entity_type: 'PERSON', start: at, end: at + 11, score: 0.9 }],
			};
		};
		const gw = makeFakeGatewayV3({
			now: NOW,
			chain: makeTrustChain({ root, delegated }),
			keyId: 7,
			offerV3,
			analyzeV3: (opened) => octet(200, opened.seal(find(opened.payload))),
			analyzeV2: (opened) => octet(200, opened.seal(find(opened.payload))),
		});
		let credentialReads = 0;
		const ctx = {
			getNode: () => NODE,
			getInputData: () => [{ json: {} }],
			continueOnFail: () => false,
			getNodeParameter(name, itemIndex, fallback) {
				const params = ctx.params;
				const value = name
					.split('.')
					.reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), params);
				return value === undefined ? fallback : structuredClone(value);
			},
			getCredentials: async () => {
				credentialReads += 1;
				if (credentials instanceof Error) throw credentials;
				return credentials;
			},
			helpers: {
				async httpRequestWithAuthentication(name, options) {
					return await gw.ctx.helpers.httpRequestWithAuthentication.call(gw.ctx, name, options);
				},
			},
			params: {},
		};
		return { gw, ctx, reads: () => credentialReads };
	}

	async function run(ctx, params) {
		ctx.params = params;
		const [out] = await new Anonymizator().execute.call(ctx);
		return out;
	}

	test('option on: Protect sends v3 frames only, and the result reveals', async () => {
		const { gw, ctx, reads } = setup({ credentials: PQ_ON });
		const text = 'Pozdrav, Janez Novak tukaj.';
		const [item] = await run(ctx, { operation: 'protect', text, placeholderStyle: 'sequential' });
		assert.equal(item.json.protectedText, 'Pozdrav, [PERSON_1] tukaj.');
		assert.deepEqual(gw.versions(), [3]);
		assert.equal(gw.v3.results[0].payload.text, text);
		assert.ok(reads() >= 1, 'the credential is read before the send');
		const latin = gw.posts()[0].body.toString('latin1');
		assert.ok(!latin.includes('Janez'));
	});

	test('option on: a long text in parts, every part v3, the credential read per send', async () => {
		const { gw, ctx, reads } = setup({ credentials: PQ_ON });
		const text = [
			'Janez Novak ' + 'a'.repeat(7000),
			'b'.repeat(7000),
			'Janez Novak ' + 'c'.repeat(7000),
		].join('\n');
		const [item] = await run(ctx, { operation: 'detect', text });
		assert.equal(item.json.entityCount, 2);
		assert.deepEqual(gw.versions(), [3, 3, 3]);
		assert.ok(reads() >= 3);
	});

	test('option off (default, old credentials, or the gate off): v2 exactly as before', async () => {
		for (const credentials of [
			{ apiKey: 'test' },
			{ apiKey: 'test', showExperimental: false, postQuantum: true },
			{ apiKey: 'test', showExperimental: true, postQuantum: false },
		]) {
			gateway.clearGatewayCaches();
			const { gw, ctx } = setup({ credentials });
			const [item] = await run(ctx, {
				operation: 'protect',
				text: 'Janez Novak',
				placeholderStyle: 'sequential',
			});
			assert.equal(item.json.protectedText, '[PERSON_1]');
			assert.deepEqual(gw.versions(), [2], JSON.stringify(credentials));
			assert.equal(gw.v3.frames.length, 0);
		}
	});

	test('option on, gateway without v3: Detect stops with the post-quantum message, nothing sent', async () => {
		const { gw, ctx } = setup({ credentials: PQ_ON, offerV3: false });
		let error;
		try {
			await run(ctx, { operation: 'detect', text: 'Janez Novak' });
		} catch (e) {
			error = e;
		}
		assert.ok(error instanceof NodeOperationError, String(error));
		assert.match(error.message, /Post-quantum encryption is on/);
		assert.match(error.description, /Post-Quantum Encryption \(Experimental\)/);
		assert.match(error.description, /credential test checks standard encryption only/);
		assert.match(error.description, /\(code: hpke_pq_unavailable\)/);
		assert.doesNotMatch(`${error.message} ${error.description}`, /Janez/);
		assert.equal(gw.posts().length, 0);
	});

	test('a credential read that throws fails the item and sends nothing', async () => {
		const { gw, ctx } = setup({ credentials: new Error('Node does not have any credentials set') });
		await assert.rejects(run(ctx, { operation: 'protect', text: 'Janez Novak' }), /credentials/);
		assert.equal(gw.posts().length, 0);
	});

	test('Reveal reads no credential and sends nothing, with the option on', async () => {
		const { gw, ctx, reads } = setup({ credentials: PQ_ON });
		const [item] = await run(ctx, {
			operation: 'reveal',
			text: 'Hi [PERSON_1]',
			placeholderMap: { PERSON_1: 'Janez Novak' },
		});
		assert.equal(item.json.revealedText, 'Hi Janez Novak');
		assert.equal(reads(), 0);
		assert.equal(gw.requests.length, 0);
	});
});
