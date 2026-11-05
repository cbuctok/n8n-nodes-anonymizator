// Protocol v3 at the node level (compiled dist/): the credential's Encryption setting (Automatic by
// default, Always Post-Quantum behind Show Experimental Options, stored in the 0.4.0 `postQuantum`
// field so 0.4.0 credentials keep their meaning), the reader, and Protect / Detect end to end
// through the real gateway.ts against a fake v2 + v3 gateway: Automatic with native ML-KEM present
// and absent (simulated with the `nativeMlKem: false` seam, and for real on Node 22), Always
// Post-Quantum, the `encryption` output field and the fail-closed messages. Only synthetic data
// is used.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { after, beforeEach, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { ed25519Signer, makeTrustChain, octet } from './helpers/pgw.mjs';
import { NATIVE_MLKEM, NATIVE_SKIP, makeFakeGatewayV3 } from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const { Anonymizator } = require(`${DIST}nodes/Anonymizator/Anonymizator.node.js`);
const { AnonymizatorApi } = require(`${DIST}credentials/AnonymizatorApi.credentials.js`);
const gateway = require(`${DIST}nodes/Anonymizator/shared/gateway.js`);
const { encryptionMode } = require(`${DIST}nodes/Anonymizator/actions/protect.js`);
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

describe('credential: Encryption', () => {
	const c = new AnonymizatorApi();
	const names = c.properties.map((p) => p.name);

	test('is the last property, behind Show Experimental Options, Automatic by default', () => {
		assert.deepEqual(names, ['apiKey', 'showExperimental', 'postQuantum']);
		const gate = c.properties[1];
		const mode = c.properties[2];
		assert.equal(gate.type, 'boolean');
		assert.equal(gate.default, false);
		assert.equal(gate.displayOptions, undefined);
		assert.equal(mode.displayName, 'Encryption');
		assert.equal(mode.type, 'options');
		assert.deepEqual(mode.displayOptions, { show: { showExperimental: [true] } });
		assert.equal(mode.default, false);
		assert.deepEqual(
			mode.options.map((o) => [o.name, o.value]),
			[
				['Always Post-Quantum (Experimental)', true],
				['Automatic', false],
			],
		);
		assert.ok(mode.options.some((o) => o.value === mode.default));
	});

	test('keeps the 0.4.0 field name and values, so old credentials keep their meaning', () => {
		// 0.4.0 stored `postQuantum` as a boolean: true (with the gate on) was the experimental
		// post-quantum option, which is now Always Post-Quantum; false or absent is Automatic.
		const mode = c.properties[2];
		assert.equal(mode.name, 'postQuantum');
		assert.equal(
			mode.options.find((o) => o.value === true).name,
			'Always Post-Quantum (Experimental)',
		);
		assert.equal(mode.options.find((o) => o.value === false).name, 'Automatic');
	});

	test('says what each choice does honestly', () => {
		const mode = c.properties[2];
		const always = mode.options.find((o) => o.value === true).description;
		const automatic = mode.options.find((o) => o.value === false).description;
		assert.match(always, /not been independently audited/);
		assert.match(always, /fail instead of using standard encryption/);
		assert.match(automatic, /ML-KEM built in \(24\.7\.0 and later\)/);
		assert.match(automatic, /standard encryption otherwise/);
		assert.match(automatic, /Never uses bundled post-quantum code/);
		assert.match(mode.description, /connection test checks standard encryption only/);
		assert.match(mode.description, /encryption field/);
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

describe('encryptionMode (the reader, and the 0.4.0 migration)', () => {
	const read = (credentials) => encryptionMode({ getCredentials: async () => credentials });

	test('Always Post-Quantum only when both booleans are exactly true (0.4.0 option on)', async () => {
		assert.equal(await read(PQ_ON), 'postQuantum');
		for (const credentials of [
			{ apiKey: 'test' },
			{ apiKey: 'test', postQuantum: true },
			{ apiKey: 'test', showExperimental: true },
			{ apiKey: 'test', showExperimental: false, postQuantum: true },
			{ apiKey: 'test', showExperimental: true, postQuantum: false },
			{ apiKey: 'test', showExperimental: 'true', postQuantum: 'true' },
			{ apiKey: 'test', showExperimental: 1, postQuantum: 1 },
		]) {
			assert.equal(await read(credentials), 'automatic', JSON.stringify(credentials));
		}
	});

	test('a context without getCredentials gets the default, Automatic', async () => {
		assert.equal(await encryptionMode({}), 'automatic');
	});

	test('a credential read that throws is passed on, never read as a mode', async () => {
		await assert.rejects(
			encryptionMode({
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
	const baseSeams = {
		trustRootsB64url: [root.publicKey],
		retryDelayMs: 1,
		keyconfigRetryDelayMs: 1,
	};
	let seams = baseSeams;

	beforeEach(() => {
		seams = baseSeams;
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

	const AUTOMATIC_CREDENTIALS = [
		{ apiKey: 'test' },
		{ apiKey: 'test', showExperimental: false, postQuantum: true },
		{ apiKey: 'test', showExperimental: true, postQuantum: false },
	];

	test('Always Post-Quantum: Protect sends v3 frames only, and the result reveals', async () => {
		const { gw, ctx, reads } = setup({ credentials: PQ_ON });
		const text = 'Pozdrav, Janez Novak tukaj.';
		const [item] = await run(ctx, { operation: 'protect', text, placeholderStyle: 'sequential' });
		assert.equal(item.json.protectedText, 'Pozdrav, [PERSON_1] tukaj.');
		assert.equal(item.json.encryption, NATIVE_MLKEM ? 'v3-native' : 'v3-noble');
		assert.deepEqual(gw.versions(), [3]);
		assert.equal(gw.v3.results[0].payload.text, text);
		assert.ok(reads() >= 1, 'the credential is read before the send');
		const latin = gw.posts()[0].body.toString('latin1');
		assert.ok(!latin.includes('Janez'));
	});

	test('Always Post-Quantum without native ML-KEM (simulated): the vendored ML-KEM, v3-noble', async () => {
		seams = { ...baseSeams, nativeMlKem: false };
		const { gw, ctx } = setup({ credentials: PQ_ON });
		const [item] = await run(ctx, { operation: 'detect', text: 'Janez Novak' });
		assert.equal(item.json.entityCount, 1);
		assert.equal(item.json.encryption, 'v3-noble');
		assert.deepEqual(gw.versions(), [3]);
	});

	test('Always Post-Quantum: a long text in parts, every part v3, the credential read per send', async () => {
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

	test('Always Post-Quantum, gateway without v3: Detect stops with the post-quantum message, nothing sent', async () => {
		const { gw, ctx } = setup({ credentials: PQ_ON, offerV3: false });
		let error;
		try {
			await run(ctx, { operation: 'detect', text: 'Janez Novak' });
		} catch (e) {
			error = e;
		}
		assert.ok(error instanceof NodeOperationError, String(error));
		assert.match(error.message, /Post-quantum encryption is on/);
		assert.match(error.description, /Set Encryption to Automatic/);
		assert.match(error.description, /credential test checks standard encryption only/);
		assert.match(error.description, /\(code: hpke_pq_unavailable\)/);
		assert.doesNotMatch(`${error.message} ${error.description}`, /Janez/);
		assert.equal(gw.posts().length, 0);
	});

	test(`Automatic (default, 0.4.0 option off, or the gate off), gateway with v3: ${NATIVE_MLKEM ? 'v3-native' : 'v2 (no native ML-KEM here)'}`, async () => {
		for (const credentials of AUTOMATIC_CREDENTIALS) {
			gateway.clearGatewayCaches();
			const { gw, ctx } = setup({ credentials });
			const [item] = await run(ctx, {
				operation: 'protect',
				text: 'Janez Novak',
				placeholderStyle: 'sequential',
			});
			assert.equal(item.json.protectedText, '[PERSON_1]');
			assert.equal(item.json.encryption, NATIVE_MLKEM ? 'v3-native' : 'v2');
			assert.deepEqual(gw.versions(), [NATIVE_MLKEM ? 3 : 2], JSON.stringify(credentials));
		}
	});

	test('Automatic without native ML-KEM (simulated), gateway with v3: v2 only, nothing of v3', async () => {
		seams = { ...baseSeams, nativeMlKem: false };
		for (const operation of ['protect', 'detect']) {
			gateway.clearGatewayCaches();
			const { gw, ctx } = setup({ credentials: { apiKey: 'test' } });
			const [item] = await run(ctx, { operation, text: 'Janez Novak' });
			assert.equal(item.json.encryption, 'v2');
			assert.deepEqual(gw.versions(), [2]);
			assert.equal(gw.v3.frames.length, 0);
		}
	});

	test('Automatic, gateway without v3: v2, as before', async () => {
		const { gw, ctx } = setup({ credentials: { apiKey: 'test' }, offerV3: false });
		const [item] = await run(ctx, { operation: 'detect', text: 'Janez Novak' });
		assert.equal(item.json.entityCount, 1);
		assert.equal(item.json.encryption, 'v2');
		assert.deepEqual(gw.versions(), [2]);
	});

	test(
		'Automatic, v3 withdrawn after a v3 attempt: the withdrawn message, never resent as v2',
		{ skip: NATIVE_SKIP },
		async () => {
			const { gw, ctx } = setup({ credentials: { apiKey: 'test' } });
			gw.v3.enabled = false;
			const helper = gw.ctx.helpers.httpRequestWithAuthentication;
			gw.ctx.helpers.httpRequestWithAuthentication = async function (name, request) {
				if (request.method === 'POST') gw.v3.offer = false;
				return await helper.call(this, name, request);
			};
			let error;
			try {
				await run(ctx, { operation: 'protect', text: 'Janez Novak' });
			} catch (e) {
				error = e;
			}
			assert.ok(error instanceof NodeOperationError, String(error));
			assert.match(error.message, /stopped offering post-quantum encryption/);
			assert.match(error.description, /not sent again with standard encryption/);
			assert.match(error.description, /\(code: hpke_pq_withdrawn\)/);
			assert.deepEqual(gw.versions(), [3]);
		},
	);

	test('blank text: nothing is sent and encryption is none', async () => {
		const { gw, ctx, reads } = setup({ credentials: PQ_ON });
		for (const operation of ['protect', 'detect']) {
			const [item] = await run(ctx, { operation, text: '   ' });
			assert.equal(item.json.encryption, 'none');
		}
		assert.equal(gw.requests.length, 0);
		assert.equal(reads(), 0);
	});

	test("Include Input Fields never carries an input item's encryption over", async () => {
		seams = { ...baseSeams, nativeMlKem: false };
		const { ctx } = setup({ credentials: { apiKey: 'test' } });
		ctx.getInputData = () => [{ json: { encryption: 'v3-native', body: 'x' } }];
		const [item] = await run(ctx, {
			operation: 'detect',
			text: 'Janez Novak',
			options: { includeInputFields: true },
		});
		assert.equal(item.json.body, 'x');
		assert.equal(item.json.encryption, 'v2');
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
