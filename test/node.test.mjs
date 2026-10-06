// NODE track tests: drive the compiled Anonymizator node with a fake IExecuteFunctions.
//
// Two layers:
// - "node logic" replaces gateway.analyze on the compiled CJS module with a dictionary-based fake,
//   so every Protect/Reveal option and every error mapping is covered without crypto.
// - "full stack" keeps the real gateway and stubs only ctx.helpers.httpRequestWithAuthentication
//   with a fake HPKE recipient (node:crypto, written here independently of shared/hpke.ts). The
//   trust root is injected through analyze's documented test seam, signed by a root generated here.
//
// Only synthetic data is used (Janez Novak, ana.kovac@example.com, the SI56 test IBAN).
import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
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

const require = createRequire(import.meta.url);
const DIST = fileURLToPath(new URL('../dist/nodes/Anonymizator/', import.meta.url));

const { Anonymizator } = require(`${DIST}Anonymizator.node.js`);
const gateway = require(`${DIST}shared/gateway.js`);
const { GatewayError } = require(`${DIST}shared/errors.js`);
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

const realAnalyze = gateway.analyze;
after(() => {
	gateway.analyze = realAnalyze;
});

// ---------------------------------------------------------------------------------------------
// Fake n8n execute context

const NODE = {
	id: 'node-1',
	name: 'Anonymizator',
	type: 'n8n-nodes-anonymizator.anonymizator',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

function getPath(object, path) {
	let value = object;
	for (const part of path.split('.')) {
		if (value === null || typeof value !== 'object' || !(part in value)) return undefined;
		value = value[part];
	}
	return value;
}

/**
 * @param {object} setup
 * @param {object[]} [setup.items] input item json objects
 * @param {object | ((i: number) => object)} setup.params node parameters (per item via function)
 * @param {boolean} [setup.continueOnFail]
 * @param {Function} [setup.http] httpRequestWithAuthentication stub; omitted = no helpers at all
 * @param {boolean} [setup.noGetNode] simulate the AI tool context without getNode
 */
function makeCtx({ items = [{}], params, continueOnFail = false, http, noGetNode = false }) {
	const ctx = {
		getInputData: () => items.map((json) => ({ json })),
		getNodeParameter(name, itemIndex, fallback) {
			const source = typeof params === 'function' ? params(itemIndex) : params;
			const value = getPath(source, name);
			if (value === undefined) {
				if (arguments.length >= 3) return fallback;
				throw new Error(`Could not get parameter "${name}"`);
			}
			return structuredClone(value);
		},
		continueOnFail: () => continueOnFail,
		helpers: http ? { httpRequestWithAuthentication: http } : {},
	};
	if (!noGetNode) ctx.getNode = () => NODE;
	return ctx;
}

async function run(setup) {
	const node = new Anonymizator();
	const ctx = makeCtx(setup);
	const [out] = await node.execute.call(ctx);
	return out;
}

async function runError(setup) {
	try {
		await run(setup);
	} catch (error) {
		return error;
	}
	assert.fail('expected the node to throw');
}

// ---------------------------------------------------------------------------------------------
// Fake analyze (node-logic layer)

const DICTIONARY = [
	['Janez Novak', 'PERSON'],
	['Marko Horvat', 'PERSON'],
	['ana.kovac@example.com', 'EMAIL_ADDRESS'],
	['SI56 1910 0000 0123 438', 'IBAN'],
];

function detect(text, entityTypes) {
	const spans = [];
	for (const [value, type] of DICTIONARY) {
		if (entityTypes && !entityTypes.includes(type)) continue;
		let from = 0;
		for (;;) {
			const start = text.indexOf(value, from);
			if (start < 0) break;
			spans.push({ entity_type: type, start, end: start + value.length, score: 0.85 });
			from = start + value.length;
		}
	}
	return spans.sort((a, b) => a.start - b.start);
}

let analyzeCalls;
let analyzeBehaviour;

function installFakeAnalyze() {
	analyzeCalls = [];
	analyzeBehaviour = {};
	gateway.analyze = async (ctx, text, entityTypes, options) => {
		analyzeCalls.push({ ctx, text, entityTypes, options });
		if (analyzeBehaviour.throw) throw analyzeBehaviour.throw;
		return {
			spans: detect(text, entityTypes),
			entityFilterIgnored: analyzeBehaviour.entityFilterIgnored === true,
		};
	};
}

const RANDOM_PERSON = /^PERSON_[a-z0-9]{5}$/;
const SAMPLE = 'Janez Novak wrote from ana.kovac@example.com about SI56 1910 0000 0123 438.';

function protectParams(overrides = {}) {
	return { operation: 'protect', text: SAMPLE, ...overrides };
}

function revealParams(text, placeholderMap, options) {
	return { operation: 'reveal', text, placeholderMap, ...(options ? { options } : {}) };
}

function keyFor(map, value) {
	return Object.keys(map).find((key) => map[key] === value);
}

// ---------------------------------------------------------------------------------------------

describe('node description', () => {
	const { description } = new Anonymizator();

	test('credential is required for Protect only', () => {
		assert.deepEqual(description.credentials, [
			{
				name: 'anonymizatorApi',
				required: true,
				displayOptions: { show: { operation: ['protect'] } },
			},
		]);
		assert.equal(description.usableAsTool, true);
	});

	test('entity types list the whole catalog, sorted by name', () => {
		const prop = description.properties.find((p) => p.name === 'entityTypes');
		assert.equal(prop.type, 'multiOptions');
		assert.equal(prop.options.length, 16);
		const names = prop.options.map((o) => o.name);
		assert.deepEqual(
			names,
			[...names].sort((a, b) => a.localeCompare(b, 'en')),
		);
		assert.deepEqual(prop.displayOptions.show.detect, ['selected']);
	});

	test('protect options are alphabetical and default off', () => {
		const prop = description.properties.find(
			(p) => p.name === 'options' && p.displayOptions.show.operation[0] === 'protect',
		);
		assert.deepEqual(
			prop.options.map((o) => o.name),
			['existingPlaceholderMap', 'includeIdFile', 'includeInputFields', 'shareMapAcrossItems'],
		);
		for (const o of prop.options.filter((x) => x.type === 'boolean'))
			assert.equal(o.default, false);
	});
});

describe('Protect (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	test('all types, random style: placeholders, map with PERSON sub-keys, entities', async () => {
		const [item] = await run({ params: protectParams() });
		assert.deepEqual(item.pairedItem, { item: 0 });
		assert.equal(analyzeCalls.length, 1);
		assert.equal(analyzeCalls[0].entityTypes, undefined, 'all types omits the filter');
		assert.equal(analyzeCalls[0].text, SAMPLE);

		const { protectedText, placeholderMap, entities } = item.json;
		const person = keyFor(placeholderMap, 'Janez Novak');
		assert.match(person, RANDOM_PERSON);
		assert.equal(placeholderMap[`${person}_NAME`], 'Janez');
		assert.equal(placeholderMap[`${person}_SURNAME`], 'Novak');
		assert.match(keyFor(placeholderMap, 'ana.kovac@example.com'), /^EMAIL_ADDRESS_[a-z0-9]{5}$/);
		assert.match(keyFor(placeholderMap, 'SI56 1910 0000 0123 438'), /^IBAN_[a-z0-9]{5}$/);
		for (const value of ['Janez', 'ana.kovac', 'SI56']) {
			assert.ok(!protectedText.includes(value), `${value} must not survive`);
		}
		assert.equal(entities.length, 3);
		for (const entity of entities) {
			assert.equal(protectedText.slice(entity.start, entity.end), entity.placeholder);
			assert.equal(entity.score, 0.85);
		}
		assert.deepEqual(
			entities.map((e) => e.entityType),
			['PERSON', 'EMAIL_ADDRESS', 'IBAN'],
		);
		assert.ok(!('entityFilterIgnored' in item.json));
		assert.ok(!('idFile' in item.json));
	});

	test('round trip through Reveal restores the original text', async () => {
		const [protectedItem] = await run({ params: protectParams() });
		const [revealed] = await run({
			params: revealParams(protectedItem.json.protectedText, protectedItem.json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, SAMPLE);
		assert.deepEqual(revealed.json.unresolvedPlaceholders, []);
	});

	test('selected types send the mapped server types', async () => {
		await run({ params: protectParams({ detect: 'selected', entityTypes: ['PERSON', 'IBAN'] }) });
		assert.deepEqual(analyzeCalls[0].entityTypes, ['PERSON', 'IBAN', 'IBAN_CODE']);
	});

	test('selecting every type is the same as all types', async () => {
		const { description } = new Anonymizator();
		const all = description.properties
			.find((p) => p.name === 'entityTypes')
			.options.map((o) => o.value);
		await run({ params: protectParams({ detect: 'selected', entityTypes: all }) });
		assert.equal(analyzeCalls[0].entityTypes, undefined);
	});

	test('entity types are ignored while detect is all (hidden parameter keeps its value)', async () => {
		await run({ params: protectParams({ detect: 'all', entityTypes: ['PERSON'] }) });
		assert.equal(analyzeCalls[0].entityTypes, undefined);
	});

	test('entityFilterIgnored is reported only when true', async () => {
		analyzeBehaviour.entityFilterIgnored = true;
		const [item] = await run({
			params: protectParams({ detect: 'selected', entityTypes: ['PERSON'] }),
		});
		assert.equal(item.json.entityFilterIgnored, true);
	});

	test('sequential style numbers per type', async () => {
		const [item] = await run({
			params: protectParams({
				text: 'Janez Novak and Marko Horvat; Janez Novak again.',
				placeholderStyle: 'sequential',
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON_1] and [PERSON_2]; [PERSON_1] again.');
		assert.deepEqual(item.json.placeholderMap, {
			PERSON_1: 'Janez Novak',
			PERSON_1_NAME: 'Janez',
			PERSON_1_SURNAME: 'Novak',
			PERSON_2: 'Marko Horvat',
			PERSON_2_NAME: 'Marko',
			PERSON_2_SURNAME: 'Horvat',
		});
	});

	test('typed style masks with the type and keeps no map', async () => {
		const [item] = await run({
			params: protectParams({
				placeholderStyle: 'typed',
				options: { includeIdFile: true },
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON] wrote from [EMAIL_ADDRESS] about [IBAN].');
		assert.deepEqual(item.json.placeholderMap, {});
		assert.ok(!('idFile' in item.json), 'masked output has nothing to save');
		for (const e of item.json.entities) {
			assert.equal(item.json.protectedText.slice(e.start, e.end), e.placeholder);
		}
	});

	test('redacted style', async () => {
		const [item] = await run({ params: protectParams({ placeholderStyle: 'redacted' }) });
		assert.equal(item.json.protectedText, '[REDACTED] wrote from [REDACTED] about [REDACTED].');
		assert.deepEqual(item.json.placeholderMap, {});
		assert.deepEqual(
			item.json.entities.map((e) => e.entityType),
			['PERSON', 'EMAIL_ADDRESS', 'IBAN'],
		);
	});

	test('existing map: known values reuse placeholders, sequential numbering continues', async () => {
		const [item] = await run({
			params: protectParams({
				text: 'Marko Horvat met Janez Novak.',
				placeholderStyle: 'sequential',
				options: {
					existingPlaceholderMap: JSON.stringify({ '[PERSON_1]': 'Janez Novak' }),
				},
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON_2] met [PERSON_1].');
		assert.equal(item.json.placeholderMap.PERSON_1, 'Janez Novak');
		assert.equal(item.json.placeholderMap.PERSON_2, 'Marko Horvat');
	});

	test('existing map values are protected even when the gateway misses them', async () => {
		const [item] = await run({
			params: protectParams({
				text: 'Ask Orion about it.',
				options: { existingPlaceholderMap: { PROJECT_x1y2z: 'Orion' } },
			}),
		});
		assert.equal(item.json.protectedText, 'Ask [PROJECT_x1y2z] about it.');
		assert.deepEqual(item.json.placeholderMap, { PROJECT_x1y2z: 'Orion' });
	});

	test('existing ID file: tombstoned placeholders are never reused', async () => {
		const idFile = {
			format: 'anonymizator-id-file',
			version: 1,
			name: 'test',
			numbering: 'sequential',
			ids: [{ value: 'Janez Novak', placeholder: '[PERSON_1]', addedByYou: false }],
			usedPlaceholders: ['[PERSON_1]', '[PERSON_2]'],
		};
		const [item] = await run({
			params: protectParams({
				text: 'Marko Horvat',
				placeholderStyle: 'sequential',
				options: { existingPlaceholderMap: idFile, includeIdFile: true },
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON_3]');
		// The retired PERSON_2 stays in the output map as an empty (retired) entry, not in the ID file.
		assert.equal(item.json.placeholderMap.PERSON_2, '');
		assert.ok(!item.json.idFile.ids.some((entry) => entry.placeholder === '[PERSON_2]'));
		assert.ok(item.json.idFile.usedPlaceholders.includes('[PERSON_2]'));
	});

	test('retired placeholders survive a round trip through the output map', async () => {
		const idFile = {
			format: 'anonymizator-id-file',
			version: 1,
			name: 'test',
			numbering: 'sequential',
			ids: [{ value: 'Ana Old', placeholder: '[PERSON_1]', addedByYou: false }],
			usedPlaceholders: ['[PERSON_1]', '[PERSON_2]'],
		};
		const [first] = await run({
			params: protectParams({
				text: 'nothing here',
				placeholderStyle: 'sequential',
				options: { existingPlaceholderMap: idFile },
			}),
		});
		assert.deepEqual(first.json.placeholderMap, { PERSON_1: 'Ana Old', PERSON_2: '' });
		const [second] = await run({
			params: protectParams({
				text: 'Janez Novak wrote',
				placeholderStyle: 'sequential',
				options: { existingPlaceholderMap: first.json.placeholderMap, includeIdFile: true },
			}),
		});
		assert.equal(second.json.protectedText, '[PERSON_3] wrote');
		assert.equal(second.json.placeholderMap.PERSON_2, '');
		assert.ok(second.json.idFile.usedPlaceholders.includes('[PERSON_2]'));
		// Reveal treats the empty entry as retired: [PERSON_2] is left alone, not erased.
		const [revealed] = await run({
			params: revealParams('[PERSON_2] and [PERSON_3]', second.json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, '[PERSON_2] and Janez Novak');
		assert.deepEqual(revealed.json.unresolvedPlaceholders, ['[PERSON_2]']);
	});

	test('an unknown placeholder style set by expression is refused', async () => {
		const error = await runError({ params: protectParams({ placeholderStyle: 'bogus' }) });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /Unknown placeholder style/);
		assert.equal(analyzeCalls.length, 0);
	});

	test('a whole Protect output item with an input field named format is unwrapped', async () => {
		const [protectedItem] = await run({
			items: [{ format: 'markdown', body: 'Hi Janez Novak' }],
			params: protectParams({ text: 'Hi Janez Novak', options: { includeInputFields: true } }),
		});
		assert.equal(protectedItem.json.format, 'markdown');
		const [revealed] = await run({
			params: revealParams(protectedItem.json.protectedText, protectedItem.json),
		});
		assert.equal(revealed.json.revealedText, 'Hi Janez Novak');
	});

	test('a bad existing map is a NodeOperationError for that item', async () => {
		const error = await runError({
			params: protectParams({ options: { existingPlaceholderMap: '{"person 1": 5' } }),
		});
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /^Existing Placeholder Map: /);
		assert.equal(error.context.itemIndex, 0);
		assert.equal(analyzeCalls.length, 0, 'nothing is sent when the map is bad');
	});

	test('share map across items OFF: every item starts from its own map', async () => {
		const texts = ['Janez Novak', 'Marko Horvat and Janez Novak'];
		const out = await run({
			items: texts.map((text) => ({ text })),
			params: (i) => protectParams({ text: texts[i], placeholderStyle: 'sequential' }),
		});
		assert.equal(out[0].json.protectedText, '[PERSON_1]');
		assert.equal(out[1].json.protectedText, '[PERSON_1] and [PERSON_2]');
		assert.equal(out[1].json.placeholderMap.PERSON_1, 'Marko Horvat');
		assert.deepEqual(
			out.map((o) => o.pairedItem),
			[{ item: 0 }, { item: 1 }],
		);
	});

	test('share map across items ON: one running map, output as it stands per item', async () => {
		const texts = ['Janez Novak', 'Marko Horvat and Janez Novak'];
		const out = await run({
			items: texts.map((text) => ({ text })),
			params: (i) => protectParams({ text: texts[i], options: { shareMapAcrossItems: true } }),
		});
		const janez = keyFor(out[0].json.placeholderMap, 'Janez Novak');
		assert.match(janez, RANDOM_PERSON);
		assert.equal(out[0].json.protectedText, `[${janez}]`);
		assert.equal(keyFor(out[0].json.placeholderMap, 'Marko Horvat'), undefined);
		const marko = keyFor(out[1].json.placeholderMap, 'Marko Horvat');
		assert.equal(out[1].json.protectedText, `[${marko}] and [${janez}]`);
		assert.equal(out[1].json.placeholderMap[janez], 'Janez Novak');
	});

	test('share map across items ON: seeded by each item, conflicts fail that item', async () => {
		const maps = [{ PERSON_1: 'Janez Novak' }, { PERSON_1: 'Marko Horvat' }];
		const params = (i) =>
			protectParams({
				text: 'Hello',
				options: { shareMapAcrossItems: true, existingPlaceholderMap: maps[i] },
			});
		const error = await runError({ items: [{}, {}], params });
		assert.ok(error instanceof NodeOperationError);
		assert.equal(error.context.itemIndex, 1);
		assert.match(error.message, /PERSON_1/);

		const out = await run({ items: [{}, {}], params, continueOnFail: true });
		assert.equal(out.length, 2);
		assert.deepEqual(out[0].json.placeholderMap, { PERSON_1: 'Janez Novak' });
		assert.match(out[1].json.error, /PERSON_1/);
		assert.deepEqual(out[1].pairedItem, { item: 1 });
	});

	test('share map ON with compatible seeds merges them', async () => {
		const maps = [
			{ PERSON_1: 'Janez Novak' },
			{ PERSON_1: 'Janez Novak', EMAIL_ADDRESS_1: 'x@example.com' },
		];
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					text: 'Marko Horvat',
					placeholderStyle: 'sequential',
					options: { shareMapAcrossItems: true, existingPlaceholderMap: maps[i] },
				}),
		});
		assert.equal(out[0].json.protectedText, '[PERSON_2]');
		assert.equal(out[1].json.protectedText, '[PERSON_2]');
		assert.equal(out[1].json.placeholderMap.EMAIL_ADDRESS_1, 'x@example.com');
	});

	test('includeIdFile adds an extension-loadable ID file that round-trips', async () => {
		const [item] = await run({ params: protectParams({ options: { includeIdFile: true } }) });
		const { idFile, placeholderMap } = item.json;
		assert.equal(idFile.format, 'anonymizator-id-file');
		assert.equal(idFile.version, 1);
		assert.equal(idFile.numbering, 'random');
		assert.equal(idFile.ids.length, Object.keys(placeholderMap).length);
		for (const entry of idFile.ids) {
			assert.match(entry.placeholder, /^\[[A-Z][A-Za-z0-9_]*\]$/);
			assert.equal(entry.addedByYou, false);
			assert.equal(placeholderMap[entry.placeholder.slice(1, -1)], entry.value);
		}
		const [revealed] = await run({
			params: revealParams(item.json.protectedText, JSON.stringify(idFile)),
		});
		assert.equal(revealed.json.revealedText, SAMPLE);
	});

	test('includeIdFile with nothing detected omits the file', async () => {
		const [item] = await run({
			params: protectParams({ text: 'Nothing here.', options: { includeIdFile: true } }),
		});
		assert.equal(item.json.protectedText, 'Nothing here.');
		assert.ok(!('idFile' in item.json));
	});

	test('includeIdFile on a map the extension would refuse names the option', async () => {
		const error = await runError({
			params: protectParams({
				options: {
					existingPlaceholderMap: { PERSON_1: 'Janez Novak', PERSON_2: 'Janez Novak' },
					includeIdFile: true,
				},
			}),
		});
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /^Include ID File: /);
		assert.match(error.description, /Turn off Include ID File/);
		assert.equal(error.context.itemIndex, 0);
	});

	test('includeInputFields copies the input item, results win on clashes', async () => {
		const [item] = await run({
			items: [{ id: 7, protectedText: 'stale', text: SAMPLE }],
			params: protectParams({ options: { includeInputFields: true } }),
		});
		assert.equal(item.json.id, 7);
		assert.equal(item.json.text, SAMPLE);
		assert.notEqual(item.json.protectedText, 'stale');
		const [plain] = await run({ items: [{ id: 7 }], params: protectParams() });
		assert.ok(!('id' in plain.json));
	});

	test('blank text never reaches the gateway', async () => {
		const [item] = await run({ params: protectParams({ text: '   ' }) });
		assert.equal(analyzeCalls.length, 0);
		assert.equal(item.json.protectedText, '   ');
		assert.deepEqual(item.json.entities, []);
	});

	test('a non-text expression result is refused clearly', async () => {
		const error = await runError({ params: protectParams({ text: { a: 1 } }) });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /must be text/);
	});
});

describe('gateway failures (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const cases = [
		['auth_required', 302, NodeApiError, /API key was rejected/],
		['no_access', 403, NodeApiError, /no access/],
		['hpke_stale', 400, NodeApiError, /clock/],
		['rate_limited', 429, NodeApiError, /Too many requests/],
		['text_too_large', 413, NodeApiError, /too large/],
		['server_error', 502, NodeApiError, /temporarily unavailable/],
		['hpke_unverified_keyconfig', 200, NodeOperationError, /could not be verified/],
		['hpke_bad_keyconfig', 200, NodeOperationError, /configuration is invalid/],
		['hpke_bad_response', 200, NodeOperationError, /could not be decrypted/],
		['hpke_seal_failed', undefined, NodeOperationError, /could not be encrypted/],
		['offline', undefined, NodeOperationError, /Could not reach/],
		['timeout', undefined, NodeOperationError, /did not answer in time/],
		['http_404', 404, NodeApiError, /unexpected status \(HTTP 404\)/],
	];

	for (const [code, httpCode, ErrorClass, pattern] of cases) {
		test(`${code} becomes ${ErrorClass.name}`, async () => {
			analyzeBehaviour.throw = new GatewayError(code, `raw ${code}`, httpCode, 'some detail');
			const error = await runError({ params: protectParams() });
			assert.ok(error instanceof ErrorClass, `${error.constructor.name}: ${error.message}`);
			assert.match(error.message, pattern);
			assert.match(error.description, new RegExp(`\\(code: ${code}\\)`));
			assert.match(error.description, /some detail/);
			assert.equal(error.context.itemIndex, 0);
			if (ErrorClass === NodeApiError) assert.equal(error.httpCode, String(httpCode));
		});
	}

	test('a 5xx on a very large text advises splitting, not retrying', async () => {
		// What gateway.analyze throws for a 5xx on a sealed body over LARGE_BODY_BYTES (not retried).
		analyzeBehaviour.throw = new GatewayError(
			'text_too_large',
			'The Anonymizator gateway could not analyse a very large text (1000000 characters); split it into smaller items',
			502,
		);
		const error = await runError({ params: protectParams() });
		assert.ok(error instanceof NodeApiError);
		assert.equal(error.httpCode, '502');
		assert.match(error.message, /too large/);
		assert.match(error.description, /Split the text/);
		assert.doesNotMatch(error.description, /twice|later/);
	});

	test('continueOnFail turns the failure into an error item and keeps going', async () => {
		let calls = 0;
		gateway.analyze = async (ctx, text) => {
			calls += 1;
			if (calls === 1) throw new GatewayError('auth_required', 'raw', 302);
			return { spans: detect(text), entityFilterIgnored: false };
		};
		const out = await run({
			items: [{}, {}],
			params: protectParams({ text: 'Janez Novak' }),
			continueOnFail: true,
		});
		assert.equal(out.length, 2);
		assert.deepEqual(out[0], {
			json: { error: 'The Anonymizator API key was rejected' },
			pairedItem: { item: 0 },
		});
		assert.match(out[1].json.protectedText, /^\[PERSON_[a-z0-9]{5}\]$/);
		assert.deepEqual(out[1].pairedItem, { item: 1 });
	});

	test('AI tool context without getNode still reports the real failure', async () => {
		analyzeBehaviour.throw = new GatewayError('no_access', 'raw', 403, 'missing_role');
		const error = await runError({ params: protectParams(), noGetNode: true });
		assert.ok(error instanceof NodeApiError);
		assert.match(error.message, /no access/);
		assert.equal(error.node.name, 'Anonymizator');
	});

	test('an unexpected error is wrapped, never rethrown raw', async () => {
		analyzeBehaviour.throw = new TypeError('boom');
		const error = await runError({ params: protectParams() });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /boom/);
	});
});

describe('Reveal', () => {
	beforeEach(() => {
		installFakeAnalyze();
		gateway.analyze = async () => assert.fail('Reveal must never call the gateway');
	});

	const TEXT =
		'Dear [PERSON_a7k2q] ([PERSON_a7k2q_NAME]), mail EMAIL_ADDRESS_q1w2e. [PERSON_zzzzz] [REDACTED]';
	const EXPECTED =
		'Dear Janez Novak (Janez), mail ana.kovac@example.com. [PERSON_zzzzz] [REDACTED]';
	const TABLE = {
		PERSON_a7k2q: 'Janez Novak',
		PERSON_a7k2q_NAME: 'Janez',
		PERSON_a7k2q_SURNAME: 'Novak',
		EMAIL_ADDRESS_q1w2e: 'ana.kovac@example.com',
	};
	const bracketed = Object.fromEntries(Object.entries(TABLE).map(([k, v]) => [`[${k}]`, v]));
	const formats = {
		'bare-key object': TABLE,
		'bracketed-key object': bracketed,
		'JSON string': JSON.stringify(TABLE),
		'array of {placeholder, value}': Object.entries(TABLE).map(([k, v]) => ({
			placeholder: `[${k}]`,
			value: v,
		})),
		'extension ID file v1': {
			format: 'anonymizator-id-file',
			version: 1,
			name: '20261005T120000-anonymizator-ids',
			numbering: 'random',
			ids: Object.entries(TABLE).map(([k, v]) => ({
				value: v,
				placeholder: `[${k}]`,
				addedByYou: false,
			})),
			usedPlaceholders: Object.keys(TABLE).map((k) => `[${k}]`),
		},
	};

	for (const [label, map] of Object.entries(formats)) {
		test(`accepts a ${label}, with no credentials helper at all`, async () => {
			const [item] = await run({ params: revealParams(TEXT, map) });
			assert.deepEqual(item.json, {
				revealedText: EXPECTED,
				unresolvedPlaceholders: ['[PERSON_zzzzz]', '[REDACTED]'],
			});
			assert.deepEqual(item.pairedItem, { item: 0 });
		});
	}

	test('empty values (tombstones) never erase text', async () => {
		const [item] = await run({
			params: revealParams('Hi [PERSON_1] and [PERSON_2]', { PERSON_1: 'Janez', PERSON_2: '' }),
		});
		assert.equal(item.json.revealedText, 'Hi Janez and [PERSON_2]');
		assert.deepEqual(item.json.unresolvedPlaceholders, ['[PERSON_2]']);
	});

	test('includeInputFields keeps the input item', async () => {
		const [item] = await run({
			items: [{ ticket: 42 }],
			params: revealParams('Hi [PERSON_1]', { PERSON_1: 'Janez' }, { includeInputFields: true }),
		});
		assert.deepEqual(item.json, {
			ticket: 42,
			revealedText: 'Hi Janez',
			unresolvedPlaceholders: [],
		});
	});

	test('a bad map is a NodeOperationError naming the parameter', async () => {
		const error = await runError({ params: revealParams('x', '{not json') });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /^Placeholder Map: /);
		assert.match(error.description, /Accepted formats/);
		const out = await run({ params: revealParams('x', '{not json'), continueOnFail: true });
		assert.match(out[0].json.error, /^Placeholder Map: /);
	});

	test('mixed operations per item: reveal items never touch the gateway', async () => {
		installFakeAnalyze();
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				i === 0 ? protectParams({ text: 'Janez Novak' }) : revealParams('[X_1]', { X_1: 'ok' }),
		});
		assert.equal(analyzeCalls.length, 1);
		assert.equal(out[1].json.revealedText, 'ok');
	});
});

// ---------------------------------------------------------------------------------------------
// Full stack: real gateway.ts + fake HPKE recipient behind httpRequestWithAuthentication

const SUITE_ID = Buffer.from('HPKE\x00\x20\x00\x01\x00\x02', 'latin1');
const KEM_ID = Buffer.from('KEM\x00\x20', 'latin1');
const HPKE_V1 = Buffer.from('HPKE-v1');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

const hmac = (key, data) =>
	createHmac('sha256', key.length ? key : Buffer.alloc(32))
		.update(data)
		.digest();
function expand(prk, info, length) {
	const out = [];
	let t = Buffer.alloc(0);
	for (let i = 1; Buffer.concat(out).length < length; i++) {
		t = hmac(prk, Buffer.concat([t, info, Buffer.from([i])]));
		out.push(t);
	}
	return Buffer.concat(out).subarray(0, length);
}
const lExtract = (sid, salt, label, ikm) =>
	hmac(salt, Buffer.concat([HPKE_V1, sid, Buffer.from(label), ikm]));
const lExpand = (sid, prk, label, info, length) =>
	expand(
		prk,
		Buffer.concat([
			Buffer.from([length >> 8, length & 255]),
			HPKE_V1,
			sid,
			Buffer.from(label),
			info,
		]),
		length,
	);

/** A real HPKE recipient (RFC 9180 base mode, X25519/HKDF-SHA256/AES-256-GCM). */
function makeRecipient() {
	const { privateKey, publicKey } = generateKeyPairSync('x25519');
	const pkR = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
	return {
		pkR,
		open(frame) {
			assert.ok(Buffer.isBuffer(frame), 'the request body must be a Buffer');
			assert.equal(frame[0], 1);
			const prefix = frame.subarray(0, 13);
			const keyId = frame.readUInt32BE(1);
			const timestamp = Number(frame.readBigUInt64BE(5));
			const enc = frame.subarray(13, 45);
			const ct = frame.subarray(45);
			const pkE = createPublicKey({
				key: Buffer.concat([X25519_SPKI, enc]),
				format: 'der',
				type: 'spki',
			});
			const dh = diffieHellman({ privateKey, publicKey: pkE });
			const eae = lExtract(KEM_ID, Buffer.alloc(0), 'eae_prk', dh);
			const shared = lExpand(KEM_ID, eae, 'shared_secret', Buffer.concat([enc, pkR]), 32);
			const empty = Buffer.alloc(0);
			const ctx = Buffer.concat([
				Buffer.from([0]),
				lExtract(SUITE_ID, empty, 'psk_id_hash', empty),
				lExtract(SUITE_ID, empty, 'info_hash', empty),
			]);
			const secret = lExtract(SUITE_ID, shared, 'secret', empty);
			const key = lExpand(SUITE_ID, secret, 'key', ctx, 32);
			const nonce = lExpand(SUITE_ID, secret, 'base_nonce', ctx, 12);
			const exporter = lExpand(SUITE_ID, secret, 'exp', ctx, 32);
			const decipher = createDecipheriv('aes-256-gcm', key, nonce);
			decipher.setAAD(prefix);
			decipher.setAuthTag(ct.subarray(ct.length - 16));
			const pt = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
			const keyNonce = lExpand(SUITE_ID, exporter, 'sec', Buffer.from('pgw response v1'), 44);
			return {
				keyId,
				timestamp,
				paddedLength: pt.length,
				payload: JSON.parse(pt.toString('utf8').trimEnd()),
				seal(object) {
					const cipher = createCipheriv(
						'aes-256-gcm',
						keyNonce.subarray(0, 32),
						keyNonce.subarray(32),
					);
					const body = Buffer.from(JSON.stringify(object).padEnd(256, ' '), 'utf8');
					return Buffer.concat([
						Buffer.from([1]),
						cipher.update(body),
						cipher.final(),
						cipher.getAuthTag(),
					]);
				},
			};
		},
	};
}

function makeRoot() {
	const { privateKey, publicKey } = generateKeyPairSync('ed25519');
	return {
		privateKey,
		b64url: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
	};
}

function signedKeyconfig(root, keyId, pkR) {
	const keys = [
		{
			key_id: keyId,
			public_key: pkR.toString('base64url'),
			suite: { kem: 32, kdf: 1, aead: 2 },
			not_after: '2030-01-01T00:00:00Z',
		},
	];
	const message = `pgw-keyconfig-v1\n${keyId}:${keys[0].public_key}\n`;
	return {
		version: 1,
		keys,
		sig_alg: 'ed25519-v1',
		signature: sign(null, Buffer.from(message), root.privateKey).toString('base64url'),
	};
}

const json = (statusCode, object) => ({
	statusCode,
	headers: { 'content-type': 'application/json' },
	body: Buffer.from(JSON.stringify(object)),
});

/**
 * Fake gateway behind httpRequestWithAuthentication. `analyzeHandler(opened, request)` returns a
 * full response; default: seal the dictionary spans.
 */
function makeGateway({ root, signer = root, analyzeHandler } = {}) {
	const recipient = makeRecipient();
	const requests = [];
	const keyconfig = signedKeyconfig(signer, 7, recipient.pkR);
	async function http(credentialName, options) {
		assert.equal(this, ctxRef.current, 'helper must be called with the execute context as this');
		assert.equal(credentialName, 'anonymizatorApi');
		assert.equal(options.disableFollowRedirect, true);
		requests.push(options);
		const url = `${options.baseURL ?? ''}${options.url}`;
		if (options.method === 'GET' && url === 'https://anon.prosecco37.com/v1/keyconfig') {
			return json(200, keyconfig);
		}
		if (options.method === 'POST' && url === 'https://anon.prosecco37.com/v1/analyze') {
			const opened = recipient.open(options.body);
			if (analyzeHandler) return analyzeHandler(opened, options);
			return {
				statusCode: 200,
				headers: { 'content-type': 'application/octet-stream' },
				body: opened.seal({ entities: detect(opened.payload.text, opened.payload.entities) }),
			};
		}
		return json(404, { error: 'not_found' });
	}
	return { http, requests, recipient };
}

const ctxRef = { current: undefined };

async function runFull(setup) {
	const node = new Anonymizator();
	const ctx = makeCtx(setup);
	ctxRef.current = ctx;
	const [out] = await node.execute.call(ctx);
	return out;
}

async function runFullError(setup) {
	try {
		await runFull(setup);
	} catch (error) {
		return error;
	}
	assert.fail('expected the node to throw');
}

describe('full stack (real gateway.ts, fake HPKE recipient)', () => {
	const root = makeRoot();

	beforeEach(() => {
		gateway.analyze = (ctx, text, entityTypes) =>
			realAnalyze(ctx, text, entityTypes, { trustRootB64url: root.b64url, retryDelayMs: 1 });
		gateway.clearKeyconfigCache();
	});

	test('protect seals the text, the body carries no plaintext, offsets survive emoji', async () => {
		const fake = makeGateway({ root });
		const text = '😀😀 Janez Novak, ana.kovac@example.com';
		const [item] = await runFull({ params: protectParams({ text }), http: fake.http });
		const post = fake.requests.find((r) => r.method === 'POST');
		assert.ok(Buffer.isBuffer(post.body));
		const latin = post.body.toString('latin1');
		for (const needle of ['Janez', 'ana.kovac', '"text"']) assert.ok(!latin.includes(needle));
		const person = keyFor(item.json.placeholderMap, 'Janez Novak');
		const email = keyFor(item.json.placeholderMap, 'ana.kovac@example.com');
		assert.equal(item.json.protectedText, `😀😀 [${person}], [${email}]`);
		const [revealed] = await runFull({
			params: revealParams(item.json.protectedText, item.json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, text);
	});

	test('selected types reach the gateway inside the sealed payload', async () => {
		let seen;
		const fake = makeGateway({
			root,
			analyzeHandler: (opened) => {
				seen = opened.payload;
				return {
					statusCode: 200,
					headers: { 'content-type': 'application/octet-stream' },
					body: opened.seal({ entities: [] }),
				};
			},
		});
		await runFull({
			params: protectParams({ detect: 'selected', entityTypes: ['EMAIL_ADDRESS', 'IBAN'] }),
			http: fake.http,
		});
		assert.deepEqual(seen.entities, ['EMAIL_ADDRESS', 'IBAN', 'IBAN_CODE']);
		assert.equal(seen.text, SAMPLE);
	});

	test('sealed invalid_entities: retried once without the filter and flagged', async () => {
		const payloads = [];
		const fake = makeGateway({
			root,
			analyzeHandler: (opened) => {
				payloads.push(opened.payload);
				if (opened.payload.entities) {
					return {
						statusCode: 400,
						headers: { 'content-type': 'application/octet-stream' },
						body: opened.seal({ error: 'invalid_entities', detail: 'unknown entity type' }),
					};
				}
				return {
					statusCode: 200,
					headers: { 'content-type': 'application/octet-stream' },
					body: opened.seal({ entities: detect(opened.payload.text) }),
				};
			},
		});
		const [item] = await runFull({
			params: protectParams({ detect: 'selected', entityTypes: ['PERSON'] }),
			http: fake.http,
		});
		assert.equal(payloads.length, 2);
		assert.ok(!('entities' in payloads[1]));
		assert.equal(item.json.entityFilterIgnored, true);
	});

	test('302 from the BFF means the API key was rejected', async () => {
		const fake = makeGateway({
			root,
			analyzeHandler: () => ({
				statusCode: 302,
				headers: { location: '/auth/login' },
				body: Buffer.alloc(0),
			}),
		});
		const error = await runFullError({ params: protectParams(), http: fake.http });
		assert.ok(error instanceof NodeApiError);
		assert.match(error.message, /API key was rejected/);
		assert.equal(error.httpCode, '302');
	});

	test('403 missing_role means no access', async () => {
		const fake = makeGateway({ root, analyzeHandler: () => json(403, { error: 'missing_role' }) });
		const error = await runFullError({ params: protectParams(), http: fake.http });
		assert.match(error.message, /no access/);
	});

	test('hpke_stale is reported as a clock problem', async () => {
		const fake = makeGateway({ root, analyzeHandler: () => json(400, { error: 'hpke_stale' }) });
		const error = await runFullError({ params: protectParams(), http: fake.http });
		assert.match(error.message, /clock/);
	});

	test('a keyconfig not signed by the trust root fails closed: nothing is sent', async () => {
		const fake = makeGateway({ root, signer: makeRoot() });
		const error = await runFullError({ params: protectParams(), http: fake.http });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /could not be verified/);
		assert.equal(fake.requests.filter((r) => r.method === 'POST').length, 0);
	});

	test('continueOnFail with a rejected key yields an error item', async () => {
		const fake = makeGateway({ root, analyzeHandler: () => json(401, {}) });
		const out = await runFull({ params: protectParams(), http: fake.http, continueOnFail: true });
		assert.deepEqual(out, [
			{ json: { error: 'The Anonymizator API key was rejected' }, pairedItem: { item: 0 } },
		]);
	});

	test('reveal makes no request even when a helper is available', async () => {
		const fake = makeGateway({ root });
		const [item] = await runFull({
			params: revealParams('[PERSON_1]', { PERSON_1: 'Janez Novak' }),
			http: fake.http,
		});
		assert.equal(item.json.revealedText, 'Janez Novak');
		assert.equal(fake.requests.length, 0);
	});
});
