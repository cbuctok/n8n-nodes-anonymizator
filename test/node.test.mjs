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
	capabilitiesText,
	ed25519Signer,
	json,
	makeFakeGateway,
	makeTrustChain,
	octet,
} from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const DIST = fileURLToPath(new URL('../dist/nodes/Anonymizator/', import.meta.url));

const { Anonymizator } = require(`${DIST}Anonymizator.node.js`);
const gateway = require(`${DIST}shared/gateway.js`);
const { GatewayError } = require(`${DIST}shared/errors.js`);
const { ENTITY_CATALOG } = require(`${DIST}shared/entities.js`);
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

const realAnalyze = gateway.analyze;
const realFetchCapabilities = gateway.fetchCapabilities;
after(() => {
	gateway.analyze = realAnalyze;
	gateway.fetchCapabilities = realFetchCapabilities;
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

/** A load-options context with a credential selected (the editor sends it with the request). */
function withCredential(ctx) {
	ctx.getCredentials = async () => ({ apiKey: 'test' });
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
let capabilitiesCalls;
/** What the fake fetchCapabilities returns (null = no verified document, the bundled catalog). */
let fakeCapabilities;

function installFakeAnalyze() {
	analyzeCalls = [];
	analyzeBehaviour = {};
	capabilitiesCalls = 0;
	fakeCapabilities = null;
	gateway.analyze = async (ctx, text, entityTypes, options) => {
		analyzeCalls.push({ ctx, text, entityTypes, options });
		if (analyzeBehaviour.throw) throw analyzeBehaviour.throw;
		return {
			spans: analyzeBehaviour.spans ? analyzeBehaviour.spans(text) : detect(text, entityTypes),
			possible:
				options?.possible === true && analyzeBehaviour.possible
					? analyzeBehaviour.possible(text)
					: [],
			entityFilterIgnored: analyzeBehaviour.entityFilterIgnored === true,
		};
	};
	gateway.fetchCapabilities = async () => {
		capabilitiesCalls += 1;
		return fakeCapabilities;
	};
}

/** A minimal verified-capabilities shape (what gateway.fetchCapabilities resolves to). */
function makeCapabilities({ entities = [], possible = [], labels = [], groups = [] } = {}) {
	return {
		version: 1,
		serverVersion: '2026.10.19.1',
		issuedAt: 1790000000,
		languages: ['en'],
		labelLanguages: ['en'],
		maxTextChars: 120000,
		maxBodyBytes: 2097152,
		features: [],
		groups,
		entities,
		possible,
		labels: new Map(labels.map(([ref, text]) => [ref, new Map([['en', text]])])),
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

	test('credential is required for Protect and Detect only', () => {
		assert.deepEqual(description.credentials, [
			{
				name: 'anonymizatorApi',
				required: true,
				displayOptions: { show: { operation: ['protect', 'detect'] } },
			},
		]);
		assert.equal(description.usableAsTool, true);
	});

	test('entity types are loaded by getEntityTypes (dynamic multiOptions, n8n wording)', () => {
		const prop = description.properties.find((p) => p.name === 'entityTypes');
		assert.equal(prop.type, 'multiOptions');
		assert.equal(prop.typeOptions.loadOptionsMethod, 'getEntityTypes');
		assert.equal(prop.options, undefined);
		assert.deepEqual(prop.default, []);
		assert.match(prop.displayName, /Names or IDs$/);
		assert.match(
			prop.description,
			/Choose from the list, or specify IDs using an <a href="https:\/\/docs\.n8n\.io\/code\/expressions\/">expression<\/a>\.?$/,
		);
		assert.deepEqual(prop.displayOptions.show.detect, ['selected']);
		assert.equal(typeof new Anonymizator().methods.loadOptions.getEntityTypes, 'function');
	});

	test('placeholder styles use the extension names; values and default unchanged', () => {
		const prop = description.properties.find((p) => p.name === 'placeholderStyle');
		assert.deepEqual(
			prop.options.map((o) => [o.name, o.value]),
			[
				['Random', 'random'],
				['Numbers in Order', 'sequential'],
				['Type Only', 'typed'],
				['Redacted', 'redacted'],
			],
		);
		assert.equal(prop.default, 'random');
		assert.match(prop.description, /No option makes text anonymous/);
	});

	const optionsFor = (operation) =>
		description.properties.find(
			(p) => p.name === 'options' && p.displayOptions.show.operation[0] === operation,
		);

	test('protect options are alphabetical; only Include Placeholder Map defaults on', () => {
		const prop = optionsFor('protect');
		assert.deepEqual(
			prop.options.map((o) => o.name),
			[
				'additionallyProtect',
				'existingPlaceholderMap',
				'ignoreTerms',
				'includeIdFile',
				'includeInputFields',
				'includePlaceholderMap',
				'includePossibleIds',
				'shareMapAcrossItems',
			],
		);
		assert.deepEqual(
			prop.options.map((o) => o.displayName),
			[...prop.options.map((o) => o.displayName)].sort(),
		);
		for (const o of prop.options.filter((x) => x.type === 'boolean')) {
			assert.equal(o.default, o.name === 'includePlaceholderMap', o.name);
		}
		const existing = prop.options.find((o) => o.name === 'existingPlaceholderMap');
		assert.match(existing.placeholder, /^e\.g\. /);
		const extra = prop.options.find((o) => o.name === 'additionallyProtect');
		assert.equal(extra.type, 'multiOptions');
		assert.deepEqual(extra.default, []);
		assert.deepEqual(
			extra.options.map((o) => [o.name, o.value]),
			[
				['All Currency Values', 'AMOUNT'],
				['All Numbers', 'NUMBER'],
				['Company Names (With Legal Suffixes Only)', 'COMPANY'],
			],
		);
		const possible = prop.options.find((o) => o.name === 'includePossibleIds');
		assert.match(possible.description, /a prompt to look, not a score/);
	});

	test('detect options are alphabetical and default off', () => {
		const prop = optionsFor('detect');
		assert.deepEqual(
			prop.options.map((o) => o.name),
			['ignoreTerms', 'includeInputFields', 'includePossibleIds', 'includeValues'],
		);
		for (const o of prop.options.filter((x) => x.type === 'boolean'))
			assert.equal(o.default, false);
	});

	test('operations: Detect, Protect, Reveal; Protect stays the default', () => {
		const op = description.properties.find((p) => p.name === 'operation');
		assert.deepEqual(
			op.options.map((o) => [o.value, o.action]),
			[
				['detect', 'Detect personal data'],
				['protect', 'Protect text'],
				['reveal', 'Reveal text'],
			],
		);
		assert.equal(op.default, 'protect');
	});

	test('Detect shares Detect and Entity Types with Protect', () => {
		for (const name of ['detect', 'entityTypes']) {
			const prop = description.properties.find((p) => p.name === name);
			assert.deepEqual(prop.displayOptions.show.operation, ['protect', 'detect'], name);
		}
	});

	test('Reveal warns about agents and hints at the usual expressions without prefilling them', () => {
		const notice = description.properties.find((p) => p.name === 'revealNotice');
		assert.equal(notice.type, 'notice');
		assert.deepEqual(notice.displayOptions.show.operation, ['reveal']);
		assert.match(notice.displayName, /real values/);
		assert.match(notice.displayName, /agent/);
		const reveal = (name) =>
			description.properties.find(
				(p) => p.name === name && p.displayOptions?.show?.operation?.[0] === 'reveal',
			);
		assert.equal(reveal('text').default, '');
		assert.match(reveal('text').hint, /\{\{ \$json\.text \}\}/);
		assert.match(reveal('text').hint, /\{\{ \$json\.output \}\}/);
		assert.equal(reveal('placeholderMap').default, '{}');
		assert.match(reveal('placeholderMap').hint, /\$\('Protect'\)\.item\.json\.placeholderMap/);
		assert.match(reveal('placeholderMap').hint, /your Protect node's name/);
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
		// Placeholders use the extension's prefixes (EMAIL_ADDRESS -> EMAIL); entityType keeps the type.
		assert.match(keyFor(placeholderMap, 'ana.kovac@example.com'), /^EMAIL_[a-z0-9]{5}$/);
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
		assert.deepEqual(analyzeCalls[0].entityTypes, ['IBAN', 'IBAN_CODE', 'PERSON']);
	});

	test('selecting every type is the same as all types', async () => {
		const all = ENTITY_CATALOG.map((row) => row.id);
		await run({ params: protectParams({ detect: 'selected', entityTypes: all }) });
		assert.equal(analyzeCalls[0].entityTypes, undefined);
	});

	test('with verified capabilities, every built-in row still omits the field', async () => {
		fakeCapabilities = makeCapabilities({
			entities: [
				{ type: 'PERSON', default: 'on', groups: ['general'] },
				{ type: 'IT_FISCAL_CODE', default: 'on', groups: [] },
			],
		});
		const all = ENTITY_CATALOG.map((row) => row.id);
		await run({ params: protectParams({ detect: 'selected', entityTypes: all }) });
		assert.equal(analyzeCalls[0].entityTypes, undefined, 'server-only types are not dropped');
		await run({
			params: protectParams({ detect: 'selected', entityTypes: [...all, 'IT_FISCAL_CODE'] }),
		});
		assert.equal(analyzeCalls[1].entityTypes, undefined, 'every built-in row selected omits it');
		await run({
			params: protectParams({
				detect: 'selected',
				entityTypes: ['IT_FISCAL_CODE', 'EMAIL_ADDRESS'],
			}),
		});
		assert.deepEqual(analyzeCalls[2].entityTypes, ['EMAIL_ADDRESS', 'IT_FISCAL_CODE']);
	});

	test('an unknown TYPE-shaped id is sent (the gateway retry covers it); others are dropped', async () => {
		await run({
			params: protectParams({ detect: 'selected', entityTypes: ['PERSON', 'NEW_TYPE', 'bad id'] }),
		});
		assert.deepEqual(analyzeCalls[0].entityTypes, ['NEW_TYPE', 'PERSON']);
	});

	test('the per-request cap comes from the verified capabilities', async () => {
		await run({ params: protectParams() });
		assert.equal(analyzeCalls[0].options.maxTextChars, 10000, 'bundled cap without a document');
		fakeCapabilities = { ...makeCapabilities(), maxTextChars: 50000, maxBodyBytes: 2097152 };
		await run({ params: protectParams() });
		assert.equal(analyzeCalls[1].options.maxTextChars, 50000);
		assert.equal(analyzeCalls[1].options.possible, undefined, 'possible only when asked for');
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
		assert.equal(item.json.protectedText, '[PERSON] wrote from [EMAIL] about [IBAN].');
		assert.deepEqual(item.json.placeholderMap, {});
		// Include ID File writes no file for masked styles (the contract before extension parity).
		assert.ok(!('idFile' in item.json));
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
		assert.equal(idFile.version, 2);
		assert.equal(idFile.numbering, 'random');
		assert.equal(idFile.ids.length + idFile.nameParts.length, Object.keys(placeholderMap).length);
		assert.equal(idFile.nameParts.length, 2, 'the PERSON name parts');
		for (const entry of [...idFile.ids, ...idFile.nameParts]) {
			assert.match(entry.placeholder, /^\[[A-Z][A-Za-z0-9_]*\]$/);
			assert.equal(placeholderMap[entry.placeholder.slice(1, -1)], entry.value);
		}
		for (const entry of idFile.ids) assert.equal(entry.addedByYou, false);
		assert.deepEqual(idFile.ids.map((e) => e.type).sort(), ['EMAIL_ADDRESS', 'IBAN', 'PERSON']);
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

	test('includeIdFile: one value under two placeholders from shared items stays loadable', async () => {
		// Two shared items bring one value under two placeholders: as inside one flat map, the first
		// key protects and the second becomes reveal-only, so the extension accepts the file.
		const maps = [{ PERSON_1: 'Janez Novak' }, { PERSON_2: 'Janez Novak' }];
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					options: {
						existingPlaceholderMap: maps[i],
						shareMapAcrossItems: true,
						includeIdFile: true,
					},
				}),
		});
		assert.ok(out[1].json.protectedText.startsWith('[PERSON_1] wrote'));
		assert.equal(out[1].json.placeholderMap.PERSON_2, 'Janez Novak');
		assert.deepEqual(
			out[1].json.idFile.revealOnly.map((r) => [r.placeholder, r.of]),
			[['[PERSON_2]', '[PERSON_1]']],
		);
	});

	test('one value under two keys in a flat map: the first key protects, both reveal', async () => {
		const [item] = await run({
			params: protectParams({
				text: 'Hi Janez Novak',
				options: {
					existingPlaceholderMap: { PERSON_1: 'Janez Novak', PERSON_2: 'Janez Novak' },
					includeIdFile: true,
				},
			}),
		});
		assert.equal(item.json.protectedText, 'Hi [PERSON_1]');
		assert.equal(item.json.placeholderMap.PERSON_2, 'Janez Novak');
		assert.deepEqual(
			item.json.idFile.revealOnly.map((r) => r.placeholder),
			['[PERSON_2]'],
		);
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

describe('Include Placeholder Map (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	test('on by default: the map is in the output', async () => {
		const [item] = await run({ params: protectParams({ options: {} }) });
		assert.ok(keyFor(item.json.placeholderMap, 'Janez Novak'));
	});

	test('off: no placeholderMap, protected text and entities unchanged in shape', async () => {
		const [item] = await run({
			params: protectParams({ options: { includePlaceholderMap: false } }),
		});
		assert.ok(!('placeholderMap' in item.json));
		assert.ok(!('idFile' in item.json));
		assert.match(item.json.protectedText, /^\[PERSON_[a-z0-9]{5}\] wrote from \[EMAIL_/);
		assert.equal(item.json.entities.length, 3);
		for (const value of ['Janez', 'ana.kovac', 'SI56']) {
			assert.ok(!JSON.stringify(item.json).includes(value), `${value} must not be in the output`);
		}
	});

	test('off, masked style: no empty map either', async () => {
		const [item] = await run({
			params: protectParams({
				placeholderStyle: 'typed',
				options: { includePlaceholderMap: false },
			}),
		});
		assert.deepEqual(Object.keys(item.json).sort(), ['entities', 'protectedText']);
	});

	test('off with Include Input Fields: a copied placeholderMap or idFile is removed too', async () => {
		const [item] = await run({
			items: [{ body: 'x', placeholderMap: { PERSON_1: 'Janez Novak' }, idFile: { ids: [] } }],
			params: protectParams({
				options: { includePlaceholderMap: false, includeInputFields: true },
			}),
		});
		assert.equal(item.json.body, 'x');
		assert.ok(!('placeholderMap' in item.json));
		assert.ok(!('idFile' in item.json));
	});

	test('off together with Include ID File is refused before anything is sent', async () => {
		const error = await runError({
			params: protectParams({ options: { includePlaceholderMap: false, includeIdFile: true } }),
		});
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /Include ID File.*Include Placeholder Map/);
		assert.equal(analyzeCalls.length, 0);
	});

	test('off with Share Map Across Items still keeps placeholders consistent', async () => {
		const out = await run({
			items: [{}, {}],
			params: protectParams({
				text: 'Janez Novak',
				options: { includePlaceholderMap: false, shareMapAcrossItems: true },
			}),
		});
		assert.equal(out[0].json.protectedText, out[1].json.protectedText);
		for (const item of out) assert.ok(!('placeholderMap' in item.json));
	});

	test('Reveal still works with the map of a run that included it', async () => {
		const [protectedItem] = await run({
			params: protectParams({ options: { includePlaceholderMap: true } }),
		});
		const [revealed] = await run({
			params: revealParams(protectedItem.json.protectedText, protectedItem.json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, SAMPLE);
	});
});

describe('Ignore Terms (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const TEXT = 'Janez Novak from Acme wrote to ana.kovac@example.com about ACME Cloud.';
	const companySpans = (text) => [
		...detect(text),
		...[...text.matchAll(/Acme Cloud|ACME Cloud|Acme/g)].map((m) => ({
			entity_type: 'ORGANIZATION',
			start: m.index,
			end: m.index + m[0].length,
			score: 0.6,
		})),
	];

	test('Protect: detections equal to a term are left in the text', async () => {
		analyzeBehaviour.spans = companySpans;
		const [item] = await run({
			params: protectParams({ text: TEXT, options: { ignoreTerms: 'acme\nJanez Novak' } }),
		});
		const { protectedText, placeholderMap, entities } = item.json;
		assert.ok(protectedText.startsWith('Janez Novak from Acme wrote to [EMAIL_'));
		// "ACME Cloud" is not equal to a term, so it is still replaced.
		assert.match(protectedText, /about \[ORGANIZATION_[a-z0-9]{5}\]\.$/);
		assert.deepEqual(
			entities.map((e) => e.entityType),
			['EMAIL_ADDRESS', 'ORGANIZATION'],
		);
		assert.ok(!Object.values(placeholderMap).includes('Janez Novak'));
		assert.equal(analyzeCalls[0].text, TEXT, 'the full text is still sent');
	});

	test('Protect: a value already in the existing map wins over Ignore Terms', async () => {
		const [item] = await run({
			params: protectParams({
				text: 'Janez Novak called.',
				options: {
					ignoreTerms: 'Janez Novak',
					existingPlaceholderMap: { PERSON_abcde: 'Janez Novak' },
				},
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON_abcde] called.');
	});

	test('Detect: ignored detections are not reported', async () => {
		analyzeBehaviour.spans = companySpans;
		const [item] = await run({
			params: { operation: 'detect', text: TEXT, options: { ignoreTerms: 'Acme, acme cloud' } },
		});
		assert.deepEqual(item.json.countsByType, { PERSON: 1, EMAIL_ADDRESS: 1 });
	});
});

describe('Detect (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const detectParams = (overrides = {}) => ({ operation: 'detect', text: SAMPLE, ...overrides });

	test('reports counts and original-text offsets without values, text unchanged', async () => {
		const [item] = await run({ params: detectParams() });
		assert.deepEqual(item.pairedItem, { item: 0 });
		assert.equal(analyzeCalls.length, 1);
		assert.equal(analyzeCalls[0].entityTypes, undefined);
		const { hasPersonalData, entityCount, countsByType, entities } = item.json;
		assert.equal(hasPersonalData, true);
		assert.equal(entityCount, 3);
		assert.deepEqual(countsByType, { PERSON: 1, EMAIL_ADDRESS: 1, IBAN: 1 });
		assert.deepEqual(
			entities.map((e) => SAMPLE.slice(e.start, e.end)),
			['Janez Novak', 'ana.kovac@example.com', 'SI56 1910 0000 0123 438'],
		);
		for (const entity of entities) {
			assert.ok(!('value' in entity));
			assert.equal(entity.score, 0.85);
		}
		assert.deepEqual(Object.keys(item.json).sort(), [
			'countsByType',
			'entities',
			'entityCount',
			'hasPersonalData',
		]);
		assert.ok(!JSON.stringify(item.json).includes('Janez'), 'no values without Include Values');
	});

	test('Include Values adds the matched text', async () => {
		const [item] = await run({ params: detectParams({ options: { includeValues: true } }) });
		assert.deepEqual(
			item.json.entities.map((e) => e.value),
			['Janez Novak', 'ana.kovac@example.com', 'SI56 1910 0000 0123 438'],
		);
	});

	test('counts repeat occurrences per type', async () => {
		const text = 'Janez Novak and Marko Horvat met Janez Novak.';
		const [item] = await run({ params: detectParams({ text }) });
		assert.deepEqual(item.json.countsByType, { PERSON: 3 });
		assert.equal(item.json.entityCount, 3);
	});

	test('nothing found: hasPersonalData false, empty counts', async () => {
		const [item] = await run({ params: detectParams({ text: 'The weather is nice.' }) });
		assert.deepEqual(item.json, {
			hasPersonalData: false,
			entityCount: 0,
			countsByType: {},
			entities: [],
		});
	});

	test('blank text never reaches the gateway', async () => {
		const [item] = await run({ params: detectParams({ text: '   ' }) });
		assert.equal(analyzeCalls.length, 0);
		assert.equal(item.json.hasPersonalData, false);
	});

	test('selected types are sent as the filter; entityFilterIgnored is passed on', async () => {
		analyzeBehaviour.entityFilterIgnored = true;
		const [item] = await run({
			params: detectParams({ detect: 'selected', entityTypes: ['IBAN'] }),
		});
		assert.deepEqual(analyzeCalls[0].entityTypes, ['IBAN', 'IBAN_CODE']);
		assert.equal(item.json.entityFilterIgnored, true);
		assert.deepEqual(item.json.countsByType, { IBAN: 1 });
	});

	test('overlapping detections are resolved as Protect does: earliest, then longest', async () => {
		analyzeBehaviour.spans = () => [
			{ entity_type: 'LOCATION', start: 6, end: 11, score: 0.5 },
			{ entity_type: 'PERSON', start: 0, end: 11, score: 0.912 },
			{ entity_type: 'PERSON', start: 0, end: 5, score: 0.7 },
		];
		const [item] = await run({ params: detectParams({ text: 'Janez Novak' }) });
		assert.deepEqual(item.json.entities, [
			{ entityType: 'PERSON', start: 0, end: 11, score: 0.91 },
		]);
	});

	test('the existing placeholder map is not used: gateway findings only', async () => {
		const [item] = await run({
			params: detectParams({
				text: 'Petra wrote.',
				options: { existingPlaceholderMap: { PERSON_abcde: 'Petra' } },
			}),
		});
		assert.equal(item.json.hasPersonalData, false);
	});

	test('Include Input Fields keeps the input item', async () => {
		const [item] = await run({
			items: [{ ticket: 7 }],
			params: detectParams({ options: { includeInputFields: true } }),
		});
		assert.equal(item.json.ticket, 7);
		assert.equal(item.json.hasPersonalData, true);
	});

	test('Include Input Fields drops a stale possibleIdsTruncated from an upstream Protect', async () => {
		const [item] = await run({
			items: [
				{ ticket: 7, possibleIds: [], possibleIdsTruncated: true, entityFilterIgnored: true },
			],
			params: detectParams({ options: { includeInputFields: true } }),
		});
		assert.equal(item.json.ticket, 7);
		for (const field of ['possibleIds', 'possibleIdsTruncated', 'entityFilterIgnored']) {
			assert.ok(!(field in item.json), `${field} is not carried over`);
		}
	});

	test('gateway failures are mapped like Protect', async () => {
		analyzeBehaviour.throw = new GatewayError('auth_required', 'rejected', 401);
		const error = await runError({ params: detectParams() });
		assert.ok(error instanceof NodeApiError);
		assert.equal(error.message, 'The Anonymizator API key was rejected');
	});
});

describe('Additionally Protect, possible IDs, ID sets (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const EXTRA_TEXT =
		'Janez Novak of Modra Vila d.o.o. paid 4.800,00 EUR for order K101. Later Janezu wrote, and Modra Vila replied.';

	test('Additionally Protect: numbers, currency values and companies, local only', async () => {
		const [item] = await run({
			params: protectParams({
				text: EXTRA_TEXT,
				placeholderStyle: 'sequential',
				options: { additionallyProtect: ['NUMBER', 'AMOUNT', 'COMPANY'] },
			}),
		});
		assert.equal(
			item.json.protectedText,
			'[PERSON_1] of [COMPANY_1] paid [AMOUNT_1] for order [NUMBER_1]. Later Janezu wrote, and Modra Vila replied.',
		);
		assert.deepEqual(
			item.json.entities.map((e) => e.entityType),
			['PERSON', 'COMPANY', 'AMOUNT', 'NUMBER'],
		);
		assert.equal(item.json.placeholderMap.COMPANY_1, 'Modra Vila d.o.o.');
		assert.equal(item.json.placeholderMap.AMOUNT_1, '4.800,00 EUR');
		assert.equal(analyzeCalls[0].text, EXTRA_TEXT, 'the gateway gets the text only');
		assert.equal(analyzeCalls[0].options.possible, undefined);
		assert.ok(!('possibleIds' in item.json), 'possible IDs only with the option');
	});

	test('Additionally Protect off by default: the old output', async () => {
		const [item] = await run({ params: protectParams({ text: EXTRA_TEXT }) });
		assert.match(
			item.json.protectedText,
			/Modra Vila d\.o\.o\. paid 4\.800,00 EUR for order K101\./,
		);
	});

	test('Include Possible IDs: variants of protected IDs, offsets into protectedText', async () => {
		const [item] = await run({
			params: protectParams({
				text: EXTRA_TEXT,
				options: { additionallyProtect: ['COMPANY'], includePossibleIds: true },
			}),
		});
		const { protectedText, possibleIds } = item.json;
		assert.deepEqual(
			possibleIds.map((p) => [p.value, p.kind, p.type]),
			[
				['Janezu', 'case-form', 'PERSON'],
				['Modra Vila', 'company-name', 'COMPANY'],
			],
		);
		for (const p of possibleIds) {
			assert.equal(protectedText.slice(p.start, p.end), p.value);
			assert.deepEqual(Object.keys(p), ['start', 'end', 'value', 'kind', 'type']);
		}
		assert.ok(!('possibleIdsTruncated' in item.json));
		// No capabilities document lists possible types, so the gateway is not asked for them.
		assert.equal(analyzeCalls[0].options.possible, undefined);
	});

	test('Include Possible IDs asks the gateway only when the capabilities list possible types', async () => {
		fakeCapabilities = makeCapabilities({ possible: [{ type: 'ORGANIZATION', groups: [] }] });
		const names = Array.from({ length: 60 }, (_, i) => `Orgx${String(i).padStart(2, '0')}`);
		const text = names.join(' ');
		analyzeBehaviour.spans = () => [];
		analyzeBehaviour.possible = (t) => [
			...names.map((name) => ({
				start: t.indexOf(name),
				end: t.indexOf(name) + name.length,
				entity_type: 'ORGANIZATION',
			})),
			// Unlisted types: 'possible spans of a type the capabilities do not list are dropped'.
		];
		const [item] = await run({
			params: protectParams({ text, options: { includePossibleIds: true } }),
		});
		assert.equal(analyzeCalls[0].options.possible, true);
		assert.equal(item.json.possibleIds.length, 50);
		assert.equal(item.json.possibleIdsTruncated, true);
		assert.deepEqual(item.json.possibleIds[0], {
			start: 0,
			end: 6,
			value: 'Orgx00',
			kind: 'detected',
			type: 'COMPANY',
		});
		assert.equal(item.json.protectedText, text, 'possible IDs are never replaced');
	});

	test('Ignore Terms is the skipped test: a company term stays, and is not listed', async () => {
		const [item] = await run({
			params: protectParams({
				text: EXTRA_TEXT,
				options: {
					additionallyProtect: ['COMPANY'],
					includePossibleIds: true,
					ignoreTerms: 'MODRA VILA D.O.O.',
				},
			}),
		});
		assert.match(item.json.protectedText, /of Modra Vila d\.o\.o\. paid/);
		assert.ok(!item.json.entities.some((e) => e.entityType === 'COMPANY'));
		assert.deepEqual(
			item.json.possibleIds.map((p) => p.value),
			['Janezu'],
		);
	});

	test('entities never carry a value or a key', async () => {
		const [item] = await run({
			params: protectParams({ options: { includePlaceholderMap: false } }),
		});
		for (const entity of item.json.entities) {
			assert.deepEqual(Object.keys(entity), ['entityType', 'placeholder', 'start', 'end', 'score']);
		}
	});

	test('an ID file v2 with a group protects every member with the group key', async () => {
		const idFile = {
			format: 'anonymizator-id-file',
			version: 2,
			name: 'test',
			numbering: 'random',
			ids: [
				{
					value: 'Janez Novak',
					placeholder: '[PERSON_abcde]',
					type: 'PERSON',
					addedByYou: false,
					main: true,
				},
				{
					value: 'J. Novak',
					placeholder: '[PERSON_abcde]',
					type: 'PERSON',
					addedByYou: true,
					main: false,
				},
			],
			nameParts: [],
			revealOnly: [],
			usedPlaceholders: ['[PERSON_abcde]', '[PERSON_zzzzz]'],
		};
		const [item] = await run({
			params: protectParams({
				text: 'J. Novak and Janez Novak',
				options: { existingPlaceholderMap: idFile, includeIdFile: true },
			}),
		});
		assert.equal(item.json.protectedText, '[PERSON_abcde] and [PERSON_abcde]');
		assert.equal(item.json.placeholderMap.PERSON_abcde, 'Janez Novak');
		assert.equal(item.json.placeholderMap.PERSON_zzzzz, '', 'the tombstone stays retired');
		assert.deepEqual(
			item.json.idFile.ids.map((e) => [e.value, e.placeholder, e.main]),
			[
				['Janez Novak', '[PERSON_abcde]', true],
				['J. Novak', '[PERSON_abcde]', false],
			],
		);
	});

	test('Share Map Across Items merges ID file sets; masked items still record what they found', async () => {
		const texts = ['Janez Novak', 'Marko Horvat and Janez Novak', 'Hello'];
		const styles = ['random', 'typed', 'random'];
		const out = await run({
			items: [{}, {}, {}],
			params: (i) =>
				protectParams({
					text: texts[i],
					placeholderStyle: styles[i],
					options: { shareMapAcrossItems: true, includeIdFile: true },
				}),
		});
		assert.equal(out[1].json.protectedText, '[PERSON] and [PERSON]');
		assert.deepEqual(out[1].json.placeholderMap, {});
		assert.ok(!('idFile' in out[1].json), 'no ID file for a masked style');
		// The masked item's finding is in the shared set: the next pseudonymising item exports it.
		assert.equal(out[2].json.idFile.numbering, 'random');
		assert.deepEqual(out[2].json.idFile.ids.map((e) => e.value).sort(), [
			'Janez Novak',
			'Marko Horvat',
		]);
	});
});

describe('Detect: sanitising and possible IDs (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	test('a malformed gateway type is reported as PII', async () => {
		analyzeBehaviour.spans = () => [{ entity_type: 'bad type', start: 0, end: 5, score: 0.5 }];
		const [item] = await run({ params: { operation: 'detect', text: 'Janez wrote' } });
		assert.deepEqual(item.json.countsByType, { PII: 1 });
		assert.equal(item.json.entities[0].entityType, 'PII');
	});

	test('possible IDs: off by default; on, listed with values only with Include Values', async () => {
		fakeCapabilities = makeCapabilities({ possible: [{ type: 'ORGANIZATION', groups: [] }] });
		const text = 'Janez Novak works at Modra Hisa.';
		analyzeBehaviour.possible = (t) => [
			{ start: t.indexOf('Modra'), end: t.indexOf('.'), entity_type: 'ORGANIZATION' },
		];
		const [plain] = await run({ params: { operation: 'detect', text } });
		assert.ok(!('possibleIds' in plain.json));
		assert.equal(analyzeCalls[0].options.possible, undefined);

		const [item] = await run({
			params: { operation: 'detect', text, options: { includePossibleIds: true } },
		});
		assert.equal(analyzeCalls[1].options.possible, true);
		assert.deepEqual(item.json.possibleIds, [{ entityType: 'ORGANIZATION', start: 21, end: 31 }]);
		assert.equal(item.json.entityCount, 1, 'possible IDs are not counted');

		const [valued] = await run({
			params: {
				operation: 'detect',
				text,
				options: { includePossibleIds: true, includeValues: true, ignoreTerms: 'nothing' },
			},
		});
		assert.equal(valued.json.possibleIds[0].value, 'Modra Hisa');

		const [ignored] = await run({
			params: {
				operation: 'detect',
				text,
				options: { includePossibleIds: true, ignoreTerms: 'modra hisa' },
			},
		});
		assert.deepEqual(ignored.json.possibleIds, []);
	});

	test('possible IDs without a capabilities document: not requested, empty list', async () => {
		const [item] = await run({
			params: { operation: 'detect', text: 'Janez Novak', options: { includePossibleIds: true } },
		});
		assert.equal(analyzeCalls[0].options.possible, undefined);
		assert.deepEqual(item.json.possibleIds, []);
	});

	test('blank text: no capabilities request either', async () => {
		await run({ params: { operation: 'detect', text: ' ' } });
		assert.equal(capabilitiesCalls, 0);
		assert.equal(analyzeCalls.length, 0);
	});
});

describe('gateway failures (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const cases = [
		['auth_required', 302, NodeApiError, /API key was rejected/],
		['no_access', 403, NodeApiError, /no access/],
		['hpke_stale', 400, NodeApiError, /clock/],
		['rate_limited', 429, NodeApiError, /Too many requests/],
		['text_too_large', 413, NodeApiError, /too long/],
		['payload_too_large', 413, NodeApiError, /too long/],
		['server_error', 502, NodeApiError, /could not process the text/],
		['busy', 503, NodeApiError, /busy/],
		['hpke_unverified_keyconfig', 200, NodeOperationError, /Could not verify/],
		['hpke_stale_keyconfig', 200, NodeOperationError, /clock/],
		['hpke_no_usable_key', 200, NodeOperationError, /Could not verify/],
		['hpke_bad_keyconfig', 200, NodeOperationError, /Could not verify/],
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

	test('payload_too_large names no limit and no advice to split items', async () => {
		fakeCapabilities = { ...makeCapabilities(), maxTextChars: 50000 };
		// The local per-request guard (no HTTP status): the node never sends a part over the cap.
		analyzeBehaviour.throw = new GatewayError('payload_too_large', 'raw');
		const error = await runError({ params: protectParams() });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /too long for one request/);
		assert.doesNotMatch(error.description, /[0-9],[0-9]{3}|Split the text/);
	});

	test('a failed part of a long text is named in the description, before the code', async () => {
		const failure = new GatewayError('busy', 'raw', 503);
		failure.failedPart = 2;
		failure.parts = 5;
		analyzeBehaviour.throw = failure;
		const error = await runError({ params: protectParams() });
		assert.ok(error instanceof NodeApiError);
		assert.match(
			error.description,
			/This was part 2 of 5 of the text; no partial result is output\. \(code: busy\)$/,
		);
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

/** UTF-16 spans -> the gateway's code-point offsets. */
function toCodePoints(text, spans) {
	const cp = (i) => [...text.slice(0, i)].length;
	return spans.map((s) => ({ ...s, start: cp(s.start), end: cp(s.end) }));
}

const NOW = Math.floor(Date.now() / 1000);

/**
 * The gateway's vector capabilities document, issued now, with ORGANIZATION as a review-only
 * `possible` type (and its labels) and a server-only type, IT_FISCAL_CODE, that it already lists.
 */
function capabilitiesWithPossible() {
	return capabilitiesText(NOW - 60)
		.replace('entity=ZZZS,on,si\n', 'entity=ZZZS,on,si\npossible=ORGANIZATION,general\n')
		.replace(
			/(label=type:OIB,sl[^\n]*\n)/,
			'$1label=type:ORGANIZATION,en,Organisations\nlabel=type:ORGANIZATION,sl,Organizacije\n',
		);
}

/**
 * Fake v2 gateway behind httpRequestWithAuthentication (independent recipient and signed keyconfig
 * from test/helpers/pgw.mjs). `analyzeHandler(opened, request)` returns a full response; default:
 * seal the dictionary spans (in code points, as the gateway reports them). `signer` signs the
 * delegation instead of `root` (an unpinned root).
 */
function makeGateway({ root, signer = root, analyzeHandler, capabilities } = {}) {
	const chain = makeTrustChain({ root: signer, delegated: root.delegated });
	const fake = makeFakeGateway({
		now: NOW,
		chain,
		keyId: 7,
		...(capabilities
			? { capabilities: () => json(200, chain.capabilities({ now: NOW, text: capabilities })) }
			: {}),
		analyze: (opened, request) => {
			if (analyzeHandler) return analyzeHandler(opened, request);
			const text = opened.payload.text;
			return octet(
				200,
				opened.seal({ entities: toCodePoints(text, detect(text, opened.payload.entities)) }),
			);
		},
	});
	const helper = fake.ctx.helpers.httpRequestWithAuthentication;
	async function http(credentialName, options) {
		assert.equal(this, ctxRef.current, 'helper must be called with the execute context as this');
		return helper.call(fake.ctx, credentialName, options);
	}
	return { http, requests: fake.requests, recipient: fake.recipient };
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
	const root = Object.assign(ed25519Signer(), { delegated: ed25519Signer() });

	const seams = { trustRootsB64url: [root.publicKey], retryDelayMs: 1 };

	beforeEach(() => {
		gateway.analyze = (ctx, text, entityTypes, options) =>
			realAnalyze(ctx, text, entityTypes, { ...options, ...seams });
		gateway.fetchCapabilities = (ctx) => realFetchCapabilities(ctx, seams);
		gateway.clearGatewayCaches();
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
		const fake = makeGateway({ root, signer: ed25519Signer() });
		const error = await runFullError({ params: protectParams(), http: fake.http });
		assert.ok(error instanceof NodeOperationError);
		assert.match(error.message, /Could not verify/);
		assert.equal(fake.requests.filter((r) => r.method === 'POST').length, 0);
	});

	test('continueOnFail with a rejected key yields an error item', async () => {
		const fake = makeGateway({ root, analyzeHandler: () => json(401, {}) });
		const out = await runFull({ params: protectParams(), http: fake.http, continueOnFail: true });
		assert.deepEqual(out, [
			{ json: { error: 'The Anonymizator API key was rejected' }, pairedItem: { item: 0 } },
		]);
	});

	test('detect seals the text and reports offsets into the original, emoji included', async () => {
		const fake = makeGateway({ root });
		const text = '😀😀 Janez Novak, ana.kovac@example.com 👍';
		const [item] = await runFull({
			params: { operation: 'detect', text, options: { includeValues: true } },
			http: fake.http,
		});
		const post = fake.requests.find((r) => r.method === 'POST');
		assert.ok(!post.body.toString('latin1').includes('Janez'));
		assert.deepEqual(
			item.json.entities.map((e) => [e.entityType, text.slice(e.start, e.end), e.value]),
			[
				['PERSON', 'Janez Novak', 'Janez Novak'],
				['EMAIL_ADDRESS', 'ana.kovac@example.com', 'ana.kovac@example.com'],
			],
		);
		assert.equal(
			item.json.entities[0].start,
			5,
			'UTF-16: two emoji are four code units, then a space',
		);
	});

	test('capabilities: verified once, cached; no possible member unless asked for', async () => {
		let seen;
		const fake = makeGateway({
			root,
			capabilities: capabilitiesWithPossible(),
			analyzeHandler: (opened) => {
				seen = opened.payload;
				return octet(200, opened.seal({ entities: [] }));
			},
		});
		await runFull({ items: [{}, {}], params: protectParams(), http: fake.http });
		assert.ok(!('possible' in seen), 'the request is unchanged without Include Possible IDs');
		assert.equal(fake.requests.filter((r) => r.url.endsWith('/v1/capabilities')).length, 1);
	});

	test('Include Possible IDs: possible requested, gateway values listed in protectedText', async () => {
		let seen;
		const text = 'Janez Novak works at Modra Hiša in Ljubljana.';
		const fake = makeGateway({
			root,
			capabilities: capabilitiesWithPossible(),
			analyzeHandler: (opened) => {
				seen = opened.payload;
				const t = opened.payload.text;
				const org = t.indexOf('Modra Hiša');
				return octet(
					200,
					opened.seal({
						entities: toCodePoints(t, detect(t)),
						possible: [{ start: org, end: org + 10, entity_type: 'ORGANIZATION' }],
					}),
				);
			},
		});
		const [item] = await runFull({
			params: protectParams({ text, options: { includePossibleIds: true } }),
			http: fake.http,
		});
		assert.equal(seen.possible, true);
		const { protectedText, possibleIds } = item.json;
		assert.deepEqual(
			possibleIds.map((p) => [p.value, p.kind, p.type, protectedText.slice(p.start, p.end)]),
			[['Modra Hiša', 'detected', 'COMPANY', 'Modra Hiša']],
		);
		assert.ok(!('possibleIdsTruncated' in item.json));
		assert.ok(!('of' in possibleIds[0]));
	});

	test('Detect with Include Possible IDs: review-only spans, original offsets, not counted', async () => {
		const text = '😀 Janez Novak works at Modra Hiša.';
		const fake = makeGateway({
			root,
			capabilities: capabilitiesWithPossible(),
			analyzeHandler: (opened) => {
				const t = opened.payload.text;
				const org = [...t].join('').indexOf('Modra Hiša');
				return octet(
					200,
					opened.seal({
						entities: toCodePoints(t, detect(t)),
						possible: toCodePoints(t, [{ start: org, end: org + 10, entity_type: 'ORGANIZATION' }]),
					}),
				);
			},
		});
		const [item] = await runFull({
			params: { operation: 'detect', text, options: { includePossibleIds: true } },
			http: fake.http,
		});
		assert.equal(item.json.entityCount, 1);
		assert.deepEqual(item.json.possibleIds, [
			{ entityType: 'ORGANIZATION', start: text.indexOf('Modra'), end: text.indexOf('.', 20) },
		]);
	});

	test('getEntityTypes: bundled rows plus the server-only types of the verified document', async () => {
		const fake = makeGateway({ root, capabilities: capabilitiesWithPossible() });
		const ctx = withCredential(makeCtx({ params: {}, http: fake.http }));
		ctxRef.current = ctx;
		const options = await new Anonymizator().methods.loadOptions.getEntityTypes.call(ctx);
		const values = options.map((o) => o.value);
		for (const row of ENTITY_CATALOG) assert.ok(values.includes(row.id), row.id);
		assert.ok(values.includes('IT_FISCAL_CODE'));
		assert.ok(values.includes('SOCIAL_HANDLE'));
		assert.ok(!values.includes('IBAN_CODE'), 'covered by the IBAN row');
		assert.ok(!values.includes('ORGANIZATION'), 'possible types never become rows');
		const names = options.map((o) => o.name);
		assert.deepEqual(
			names,
			[...names].sort((a, b) => a.localeCompare(b, 'en')),
		);
		assert.equal(options.find((o) => o.value === 'PERSON').name, 'Names');
		assert.match(options.find((o) => o.value === 'IBAN').description, /IBAN, IBAN_CODE/);
	});

	test('getEntityTypes falls back to the bundled catalog when nothing verifies', async () => {
		const fake = makeGateway({
			root,
			signer: ed25519Signer(),
			capabilities: capabilitiesWithPossible(),
		});
		const ctx = withCredential(makeCtx({ params: {}, http: fake.http }));
		ctxRef.current = ctx;
		const options = await new Anonymizator().methods.loadOptions.getEntityTypes.call(ctx);
		assert.deepEqual(options.map((o) => o.value).sort(), ENTITY_CATALOG.map((r) => r.id).sort());
	});

	test('getEntityTypes without a credential: bundled rows, no request, no held failure', async () => {
		const fake = makeGateway({ root, capabilities: capabilitiesWithPossible() });
		const bare = makeCtx({ params: {}, http: fake.http });
		bare.getCredentials = async () => {
			throw new Error('Node does not have any credentials set');
		};
		ctxRef.current = bare;
		const getEntityTypes = new Anonymizator().methods.loadOptions.getEntityTypes;
		const before = await getEntityTypes.call(bare);
		assert.deepEqual(before.map((o) => o.value).sort(), ENTITY_CATALOG.map((r) => r.id).sort());
		assert.equal(fake.requests.length, 0);
		// Selecting a credential right after gives the server rows, not a held fallback.
		const ctx = withCredential(makeCtx({ params: {}, http: fake.http }));
		ctxRef.current = ctx;
		const after = (await getEntityTypes.call(ctx)).map((o) => o.value);
		assert.ok(after.includes('IT_FISCAL_CODE'));
		assert.ok(after.includes('SOCIAL_HANDLE'));
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

// ---------------------------------------------------------------------------------------------
// Review findings (actions cluster): each test reproduces one confirmed scenario.

describe('long texts in parts (real gateway.ts, fake HPKE recipient)', () => {
	const root = Object.assign(ed25519Signer(), { delegated: ed25519Signer() });
	const seams = { trustRootsB64url: [root.publicKey], retryDelayMs: 1 };
	const codePoints = (s) => [...s].length;
	const posts = (fake) => fake.requests.filter((r) => r.method === 'POST');

	beforeEach(() => {
		gateway.analyze = (ctx, text, entityTypes, options) =>
			realAnalyze(ctx, text, entityTypes, { ...options, ...seams });
		gateway.fetchCapabilities = (ctx) => realFetchCapabilities(ctx, seams);
		gateway.clearGatewayCaches();
	});

	// About 39 000 code points: five parts of at most 8 000 (no capabilities: the bundled cap).
	const UNIT = '🎉 Janez Novak piše z ana.kovac@example.com, Žiga 👍🏽 čaka.\n';
	const LONG = UNIT.repeat(700);

	test('Protect: a long item is split, merged, and gets one placeholder per value', async () => {
		const seen = [];
		const fake = makeGateway({
			root,
			analyzeHandler: (opened) => {
				seen.push(opened.payload.text);
				const t = opened.payload.text;
				return octet(200, opened.seal({ entities: toCodePoints(t, detect(t)) }));
			},
		});
		const [item] = await runFull({ params: protectParams({ text: LONG }), http: fake.http });
		assert.ok(seen.length >= 5, `${seen.length} parts`);
		assert.ok(seen.every((t) => codePoints(t) <= 8000));
		for (const t of seen.slice(0, -1)) assert.ok(t.endsWith('\n'), 'cut after a line');
		const map = item.json.placeholderMap;
		// One placeholder per value (plus the PERSON's _NAME / _SURNAME parts).
		assert.deepEqual(Object.values(map).sort(), [
			'Janez',
			'Janez Novak',
			'Novak',
			'ana.kovac@example.com',
		]);
		const person = keyFor(map, 'Janez Novak');
		const email = keyFor(map, 'ana.kovac@example.com');
		assert.equal(
			item.json.protectedText,
			UNIT.replace('Janez Novak', `[${person}]`)
				.replace('ana.kovac@example.com', `[${email}]`)
				.repeat(700),
		);
		assert.equal(item.json.entities.length, 1400);
		for (const e of item.json.entities) {
			assert.equal(
				item.json.protectedText.slice(e.start, e.end),
				`[${e.placeholder.replace(/^\[|\]$/g, '')}]`,
			);
		}
		const [revealed] = await runFull({
			params: revealParams(item.json.protectedText, item.json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, LONG);
	});

	test('Protect: a value straddling a hard cut after emoji is protected whole', async () => {
		const NAME = 'ALICESMITH';
		const fake = makeGateway({
			root,
			analyzeHandler: (opened) => {
				const t = opened.payload.text;
				const entities = [];
				for (let at = t.indexOf(NAME); at !== -1; at = t.indexOf(NAME, at + NAME.length)) {
					const start = codePoints(t.slice(0, at));
					entities.push({ entity_type: 'PERSON', start, end: start + NAME.length, score: 0.9 });
				}
				for (let k = NAME.length - 1; k >= 2; k--) {
					if (t.endsWith(NAME.slice(0, k))) {
						const end = codePoints(t);
						entities.push({ entity_type: 'PERSON', start: end - k, end, score: 0.9 });
						break;
					}
				}
				return octet(200, opened.seal({ entities }));
			},
		});
		const text = '😀'.repeat(7996) + NAME + '😀'.repeat(500);
		const [item] = await runFull({ params: protectParams({ text }), http: fake.http });
		assert.equal(posts(fake).length, 2);
		const key = keyFor(item.json.placeholderMap, NAME);
		assert.ok(key);
		assert.equal(item.json.protectedText, `${'😀'.repeat(7996)}[${key}]${'😀'.repeat(500)}`);
		assert.doesNotMatch(item.json.protectedText, /ALIC|SMITH/);
		const [e] = item.json.entities;
		assert.equal(e.start, 7996 * 2);
		assert.equal(item.json.protectedText.slice(e.start, e.end), `[${key}]`);
	});

	test('Detect: offsets of every part index the original text', async () => {
		const fake = makeGateway({ root });
		const [item] = await runFull({
			params: { operation: 'detect', text: LONG, options: { includeValues: true } },
			http: fake.http,
		});
		assert.ok(posts(fake).length >= 5);
		assert.equal(item.json.entityCount, 1400);
		for (const e of item.json.entities) assert.equal(LONG.slice(e.start, e.end), e.value);
		assert.equal(item.json.entities.at(-1).value, 'ana.kovac@example.com');
	});

	test('no up-front refusal: 120 001 characters are protected in parts', async () => {
		const fake = makeGateway({ root });
		const text = `${'a'.repeat(120000)} Janez Novak`.slice(0, 120001);
		const [item] = await runFull({ params: protectParams({ text }), http: fake.http });
		assert.equal(item.json.protectedText.length, 120001);
		assert.equal(posts(fake).length, 16);
	});

	test('one failing part fails the item: no partial output, later parts never sent', async () => {
		let n = 0;
		const fake = makeGateway({
			root,
			analyzeHandler: (opened) => {
				n += 1;
				if (n >= 2) return json(500, { error: 'internal_error' });
				const t = opened.payload.text;
				return octet(200, opened.seal({ entities: toCodePoints(t, detect(t)) }));
			},
		});
		const error = await runFullError({ params: protectParams({ text: LONG }), http: fake.http });
		assert.ok(error instanceof NodeApiError);
		assert.match(error.message, /could not process the text/);
		assert.match(
			error.description,
			/This was part 2 of \d+ of the text; no partial result is output\./,
		);
		assert.match(error.description, /\(code: internal_error\)$/);
		assert.equal(posts(fake).length, 3, 'part 1, part 2 twice (the 5xx retry)');

		gateway.clearGatewayCaches();
		n = 0;
		const out = await runFull({
			items: [{ text: LONG }],
			params: protectParams({ text: LONG }),
			http: fake.http,
			continueOnFail: true,
		});
		assert.equal(out.length, 1);
		assert.deepEqual(Object.keys(out[0].json), ['error']);
		assert.doesNotMatch(JSON.stringify(out), /Janez|ana\.kovac|PERSON_|EMAIL_/);
	});
});

describe('review fixes: ID files, shared maps, stale input fields (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const { outputMap } = require(`${DIST}actions/protect.js`);
	const { parsePlaceholderMap } = require(`${DIST}shared/placeholderMap.js`);

	/** An extension ID file v2 with one group: PERSON_aaaaa = Janez Novak (main) + J. Novak. */
	const GROUP_FILE = {
		format: 'anonymizator-id-file',
		version: 2,
		name: 'group',
		numbering: 'random',
		ids: [
			{
				value: 'Janez Novak',
				placeholder: '[PERSON_aaaaa]',
				type: 'PERSON',
				addedByYou: false,
				main: true,
			},
			{
				value: 'J. Novak',
				placeholder: '[PERSON_aaaaa]',
				type: 'PERSON',
				addedByYou: true,
				main: false,
			},
		],
		nameParts: [],
		revealOnly: [{ placeholder: '[PERSON_old00]', value: 'Janez N.', of: '[PERSON_aaaaa]' }],
		usedPlaceholders: ['[PERSON_aaaaa]', '[PERSON_old00]'],
	};

	// #1
	test('outputMap is linear in records and name parts, main key first then its parts', () => {
		const n = 2000; // the old nested loop took about 15 s here
		const ids = [];
		const subKeys = {};
		for (let i = 0; i < n; i++) {
			ids.unshift({
				value: `Ime${i} Priimek${i}`,
				key: `PERSON_${i + 1}`,
				type: 'PERSON',
				mine: false,
				main: true,
			});
			subKeys[`PERSON_${i + 1}_NAME`] = {
				of: `PERSON_${i + 1}`,
				value: `Ime${i}`,
				rec: `Ime${i} Priimek${i}`,
			};
			subKeys[`PERSON_${i + 1}_SURNAME`] = {
				of: `PERSON_${i + 1}`,
				value: `Priimek${i}`,
				rec: `Ime${i} Priimek${i}`,
			};
		}
		const state = { numbering: 'sequential', ids, subKeys, aliases: {}, used: ['PERSON_0'] };
		const started = Date.now();
		const map = outputMap(state);
		const elapsed = Date.now() - started;
		assert.ok(elapsed < 1000, `outputMap took ${elapsed} ms for ${n} persons`);
		const keys = Object.keys(map);
		assert.equal(keys.length, 3 * n + 1);
		assert.deepEqual(keys.slice(0, 6), [
			'PERSON_1',
			'PERSON_1_NAME',
			'PERSON_1_SURNAME',
			'PERSON_2',
			'PERSON_2_NAME',
			'PERSON_2_SURNAME',
		]);
		assert.equal(map.PERSON_0, '', 'retired keys come last, empty');
	});

	// #8 (and #5)
	for (const style of ['typed', 'redacted']) {
		test(`Include ID File adds no idFile for ${style} (old contract), even with a group file`, async () => {
			const [plain] = await run({
				params: protectParams({ placeholderStyle: style, options: { includeIdFile: true } }),
			});
			assert.ok(!('idFile' in plain.json));
			assert.ok(!JSON.stringify(plain.json).includes('Janez'), 'no real value in the output');

			const [grouped] = await run({
				params: protectParams({
					text: 'J. Novak and Janez Novak, ana.kovac@example.com',
					placeholderStyle: style,
					options: { existingPlaceholderMap: GROUP_FILE, includeIdFile: true },
				}),
			});
			const mask = style === 'typed' ? '[PERSON]' : '[REDACTED]';
			const email = style === 'typed' ? '[EMAIL]' : '[REDACTED]';
			assert.equal(grouped.json.protectedText, `${mask} and ${mask}, ${email}`);
			assert.deepEqual(grouped.json.placeholderMap, {});
			assert.ok(!('idFile' in grouped.json));
		});
	}

	test('Include ID File still adds a v2 file for Random and Numbers in Order, groups included', async () => {
		for (const style of ['random', 'sequential']) {
			const [item] = await run({
				params: protectParams({
					text: 'J. Novak and Janez Novak',
					placeholderStyle: style,
					options: { existingPlaceholderMap: GROUP_FILE, includeIdFile: true },
				}),
			});
			assert.equal(item.json.protectedText, '[PERSON_aaaaa] and [PERSON_aaaaa]');
			assert.equal(item.json.idFile.numbering, style);
			assert.ok(parsePlaceholderMap(item.json.idFile).set, 'the file loads again');
		}
	});

	test('a shared run mixing masked and pseudonymising styles never crashes Include ID File', async () => {
		const styles = ['random', 'typed', 'redacted', 'sequential'];
		const texts = [
			'J. Novak wrote',
			'Marko Horvat and Janez Novak',
			'ana.kovac@example.com',
			'Janez Novak again',
		];
		const out = await run({
			items: styles.map(() => ({})),
			params: (i) =>
				protectParams({
					text: texts[i],
					placeholderStyle: styles[i],
					options: {
						shareMapAcrossItems: true,
						includeIdFile: true,
						existingPlaceholderMap: i === 0 ? GROUP_FILE : {},
					},
				}),
		});
		assert.equal(out[0].json.protectedText, '[PERSON_aaaaa] wrote');
		assert.ok(!('idFile' in out[1].json));
		assert.ok(!('idFile' in out[2].json));
		assert.equal(out[1].json.protectedText, '[PERSON] and [PERSON]');
		const last = out[3].json;
		assert.equal(last.protectedText, '[PERSON_aaaaa] again');
		const values = last.idFile.ids.map((e) => e.value);
		for (const v of ['Janez Novak', 'J. Novak', 'Marko Horvat', 'ana.kovac@example.com']) {
			assert.ok(values.includes(v), `${v} recorded in the shared set`);
		}
		assert.ok(parsePlaceholderMap(last.idFile).set);
	});

	// #11, #30
	test('Protect with Include Input Fields drops stale possibleIds, possibleIdsTruncated, entityFilterIgnored and idFile', async () => {
		const stale = {
			ticket: 9,
			possibleIds: [{ start: 18, end: 24, value: 'Zupanu', kind: 'case-form', type: 'PERSON' }],
			possibleIdsTruncated: true,
			entityFilterIgnored: true,
			idFile: { format: 'anonymizator-id-file', version: 2 },
		};
		const [on] = await run({
			items: [stale],
			params: protectParams({
				text: 'Janez Novak met Mr. Novak',
				options: { includeInputFields: true, includePossibleIds: true },
			}),
		});
		assert.equal(on.json.ticket, 9);
		assert.deepEqual(
			on.json.possibleIds.map((p) => p.value),
			['Mr. Novak'],
		);
		assert.ok(!('possibleIdsTruncated' in on.json), 'this run was not capped');
		assert.ok(!('entityFilterIgnored' in on.json), 'this run sent no filter');
		assert.ok(!('idFile' in on.json), 'no ID file was asked for');

		const [off] = await run({
			items: [stale],
			params: protectParams({ text: 'Nothing here.', options: { includeInputFields: true } }),
		});
		assert.equal(off.json.protectedText, 'Nothing here.');
		for (const field of ['possibleIds', 'possibleIdsTruncated', 'entityFilterIgnored', 'idFile']) {
			assert.ok(!(field in off.json), `${field} is not carried over`);
		}
	});

	test('Detect with Include Input Fields drops stale possibleIds and entityFilterIgnored', async () => {
		const [item] = await run({
			items: [
				{
					ticket: 9,
					possibleIds: [{ entityType: 'X', start: 0, end: 3 }],
					entityFilterIgnored: true,
				},
			],
			params: { operation: 'detect', text: 'Janez Novak', options: { includeInputFields: true } },
		});
		assert.equal(item.json.ticket, 9);
		assert.equal(item.json.entityCount, 1);
		assert.ok(!('possibleIds' in item.json));
		assert.ok(!('entityFilterIgnored' in item.json));
	});

	// #13
	test('Share Map: a later live key that is only reveal-only in the shared set takes it back', async () => {
		const file = {
			format: 'anonymizator-id-file',
			version: 2,
			name: 'alias',
			numbering: 'random',
			ids: [
				{
					value: 'Janez Novak-Kos',
					placeholder: '[PERSON_new12]',
					type: 'PERSON',
					addedByYou: false,
					main: true,
				},
			],
			nameParts: [],
			revealOnly: [{ placeholder: '[PERSON_old12]', value: 'Janez Novak', of: '[PERSON_new12]' }],
			usedPlaceholders: ['[PERSON_new12]', '[PERSON_old12]'],
		};
		analyzeBehaviour.spans = () => [];
		const maps = [file, { PERSON_old12: 'Janez Novak' }];
		const texts = ['Hello', 'Mail Janez Novak today'];
		for (const share of [false, true]) {
			const out = await run({
				items: [{}, {}],
				params: (i) =>
					protectParams({
						text: texts[i],
						options: {
							shareMapAcrossItems: share,
							existingPlaceholderMap: maps[i],
							includeIdFile: true,
						},
					}),
			});
			assert.equal(out[1].json.protectedText, 'Mail [PERSON_old12] today', `share ${share}`);
			assert.equal(out[1].json.placeholderMap.PERSON_old12, 'Janez Novak');
			assert.ok(parsePlaceholderMap(out[1].json.idFile).set);
		}
	});

	// #19
	test('Share Map: the same seed on every item is kept once (flat map and ID file v2)', async () => {
		const flat = { PERSON_aaaaa: 'Janez Novak', EMAIL_bbbbb: 'ana.kovac@example.com' };
		const seeds = {
			flat,
			'ID file v2': {
				format: 'anonymizator-id-file',
				version: 2,
				name: 'seed',
				numbering: 'random',
				ids: [
					{
						value: 'Janez Novak',
						placeholder: '[PERSON_aaaaa]',
						type: 'PERSON',
						addedByYou: false,
						main: true,
					},
					{
						value: 'ana.kovac@example.com',
						placeholder: '[EMAIL_bbbbb]',
						type: 'EMAIL_ADDRESS',
						addedByYou: false,
						main: true,
					},
				],
				nameParts: [],
				revealOnly: [],
				usedPlaceholders: ['[PERSON_aaaaa]', '[EMAIL_bbbbb]'],
			},
		};
		for (const [label, seed] of Object.entries(seeds)) {
			const out = await run({
				items: [{}, {}, {}],
				params: () =>
					protectParams({
						text: 'Janez Novak, ana.kovac@example.com',
						options: {
							shareMapAcrossItems: true,
							includeIdFile: true,
							existingPlaceholderMap: seed,
						},
					}),
			});
			for (const item of out) {
				assert.equal(item.json.protectedText, '[PERSON_aaaaa], [EMAIL_bbbbb]', label);
				const placeholders = item.json.idFile.ids.map((e) => e.placeholder).sort();
				assert.deepEqual(placeholders, ['[EMAIL_bbbbb]', '[PERSON_aaaaa]'], label);
			}
		}
	});

	// #20
	test('Share Map: a name part or reveal-only key reused for another value fails that item', async () => {
		const out = await run({
			items: [{}, {}],
			continueOnFail: true,
			params: (i) =>
				protectParams({
					text: i === 0 ? 'Janez Novak wrote' : 'Marko said hi',
					placeholderStyle: 'sequential',
					options: {
						shareMapAcrossItems: true,
						existingPlaceholderMap: i === 0 ? {} : { PERSON_1_NAME: 'Marko' },
					},
				}),
		});
		assert.equal(out[0].json.protectedText, '[PERSON_1] wrote');
		assert.match(out[1].json.error, /PERSON_1_NAME already stands for a different value/);

		const aliased = await run({
			items: [{}, {}],
			continueOnFail: true,
			params: (i) =>
				protectParams({
					text: 'Hello',
					options: {
						shareMapAcrossItems: true,
						existingPlaceholderMap: i === 0 ? GROUP_FILE : { PERSON_old00: 'Marko Horvat' },
					},
				}),
		});
		assert.match(aliased[1].json.error, /PERSON_old00 already stands for a different value/);
	});

	// #22, #36
	test('Share Map: a later item’s retired keys stay retired in the shared map', async () => {
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					text: i === 0 ? 'hello' : 'Janez Novak',
					placeholderStyle: 'sequential',
					options: {
						shareMapAcrossItems: true,
						existingPlaceholderMap: i === 0 ? {} : { PERSON_1: 'Ana Kos', PERSON_2: '' },
					},
				}),
		});
		assert.equal(out[1].json.protectedText, '[PERSON_3]');
		assert.equal(out[1].json.placeholderMap.PERSON_2, '');
		assert.equal(out[1].json.placeholderMap.PERSON_3, 'Janez Novak');

		const above = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					text: i === 0 ? 'Janez Novak' : 'Marko Horvat',
					placeholderStyle: 'sequential',
					options: {
						shareMapAcrossItems: true,
						existingPlaceholderMap: i === 0 ? {} : { PERSON_5: 'Ana Kos', PERSON_6: '' },
					},
				}),
		});
		assert.equal(above[1].json.protectedText, '[PERSON_7]');
		assert.equal(above[1].json.placeholderMap.PERSON_6, '');
	});

	// #26
	test('Share Map: one value under a second key in a later item becomes reveal-only', async () => {
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					text: 'Mail ana.kovac@example.com',
					options: {
						shareMapAcrossItems: true,
						includeIdFile: true,
						existingPlaceholderMap: i === 0 ? {} : { EMAIL_1: 'ana.kovac@example.com' },
					},
				}),
		});
		const key = keyFor(out[0].json.placeholderMap, 'ana.kovac@example.com');
		assert.match(key, /^EMAIL_[a-z0-9]{5}$/);
		assert.equal(out[1].json.protectedText, `Mail [${key}]`);
		assert.equal(out[1].json.placeholderMap.EMAIL_1, 'ana.kovac@example.com');
		assert.deepEqual(
			out[1].json.idFile.revealOnly.map((r) => [r.placeholder, r.of]),
			[['[EMAIL_1]', `[${key}]`]],
		);
		const [revealed] = await run({
			params: revealParams('[EMAIL_1] [' + key + ']', out[1].json.idFile),
		});
		assert.equal(revealed.json.revealedText, 'ana.kovac@example.com ana.kovac@example.com');
	});

	test('Share Map: name parts of a key that became reveal-only never orphan the shared set', async () => {
		const maps = [
			{ PERSON_1: 'Janez Novak', PERSON_2: 'Janez Novak' },
			{ PERSON_2: 'Janez Novak', PERSON_2_NAME: 'Janez', PERSON_2_SURNAME: 'Novak' },
			{},
		];
		const out = await run({
			items: [{}, {}, {}],
			params: (i) =>
				protectParams({
					text: i === 2 ? 'Marko Horvat' : 'Janez Novak',
					placeholderStyle: 'sequential',
					options: {
						shareMapAcrossItems: true,
						includeIdFile: true,
						existingPlaceholderMap: maps[i],
					},
				}),
		});
		assert.equal(out[1].json.protectedText, '[PERSON_1]');
		assert.equal(out[1].json.placeholderMap.PERSON_2, 'Janez Novak');
		assert.equal(out[1].json.placeholderMap.PERSON_2_NAME, 'Janez');
		assert.equal(out[2].json.protectedText, '[PERSON_3]');
		for (const item of out) assert.ok(parsePlaceholderMap(item.json.idFile).set);
		const [revealed] = await run({
			params: revealParams('[PERSON_2_NAME] [PERSON_2]', out[2].json.placeholderMap),
		});
		assert.equal(revealed.json.revealedText, 'Janez Janez Novak');
	});

	test('Share Map: a later group whose main value is already shared joins the shared key', async () => {
		const out = await run({
			items: [{}, {}],
			params: (i) =>
				protectParams({
					text: i === 0 ? 'Hello' : 'J. Novak and Janez Novak',
					placeholderStyle: 'sequential',
					options: {
						shareMapAcrossItems: true,
						includeIdFile: true,
						existingPlaceholderMap: i === 0 ? { PERSON_1: 'Janez Novak' } : GROUP_FILE,
					},
				}),
		});
		const item = out[1].json;
		assert.equal(item.protectedText, '[PERSON_1] and [PERSON_1]');
		assert.equal(item.placeholderMap.PERSON_aaaaa, 'Janez Novak');
		assert.equal(item.placeholderMap.PERSON_old00, 'Janez N.');
		assert.deepEqual(item.idFile.ids.map((e) => [e.value, e.placeholder, e.main]).sort(), [
			['J. Novak', '[PERSON_1]', false],
			['Janez Novak', '[PERSON_1]', true],
		]);
		assert.ok(parsePlaceholderMap(item.idFile).set);
	});

	// #33
	test('Share Map: reveal-only placeholders of a later item’s map are merged and reveal', async () => {
		const seeds = [
			{ PERSON_aaaaa: 'Janez Novak', PERSON_bbbbb: 'Janez Novak' },
			{
				format: 'anonymizator-id-file',
				version: 2,
				name: 'aliases',
				numbering: 'random',
				ids: [
					{
						value: 'Janez Novak',
						placeholder: '[PERSON_aaaaa]',
						type: 'PERSON',
						addedByYou: false,
						main: true,
					},
				],
				nameParts: [],
				revealOnly: [{ placeholder: '[PERSON_bbbbb]', value: 'Janez Novak', of: '[PERSON_aaaaa]' }],
				usedPlaceholders: ['[PERSON_aaaaa]', '[PERSON_bbbbb]'],
			},
		];
		for (const seed of seeds) {
			const out = await run({
				items: [{}, {}, {}],
				params: (i) =>
					protectParams({
						text: 'Hello',
						options: { shareMapAcrossItems: true, existingPlaceholderMap: i === 1 ? seed : {} },
					}),
			});
			for (const item of out.slice(1)) {
				assert.equal(item.json.placeholderMap.PERSON_bbbbb, 'Janez Novak');
			}
			const [revealed] = await run({
				params: revealParams('Hi [PERSON_bbbbb]', out[2].json.placeholderMap),
			});
			assert.equal(revealed.json.revealedText, 'Hi Janez Novak');
		}
	});

	// #35
	test('Additionally Protect from an expression: case and spaces are folded', async () => {
		for (const raw of ['number, amount', ['Number', ' amount '], 'NUMBER\nAMOUNT']) {
			const [item] = await run({
				params: protectParams({
					text: 'Invoice K101 for 4.800,00 EUR',
					placeholderStyle: 'sequential',
					options: { additionallyProtect: raw },
				}),
			});
			assert.equal(
				item.json.protectedText,
				'Invoice [NUMBER_1] for [AMOUNT_1]',
				JSON.stringify(raw),
			);
		}
	});

	test('Additionally Protect from an expression: an unknown value is refused, naming the option', async () => {
		for (const raw of [['All Numbers'], 'numbers', { NUMBER: true }, 5]) {
			const error = await runError({
				params: protectParams({ text: 'Invoice K101', options: { additionallyProtect: raw } }),
			});
			assert.ok(error instanceof NodeOperationError, JSON.stringify(raw));
			assert.match(error.message, /Additionally Protect/);
			assert.match(error.description, /NUMBER, AMOUNT, COMPANY/);
			assert.equal(analyzeCalls.length, 0, 'nothing is sent');
		}
		for (const raw of ['', [], null]) {
			const [item] = await run({
				params: protectParams({ text: 'Invoice K101', options: { additionallyProtect: raw } }),
			});
			assert.equal(item.json.protectedText, 'Invoice K101');
		}
	});
});

describe('review fixes: Detect matches Protect (fake analyze)', () => {
	beforeEach(installFakeAnalyze);

	const detectRun = (text, options = {}) =>
		run({ params: { operation: 'detect', text, options: { includeValues: true, ...options } } });

	// #17
	test('an ignored name inside a company with a legal form is still reported, as Protect replaces it', async () => {
		const text = 'Invoice for Modra d.o.o. is attached';
		analyzeBehaviour.spans = () => [{ entity_type: 'LOCATION', start: 12, end: 17, score: 0.85 }];
		const [detected] = await detectRun(text, { ignoreTerms: 'Modra' });
		const [protectedItem] = await run({
			params: protectParams({ text, options: { ignoreTerms: 'Modra' } }),
		});
		assert.match(
			protectedItem.json.protectedText,
			/^Invoice for \[COMPANY_[a-z0-9]{5}\] is attached$/,
		);
		assert.equal(detected.json.hasPersonalData, true);
		assert.deepEqual(detected.json.entities, [
			{ entityType: 'COMPANY', start: 12, end: 24, score: 0.85, value: 'Modra d.o.o.' },
		]);
		const [exact] = await detectRun(text, { ignoreTerms: 'Modra d.o.o.' });
		assert.equal(exact.json.hasPersonalData, false, 'the whole company as a term is ignored');
	});

	// #32
	test('span edges are trimmed and whitespace-only spans dropped, as Protect does', async () => {
		analyzeBehaviour.spans = () => [{ entity_type: 'PERSON', start: 3, end: 15, score: 0.9 }];
		const [edge] = await detectRun('Hi\nJanez Novak\n\nThanks');
		assert.deepEqual(edge.json.entities, [
			{ entityType: 'PERSON', start: 3, end: 14, score: 0.9, value: 'Janez Novak' },
		]);

		analyzeBehaviour.spans = () => [{ entity_type: 'LOCATION', start: 22, end: 24, score: 0.9 }];
		const [blank] = await detectRun('Thanks for the update.\n\nSee you');
		assert.equal(blank.json.hasPersonalData, false);
		assert.equal(blank.json.entityCount, 0);

		const text = 'Janez Novak\nLjubljana';
		analyzeBehaviour.spans = () => [
			{ entity_type: 'PERSON', start: 0, end: 12, score: 0.9 },
			{ entity_type: 'LOCATION', start: 11, end: 21, score: 0.9 },
		];
		const [both] = await detectRun(text);
		assert.deepEqual(
			both.json.entities.map((e) => [e.entityType, e.value]),
			[
				['PERSON', 'Janez Novak'],
				['LOCATION', 'Ljubljana'],
			],
		);
		const [protectedItem] = await run({ params: protectParams({ text }) });
		assert.equal(protectedItem.json.entities.length, both.json.entityCount);
	});

	test('possible IDs are trimmed too, blank ones dropped', async () => {
		fakeCapabilities = makeCapabilities({ possible: [{ type: 'ORGANIZATION', groups: [] }] });
		const text = 'See  Modra Hisa \n and \n\n';
		analyzeBehaviour.spans = () => [];
		analyzeBehaviour.possible = () => [
			{ start: 4, end: 17, entity_type: 'ORGANIZATION' },
			{ start: 22, end: 24, entity_type: 'ORGANIZATION' },
		];
		const [item] = await detectRun(text, { includePossibleIds: true });
		assert.deepEqual(item.json.possibleIds, [
			{ entityType: 'ORGANIZATION', start: 5, end: 15, value: 'Modra Hisa' },
		]);
	});

	// #27
	test('possible spans of a type the capabilities do not list are dropped (Protect and Detect)', async () => {
		fakeCapabilities = makeCapabilities({ possible: [{ type: 'ORGANIZATION', groups: [] }] });
		const text = 'Ljubljana is nice, Orgx works here.';
		analyzeBehaviour.spans = () => [];
		analyzeBehaviour.possible = (t) => [
			{ start: 0, end: 9, entity_type: 'OTHER' },
			{ start: t.indexOf('Orgx'), end: t.indexOf('Orgx') + 4, entity_type: 'ORGANIZATION' },
		];
		const [detected] = await detectRun(text, { includePossibleIds: true });
		assert.deepEqual(detected.json.possibleIds, [
			{ entityType: 'ORGANIZATION', start: 19, end: 23, value: 'Orgx' },
		]);
		const [protectedItem] = await run({
			params: protectParams({ text, options: { includePossibleIds: true } }),
		});
		assert.deepEqual(
			protectedItem.json.possibleIds.map((p) => p.value),
			['Orgx'],
		);
	});
});
