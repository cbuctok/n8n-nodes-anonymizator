// Placeholder map normaliser and ID files v1/v2 (incl. interop with the extension's real
// sidepanel/sidepanel-idfile.js, lib/id-model.js and lib/id-rules.js). Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

const require = createRequire(import.meta.url);
const pm = require('../dist/nodes/Anonymizator/shared/placeholderMap.js');
const { protectText, revealText } = require('../dist/nodes/Anonymizator/shared/anonymizer.js');
const { PlaceholderMapError } = require('../dist/nodes/Anonymizator/shared/errors.js');
const {
	parsePlaceholderMap,
	normalizePlaceholderMap,
	normalizePlaceholder,
	toIdFile,
	toIdFileV1,
	idSetFromTable,
	idSetProblem,
	defaultIdFileName,
	subKeyParent,
	ID_FILE_ERRORS,
} = pm;

const EXT_FILES = ['lib/id-model.js', 'lib/id-rules.js', 'sidepanel/sidepanel-idfile.js'];
const EXT_DIR =
	process.env.ANON_EXT_DIR ??
	[
		'/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
		'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
	].find((dir) => existsSync(join(dir, 'sidepanel/sidepanel-idfile.js'))) ??
	'';
const hasExt = EXT_DIR !== '' && EXT_FILES.every((file) => existsSync(join(EXT_DIR, file)));
const plain = (x) => JSON.parse(JSON.stringify(x));

/** assert.throws for a PlaceholderMapError with `code` whose message matches `re`. */
function throwsMap(fn, code, re) {
	assert.throws(fn, (err) => {
		assert.ok(err instanceof PlaceholderMapError, `expected PlaceholderMapError, got ${err}`);
		assert.equal(err.code, code, err.message);
		if (re) assert.match(err.message, re);
		return true;
	});
}

const STATE = {
	table: {
		PERSON_a7k2q: 'Ana Kovač Horvat',
		PERSON_a7k2q_NAME: 'Ana',
		PERSON_a7k2q_SURNAME: 'Kovač Horvat',
		CLIENT_x9y8z: 'Modra Vila d.o.o.',
	},
	mine: ['CLIENT_x9y8z'],
	used: [
		'PERSON_a7k2q',
		'PERSON_a7k2q_NAME',
		'PERSON_a7k2q_SURNAME',
		'CLIENT_x9y8z',
		'EMAIL_ADDRESS_q1w2e',
	],
	skipped: ['luka@example.si'],
	numbering: 'random',
	dirty: true,
	fileName: null,
};

function validFile(overrides = {}) {
	return {
		format: 'anonymizator-id-file',
		version: 1,
		name: 'contract',
		numbering: 'sequential',
		ids: [
			{ value: 'Luka Zupan', placeholder: '[PERSON_1]', addedByYou: false },
			{ value: 'K101', placeholder: '[CASE_1]', addedByYou: true },
		],
		usedPlaceholders: ['[PERSON_1]', '[CASE_1]', '[PERSON_2]'],
		...overrides,
	};
}

describe('normalizePlaceholder', () => {
	test('trim, one pair of brackets, inner whitespace to _', () => {
		assert.equal(normalizePlaceholder('  [Client  id] '), 'Client_id');
		assert.equal(normalizePlaceholder('[CASE_2'), 'CASE_2');
		assert.equal(normalizePlaceholder('[[X]]'), '[X]');
		assert.equal(normalizePlaceholder(5), '');
	});
});

describe('parsePlaceholderMap: plain inputs', () => {
	test('empty inputs give an empty map', () => {
		for (const input of [undefined, null, '', '   ', {}, [], '{}', '[]']) {
			assert.deepEqual(
				plain(parsePlaceholderMap(input)),
				{ table: {}, used: [], mine: [] },
				String(input),
			);
		}
	});

	test('object with bare and bracketed keys, insertion order preserved', () => {
		const parsed = parsePlaceholderMap({
			'[PERSON_a7k2q]': 'Janez Novak',
			PERSON_a7k2q_NAME: 'Janez',
			' [EMAIL_ADDRESS_1] ': 'ana.kovac@example.com',
		});
		assert.deepEqual(Object.entries(parsed.table), [
			['PERSON_a7k2q', 'Janez Novak'],
			['PERSON_a7k2q_NAME', 'Janez'],
			['EMAIL_ADDRESS_1', 'ana.kovac@example.com'],
		]);
		assert.deepEqual(parsed.used, ['PERSON_a7k2q', 'PERSON_a7k2q_NAME', 'EMAIL_ADDRESS_1']);
		assert.deepEqual(parsed.mine, []);
		assert.equal(parsed.numbering, undefined);
	});

	test('JSON string, double-encoded JSON string and Protect output item', () => {
		const map = { PERSON_1: 'Janez Novak' };
		assert.deepEqual(plain(normalizePlaceholderMap(JSON.stringify(map))), map);
		assert.deepEqual(plain(normalizePlaceholderMap(JSON.stringify(JSON.stringify(map)))), map);
		assert.deepEqual(
			plain(
				normalizePlaceholderMap({ protectedText: '[PERSON_1]', placeholderMap: map, entities: [] }),
			),
			map,
		);
		assert.deepEqual(plain(normalizePlaceholderMap({ placeholderMap: JSON.stringify(map) })), map);
	});

	test('list of {placeholder, value} or {key, value}; addedByYou goes to mine', () => {
		const parsed = parsePlaceholderMap([
			{ placeholder: '[PERSON_1]', value: 'Janez Novak' },
			{ key: 'CASE_1', value: 'K101', addedByYou: true },
			{ placeholder: 'PERSON_2', value: '' },
		]);
		assert.deepEqual(plain(parsed), {
			table: { PERSON_1: 'Janez Novak', CASE_1: 'K101' },
			used: ['PERSON_1', 'CASE_1', 'PERSON_2'],
			mine: ['CASE_1'],
		});
	});

	test('tombstones (blank values) are used but never in the reveal table', () => {
		const parsed = parsePlaceholderMap({ PERSON_1: 'Ana', PERSON_2: '', PERSON_3: '   ' });
		assert.deepEqual(plain(parsed.table), { PERSON_1: 'Ana' });
		assert.deepEqual(parsed.used, ['PERSON_1', 'PERSON_2', 'PERSON_3']);
		assert.equal(
			revealText(
				'[PERSON_2] and [PERSON_1]',
				normalizePlaceholderMap({ PERSON_1: 'Ana', PERSON_2: '' }),
			),
			'[PERSON_2] and Ana',
		);
	});

	test('duplicate values are allowed in plain maps (reveal does not care)', () => {
		assert.deepEqual(plain(normalizePlaceholderMap({ A_1: 'x', A_2: 'x' })), {
			A_1: 'x',
			A_2: 'x',
		});
	});
});

describe('parsePlaceholderMap: errors', () => {
	test('invalid JSON names the problem', () => {
		throwsMap(() => parsePlaceholderMap('{PERSON_1: Ana}'), 'format', /not valid JSON/);
		throwsMap(
			() => parsePlaceholderMap('{"PERSON_1": "Ana",}'),
			'format',
			/not valid JSON \(line 1, column \d+\)/,
		);
	});

	test('invalid JSON never repeats a value (V8 quotes the input on an unexpected token)', () => {
		for (const input of [
			'{"PERSON_1": "Marta Zupan", "EMAIL_ADDRESS_1": ana.kovac@example.com}',
			'{"PERSON_ab12c": Marta Zupan, "EMAIL_ADDRESS_x1": "x@example.com"}',
			'not json',
		]) {
			assert.throws(
				() => parsePlaceholderMap(input),
				(err) => {
					assert.ok(err instanceof PlaceholderMapError);
					assert.match(err.message, /not valid JSON/);
					for (const leak of ['ana.kovac', 'Marta', 'Zupan', 'not json']) {
						assert.ok(!err.message.includes(leak), `message repeats "${leak}": ${err.message}`);
					}
					return true;
				},
			);
		}
	});

	test('an invalid key is named by position, never repeated (it may be a real value)', () => {
		throwsMap(
			() => parsePlaceholderMap({ PERSON_1: 'Ana', 'Marta Zupan Kovač': 5 }),
			'entries',
			/entry 2 has an invalid placeholder/,
		);
		assert.throws(
			() => parsePlaceholderMap({ 'Marta Zupan Kovač': 'x' }),
			(err) => !err.message.includes('Marta'),
		);
	});

	test('a Protect output item with an unrelated "format" field is unwrapped', () => {
		assert.deepEqual(
			plain(
				normalizePlaceholderMap({
					format: 'markdown',
					protectedText: 'Hi [PERSON_a7k2q]',
					placeholderMap: { PERSON_a7k2q: 'Janez Novak' },
				}),
			),
			{ PERSON_a7k2q: 'Janez Novak' },
		);
		// Without a placeholderMap, a wrong format is still reported as an ID file problem.
		throwsMap(() => parsePlaceholderMap({ format: 'markdown', ids: [] }), 'format', /ID file/);
	});

	test('non-object JSON and scalars', () => {
		throwsMap(() => parsePlaceholderMap(42), 'format', /got a number/);
		throwsMap(() => parsePlaceholderMap('42'), 'format', /got a number/);
		throwsMap(() => parsePlaceholderMap(true), 'format', /got a boolean/);
	});

	test('invalid keys, incl. a suffix longer than 9 digits', () => {
		throwsMap(
			() => parsePlaceholderMap({ person_1: 'Ana' }),
			'entries',
			/entry 1 has an invalid placeholder: a placeholder must start with a capital letter/,
		);
		throwsMap(() => parsePlaceholderMap({ A_1: 'a', '1CASE': 'x' }), 'entries', /entry 2/);
		throwsMap(() => parsePlaceholderMap({ '[[X]]': 'x' }), 'entries', /invalid placeholder/);
		throwsMap(
			() => parsePlaceholderMap({ CUSTOM_1234567890: 'x' }),
			'entries',
			/more than 9 digits/,
		);
		throwsMap(() => parsePlaceholderMap({ '[]': 'x' }), 'entries', /it is empty/);
		throwsMap(() => parsePlaceholderMap({ __proto__: 'x', ['__proto__']: 'y' }), 'entries');
		assert.deepEqual(plain(normalizePlaceholderMap({ CUSTOM_999999999: 'x' })), {
			CUSTOM_999999999: 'x',
		});
	});

	test('non-string values name the key, never the value', () => {
		throwsMap(
			() => parsePlaceholderMap({ CASE_1: 101 }),
			'entries',
			/value of "CASE_1" must be text, got a number/,
		);
		throwsMap(() => parsePlaceholderMap({ CASE_1: null }), 'entries', /got null/);
		throwsMap(() => parsePlaceholderMap({ CASE_1: { a: 1 } }), 'entries', /got an object/);
	});

	test('a reversed map is detected', () => {
		throwsMap(
			() => parsePlaceholderMap({ 'Janez Novak': '[PERSON_1]' }),
			'entries',
			/looks reversed/,
		);
		throwsMap(
			() => parsePlaceholderMap({ 'ana.kovac@example.com': 'EMAIL_ADDRESS_1' }),
			'entries',
			/looks reversed/,
		);
		assert.throws(
			() => parsePlaceholderMap({ 'ana.kovac@example.com': 'EMAIL_ADDRESS_1' }),
			(err) => !err.message.includes('ana.kovac'),
		);
	});

	test('a valid key may hold a bracketed value (an ID written as "[ACME]")', () => {
		const parsed = parsePlaceholderMap({ CUSTOM_ab12c: '[ACME]', CLIENT: '[Big Client]x' });
		assert.deepEqual(plain(parsed.table), { CUSTOM_ab12c: '[ACME]', CLIENT: '[Big Client]x' });
		assert.deepEqual(plain(parsePlaceholderMap({ CLIENT: '[ACME]' }).table), { CLIENT: '[ACME]' });
		assert.deepEqual(
			plain(parsePlaceholderMap([{ placeholder: '[CUSTOM_1]', value: '[ACME]' }]).table),
			{
				CUSTOM_1: '[ACME]',
			},
		);
		// Still reversed: a word as the key and a minted-looking placeholder as the value.
		throwsMap(() => parsePlaceholderMap({ Janez: '[PERSON_1]' }), 'entries', /looks reversed/);
	});

	test('the same key bare and bracketed is a duplicate', () => {
		throwsMap(
			() => parsePlaceholderMap({ PERSON_1: 'Ana', '[PERSON_1]': 'Bob' }),
			'duplicates',
			/"PERSON_1" appears more than once/,
		);
	});

	test('list items must be objects with a placeholder', () => {
		throwsMap(() => parsePlaceholderMap(['PERSON_1']), 'entries', /entry 1 must be an object/);
		throwsMap(
			() => parsePlaceholderMap([{ value: 'Ana' }]),
			'entries',
			/entry 1 has no placeholder/,
		);
		throwsMap(
			() =>
				parsePlaceholderMap([
					{ placeholder: '[A_1]', value: 'a' },
					{ placeholder: 'bad key', value: 'b' },
				]),
			'entries',
			/entry 2 has an invalid placeholder/,
		);
	});
});

// --- ID files: fixtures from the extension's tests/idfile.test.js ---

const rec = (value, key, type, extra = {}) => ({
	value,
	key,
	type,
	mine: false,
	main: true,
	...extra,
});

/** E1 of the extension's M1 contract: a group, name parts and a reveal-only placeholder. */
const E1_SET = {
	ids: [
		rec('Luka Zupan', 'PERSON_a7k2q', 'PERSON'),
		rec('Mr. Zupan', 'PERSON_a7k2q', 'PERSON', { mine: true, main: false }),
		rec('ACME d.o.o.', 'COMPANY_x7gs2', 'COMPANY', { mine: true }),
	],
	subKeys: {
		PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Luka', rec: 'Luka Zupan' },
		PERSON_a7k2q_SURNAME: { of: 'PERSON_a7k2q', value: 'Zupan', rec: 'Luka Zupan' },
	},
	aliases: { CUSTOM_h3k9d: { value: 'Mr. Zupan', owner: 'PERSON_a7k2q' } },
	used: [
		'PERSON_a7k2q',
		'PERSON_a7k2q_NAME',
		'PERSON_a7k2q_SURNAME',
		'CUSTOM_h3k9d',
		'COMPANY_x7gs2',
		'CUSTOM_q1w2e',
	],
	numbering: 'random',
};

const E1_FILE = `{
  "format": "anonymizator-id-file",
  "version": 2,
  "name": "contract",
  "numbering": "random",
  "ids": [
    { "value": "Luka Zupan",  "placeholder": "[PERSON_a7k2q]",  "type": "PERSON",  "addedByYou": false, "main": true },
    { "value": "Mr. Zupan",   "placeholder": "[PERSON_a7k2q]",  "type": "PERSON",  "addedByYou": true,  "main": false },
    { "value": "ACME d.o.o.", "placeholder": "[COMPANY_x7gs2]", "type": "COMPANY", "addedByYou": true }
  ],
  "nameParts":  [ { "placeholder": "[PERSON_a7k2q_NAME]", "value": "Luka", "of": "[PERSON_a7k2q]", "from": "Luka Zupan" },
                  { "placeholder": "[PERSON_a7k2q_SURNAME]", "value": "Zupan", "of": "[PERSON_a7k2q]", "from": "Luka Zupan" } ],
  "revealOnly": [ { "placeholder": "[CUSTOM_h3k9d]", "value": "Mr. Zupan", "of": "[PERSON_a7k2q]" } ],
  "usedPlaceholders": ["[PERSON_a7k2q]", "[PERSON_a7k2q_NAME]", "[PERSON_a7k2q_SURNAME]", "[CUSTOM_h3k9d]", "[COMPANY_x7gs2]", "[CUSTOM_q1w2e]"]
}`;

const v2 = (overrides = {}) => ({ ...JSON.parse(E1_FILE), ...overrides });

/** v2 files the extension refuses as "missing or invalid entries", with our detail. */
const V2_ENTRIES_CASES = [
	[
		'an empty value',
		{ ids: [{ value: ' ', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true }] },
		/Entry 1 has a missing or blank value/,
	],
	[
		'a bad placeholder',
		{ ids: [{ value: 'a', placeholder: 'A_1', type: 'CUSTOM', addedByYou: true }] },
		/Entry 1 has an invalid placeholder/,
	],
	[
		'a digit suffix over 9',
		{ ids: [{ value: 'a', placeholder: '[A_1234567890]', type: 'CUSTOM', addedByYou: true }] },
		/more than 9 digits/,
	],
	[
		'a bad type',
		{ ids: [{ value: 'a', placeholder: '[A_1]', type: 'bad', addedByYou: true }] },
		/Entry 1 has an invalid "type"/,
	],
	[
		'main not a boolean',
		{ ids: [{ value: 'a', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: 'yes' }] },
		/invalid "main"/,
	],
	['an empty ID list', { ids: [] }, /"ids" list is empty/],
	[
		'a name part with an empty value',
		{ nameParts: [{ placeholder: '[PERSON_a7k2q_NAME]', value: '', of: '[PERSON_a7k2q]' }] },
		/nameParts item 1 has a missing or blank value/,
	],
	[
		'a name part with a bad placeholder',
		{ nameParts: [{ placeholder: '[bad]', value: 'x', of: '[PERSON_a7k2q]' }] },
		/nameParts item 1 has an invalid placeholder/,
	],
	[
		'a name part with a long suffix',
		{ nameParts: [{ placeholder: '[P_1234567890]', value: 'x', of: '[PERSON_a7k2q]' }] },
		/more than 9 digits/,
	],
	[
		'a name part without of',
		{ nameParts: [{ placeholder: '[PERSON_a7k2q_NAME]', value: 'x' }] },
		/nameParts item 1 has an invalid "of"/,
	],
	[
		'a name part with a non-text from',
		{
			nameParts: [
				{ placeholder: '[PERSON_a7k2q_NAME]', value: 'x', of: '[PERSON_a7k2q]', from: 1 },
			],
		},
		/invalid "from"/,
	],
	[
		'a name part from a value not in its group',
		{
			nameParts: [
				{
					placeholder: '[PERSON_a7k2q_NAME]',
					value: 'x',
					of: '[PERSON_a7k2q]',
					from: 'ACME d.o.o.',
				},
			],
		},
		/"from" that is not one of the values of "\[PERSON_a7k2q\]"/,
	],
	[
		'a reveal-only entry without of',
		{ revealOnly: [{ placeholder: '[X_1]', value: 'x' }] },
		/revealOnly item 1 has an invalid "of"/,
	],
	[
		'a reveal-only entry with an empty value',
		{ revealOnly: [{ placeholder: '[X_1]', value: '', of: '[PERSON_a7k2q]' }] },
		/revealOnly item 1 has a missing or blank value/,
	],
	[
		'a name part whose of is not an ID',
		{ nameParts: [{ placeholder: '[P_NAME]', value: 'x', of: '[NOPE_1]' }] },
		/"\[NOPE_1\]", which is not an ID in this file/,
	],
	[
		'a name part of a COMPANY (only a PERSON has name parts)',
		{ nameParts: [{ placeholder: '[COMPANY_x7gs2_NAME]', value: 'ACME', of: '[COMPANY_x7gs2]' }] },
		/not a PERSON ID/,
	],
	[
		'a name part of an untyped CUSTOM ID',
		{
			ids: [{ value: 'Mr. Zupan', placeholder: '[CUSTOM_h3k9d]', addedByYou: true }],
			nameParts: [{ placeholder: '[CUSTOM_h3k9d_SURNAME]', value: 'Zupan', of: '[CUSTOM_h3k9d]' }],
			revealOnly: [],
		},
		/not a PERSON ID/,
	],
	[
		'a reveal-only entry whose of is not an ID',
		{ revealOnly: [{ placeholder: '[X_1]', value: 'x', of: '[NOPE_1]' }] },
		/Reveal-only placeholder "\[X_1\]" belongs to "\[NOPE_1\]"/,
	],
	[
		'a group without a main',
		{
			ids: [
				{ value: 'a', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: false },
				{ value: 'b', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: false },
			],
		},
		/exactly one of them must have "main": true/,
	],
	[
		'a group with two mains',
		{
			ids: [
				{ value: 'a', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: true },
				{ value: 'b', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: true },
			],
			nameParts: [],
			revealOnly: [],
		},
		/exactly one/,
	],
	[
		'a group with two types',
		{
			ids: [
				{ value: 'a', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true, main: true },
				{ value: 'b', placeholder: '[A_1]', type: 'PERSON', addedByYou: true, main: false },
			],
		},
		/different types/,
	],
	[
		'a group in a masked file',
		{ numbering: 'typed', revealOnly: [] },
		/"typed" numbering cannot have/,
	],
	[
		'reveal-only entries in a masked file',
		{ numbering: 'redacted', ids: [JSON.parse(E1_FILE).ids[2]], nameParts: [] },
		/"redacted" numbering cannot have "revealOnly"/,
	],
	['nameParts not a list', { nameParts: {} }, /"nameParts" must be a list/],
	['revealOnly not a list', { revealOnly: 'x' }, /"revealOnly" must be a list/],
	['bad usedPlaceholders', { usedPlaceholders: ['nope'] }, /usedPlaceholders item 1 is invalid/],
	['usedPlaceholders not a list', { usedPlaceholders: 'x' }, /"usedPlaceholders" must be a list/],
	['an entry that is not an object', { ids: [null] }, /Entry 1 is not an object/],
];

/** v2 files the extension refuses as duplicates, with our detail. */
const V2_DUPLICATE_CASES = [
	[
		'a duplicate value',
		{
			ids: [
				{ value: 'a', placeholder: '[A_1]', type: 'CUSTOM', addedByYou: true },
				{ value: 'a', placeholder: '[A_2]', type: 'CUSTOM', addedByYou: true },
			],
		},
		/Entries 1 and 2 have the same value/,
	],
	[
		'values that differ only by spaces',
		{
			ids: [
				{ value: 'ACME', placeholder: '[CUSTOM_aaaa1]', type: 'CUSTOM', addedByYou: true },
				{ value: ' ACME ', placeholder: '[CUSTOM_bbbb2]', type: 'CUSTOM', addedByYou: true },
			],
		},
		/Entries 1 and 2/,
	],
	[
		'a name part that is also an ID',
		{ nameParts: [{ placeholder: '[COMPANY_x7gs2]', value: 'x', of: '[PERSON_a7k2q]' }] },
		/both an ID and a name part/,
	],
	[
		'a reveal-only placeholder that is also an ID',
		{ revealOnly: [{ placeholder: '[COMPANY_x7gs2]', value: 'x', of: '[PERSON_a7k2q]' }] },
		/both an ID and a reveal-only placeholder/,
	],
	[
		'a placeholder in nameParts and revealOnly',
		{ revealOnly: [{ placeholder: '[PERSON_a7k2q_NAME]', value: 'x', of: '[PERSON_a7k2q]' }] },
		/both a name part and a reveal-only placeholder/,
	],
	[
		'a placeholder twice in nameParts',
		{
			nameParts: [
				{ placeholder: '[P_NAME]', value: 'x', of: '[PERSON_a7k2q]' },
				{ placeholder: '[P_NAME]', value: 'y', of: '[PERSON_a7k2q]' },
			],
		},
		/more than once in "nameParts"/,
	],
	[
		'a placeholder twice in revealOnly',
		{
			revealOnly: [
				{ placeholder: '[X_1]', value: 'x', of: '[PERSON_a7k2q]' },
				{ placeholder: '[X_1]', value: 'y', of: '[PERSON_a7k2q]' },
			],
		},
		/more than once in "revealOnly"/,
	],
];

const V1_FORMAT_CASES = [
	['another format', { format: 'anonymizator-key' }, /"format" must be/],
	['another version', { version: 3 }, /Only versions 1 and 2/],
	['a string version', { version: '2' }, /Only versions 1 and 2/],
	['unknown numbering', { numbering: 'shuffled' }, /"numbering" must be one of/],
	['ids not a list', { ids: {} }, /"ids" must be a list/],
];

/** Every value of the fixtures, so a test can check that no message repeats one. */
function valuesOf(data) {
	const out = [];
	const walk = (x) => {
		if (Array.isArray(x)) x.forEach(walk);
		else if (x && typeof x === 'object') {
			for (const [k, v] of Object.entries(x)) {
				if ((k === 'value' || k === 'from') && typeof v === 'string' && v.trim().length > 2) {
					out.push(v.trim());
				} else walk(v);
			}
		}
	};
	walk(data);
	return out;
}

describe('ID file v1 input (port of tests/idfile.test.js parse cases)', () => {
	test('turns a valid file into table, mine, used, numbering and the v2 set', () => {
		assert.deepEqual(plain(parsePlaceholderMap(validFile())), {
			table: { PERSON_1: 'Luka Zupan', CASE_1: 'K101' },
			used: ['PERSON_1', 'CASE_1', 'PERSON_2'],
			mine: ['CASE_1'],
			numbering: 'sequential',
			set: {
				ids: [
					rec('K101', 'CASE_1', 'CUSTOM', { mine: true }),
					rec('Luka Zupan', 'PERSON_1', 'PERSON'),
				],
				subKeys: {},
				aliases: {},
				used: ['PERSON_1', 'CASE_1', 'PERSON_2'],
				numbering: 'sequential',
			},
		});
		assert.deepEqual(plain(parsePlaceholderMap(JSON.stringify(validFile())).table), {
			PERSON_1: 'Luka Zupan',
			CASE_1: 'K101',
		});
	});

	test('PERSON sub-keys become name parts; types come from the keys', () => {
		const { set, table } = parsePlaceholderMap(
			validFile({
				ids: [
					{ value: 'Luka Zupan', placeholder: '[PERSON_1]', addedByYou: false },
					{ value: 'Luka', placeholder: '[PERSON_1_NAME]', addedByYou: false },
					{ value: 'luka@x.si', placeholder: '[EMAIL_ADDRESS_2]', addedByYou: false },
					{ value: 'SI56', placeholder: '[IBAN_CODE_3]', addedByYou: false },
					{ value: 'x@y.si', placeholder: '[EMAIL_ab1cd]', addedByYou: false },
				],
			}),
		);
		assert.deepEqual(plain(set.subKeys), {
			PERSON_1_NAME: { of: 'PERSON_1', value: 'Luka', rec: 'Luka Zupan' },
		});
		assert.deepEqual(
			set.ids.map((r) => [r.key, r.type]),
			[
				['EMAIL_ab1cd', 'EMAIL_ADDRESS'],
				['IBAN_CODE_3', 'IBAN'],
				['EMAIL_ADDRESS_2', 'EMAIL_ADDRESS'],
				['PERSON_1', 'PERSON'],
			],
		);
		assert.equal(table.PERSON_1_NAME, 'Luka');
	});

	test('values are stored trimmed, as the extension keeps them', () => {
		const ids = [{ value: '  K101 ', placeholder: '[CASE_1]', addedByYou: true }];
		const parsed = parsePlaceholderMap(validFile({ ids }));
		assert.equal(parsed.table.CASE_1, 'K101');
		assert.equal(parsed.set.ids[0].value, 'K101');
	});

	test('a file without usedPlaceholders; lowercase random suffixes', () => {
		const data = validFile();
		delete data.usedPlaceholders;
		assert.deepEqual(parsePlaceholderMap(data).used, ['PERSON_1', 'CASE_1']);
		const random = validFile({
			ids: [{ value: 'Ana', placeholder: '[PERSON_a7k2q]', addedByYou: false }],
			usedPlaceholders: [],
		});
		assert.deepEqual(plain(parsePlaceholderMap(random).table), { PERSON_a7k2q: 'Ana' });
	});

	for (const [label, overrides, re] of V1_FORMAT_CASES) {
		test(`rejects ${label}`, () =>
			throwsMap(() => parsePlaceholderMap(validFile(overrides)), 'format', re));
	}

	test('rejects an empty ID list', () => {
		throwsMap(() => parsePlaceholderMap(validFile({ ids: [] })), 'entries', /empty/);
	});

	for (const [label, placeholder] of [
		['bare', 'PERSON_1'],
		['lowercase start', '[person_1]'],
		['digit start', '[1_PERSON]'],
		['with spaces', '[PERSON 1]'],
		['with a dash', '[PERSON-1]'],
		['empty', '[]'],
		['10-digit suffix', '[CASE_1234567890]'],
	]) {
		test(`rejects a ${label} placeholder`, () => {
			throwsMap(
				() =>
					parsePlaceholderMap(validFile({ ids: [{ value: 'a', placeholder, addedByYou: true }] })),
				'entries',
				/Entry 1 has an invalid placeholder/,
			);
		});
	}

	test('rejects blank or non-string values, bad usedPlaceholders', () => {
		throwsMap(
			() => parsePlaceholderMap(validFile({ ids: [{ value: '  ', placeholder: '[A_1]' }] })),
			'entries',
			/blank value/,
		);
		throwsMap(
			() => parsePlaceholderMap(validFile({ ids: [{ value: 5, placeholder: '[A_1]' }] })),
			'entries',
		);
		throwsMap(
			() => parsePlaceholderMap(validFile({ usedPlaceholders: 'x' })),
			'entries',
			/must be a list/,
		);
		throwsMap(() => parsePlaceholderMap(validFile({ usedPlaceholders: [1] })), 'entries', /item 1/);
		throwsMap(() => parsePlaceholderMap(validFile({ usedPlaceholders: ['nope'] })), 'entries');
		throwsMap(
			() => parsePlaceholderMap(validFile({ usedPlaceholders: ['[CASE_99999999999999999999]'] })),
			'entries',
			/9 digits/,
		);
	});

	test('rejects duplicate placeholders and values (also when only spaces differ); PERSON sub-keys may share', () => {
		throwsMap(
			() =>
				parsePlaceholderMap(
					validFile({
						ids: [
							{ value: 'a', placeholder: '[A_1]' },
							{ value: 'b', placeholder: '[A_1]' },
						],
					}),
				),
			'duplicates',
			/"\[A_1\]" appears more than once/,
		);
		throwsMap(
			() =>
				parsePlaceholderMap(
					validFile({
						ids: [
							{ value: 'a', placeholder: '[A_1]' },
							{ value: ' a ', placeholder: '[A_2]' },
						],
					}),
				),
			'duplicates',
			/"\[A_1\]" and "\[A_2\]" have the same value/,
		);
		const anas = [
			{ value: 'Ana Kovač', placeholder: '[PERSON_1]' },
			{ value: 'Ana', placeholder: '[PERSON_1_NAME]' },
			{ value: 'Ana Novak', placeholder: '[PERSON_2]' },
			{ value: 'Ana', placeholder: '[PERSON_2_NAME]' },
		];
		assert.equal(Object.keys(parsePlaceholderMap(validFile({ ids: anas })).table).length, 4);
		const client = [
			{ value: 'Acme', placeholder: '[CLIENT]', addedByYou: true },
			{ value: 'Acme', placeholder: '[CLIENT_NAME]', addedByYou: true },
		];
		throwsMap(() => parsePlaceholderMap(validFile({ ids: client })), 'duplicates');
		const own = [
			{ value: 'Ana', placeholder: '[PERSON_x]', addedByYou: true },
			{ value: 'Ana', placeholder: '[PERSON_x_NAME]', addedByYou: true },
		];
		throwsMap(() => parsePlaceholderMap(validFile({ ids: own })), 'duplicates');
	});

	test('messages start with the extension message', () => {
		assert.throws(
			() => parsePlaceholderMap(validFile({ version: 9 })),
			(e) => e.message.startsWith(ID_FILE_ERRORS.format),
		);
	});

	test('subKeyParent', () => {
		assert.equal(subKeyParent('PERSON_1_NAME', { PERSON_1: 'a' }, []), 'PERSON_1');
		assert.equal(subKeyParent('PERSON_1_NAME', { PERSON_1: 'a' }, new Set(['PERSON_1'])), null);
		assert.equal(subKeyParent('PERSON_1_NAME', {}, []), null);
		assert.equal(subKeyParent('CLIENT_NAME', { CLIENT: 'a' }, []), null);
	});
});

describe('ID file v2 input (port of tests/idfile.test.js parse cases)', () => {
	test('E1: groups, name parts and reveal-only placeholders', () => {
		const parsed = parsePlaceholderMap(E1_FILE);
		assert.deepEqual(plain(parsed.set), E1_SET);
		// Reveal table: main values, then name parts, then reveal-only placeholders. The group
		// member "Mr. Zupan" of PERSON_a7k2q is only in `set`.
		assert.deepEqual(Object.entries(parsed.table), [
			['PERSON_a7k2q', 'Luka Zupan'],
			['COMPANY_x7gs2', 'ACME d.o.o.'],
			['PERSON_a7k2q_NAME', 'Luka'],
			['PERSON_a7k2q_SURNAME', 'Zupan'],
			['CUSTOM_h3k9d', 'Mr. Zupan'],
		]);
		assert.deepEqual(parsed.mine, ['COMPANY_x7gs2']);
		assert.deepEqual(parsed.used, E1_SET.used);
		assert.equal(parsed.numbering, 'random');
	});

	test('reveal brings back main values, name parts and reveal-only placeholders', () => {
		const { table } = parsePlaceholderMap(v2());
		assert.equal(
			revealText('[PERSON_a7k2q] ([PERSON_a7k2q_NAME]), [CUSTOM_h3k9d] of [COMPANY_x7gs2]', table),
			'Luka Zupan (Luka), Mr. Zupan of ACME d.o.o.',
		);
	});

	test('optional fields: no nameParts / revealOnly / usedPlaceholders, no main on a single ID, from defaults to the main', () => {
		const data = v2({
			nameParts: [{ placeholder: '[PERSON_a7k2q_NAME]', value: 'Luka', of: '[PERSON_a7k2q]' }],
		});
		delete data.revealOnly;
		delete data.usedPlaceholders;
		const { set, used } = parsePlaceholderMap(data);
		assert.deepEqual(plain(set.subKeys.PERSON_a7k2q_NAME), {
			of: 'PERSON_a7k2q',
			value: 'Luka',
			rec: 'Luka Zupan',
		});
		assert.deepEqual(plain(set.aliases), {});
		assert.deepEqual(used, ['PERSON_a7k2q', 'COMPANY_x7gs2', 'PERSON_a7k2q_NAME']);
		assert.deepEqual(
			plain(set.ids[2]),
			rec('ACME d.o.o.', 'COMPANY_x7gs2', 'COMPANY', { mine: true }),
		);
	});

	test('an entry without a type gets the type of its key', () => {
		const data = v2({
			ids: [{ value: 'x@y.si', placeholder: '[EMAIL_ab1cd]', addedByYou: false }],
			nameParts: [],
			revealOnly: [],
		});
		assert.equal(parsePlaceholderMap(data).set.ids[0].type, 'EMAIL_ADDRESS');
	});

	test('name parts may repeat any value (two people named Ana)', () => {
		const data = v2({
			ids: [
				{ value: 'Ana Kovač', placeholder: '[PERSON_1]', type: 'PERSON', addedByYou: false },
				{ value: 'Ana Novak', placeholder: '[PERSON_2]', type: 'PERSON', addedByYou: false },
			],
			nameParts: [
				{ placeholder: '[PERSON_1_NAME]', value: 'Ana', of: '[PERSON_1]' },
				{ placeholder: '[PERSON_2_NAME]', value: 'Ana', of: '[PERSON_2]' },
			],
			revealOnly: [],
			usedPlaceholders: [],
		});
		assert.deepEqual(Object.keys(parsePlaceholderMap(data).set.subKeys), [
			'PERSON_1_NAME',
			'PERSON_2_NAME',
		]);
	});

	test('a Protect output item that carries an ID file v2 in `format` fields is still unwrapped', () => {
		const parsed = parsePlaceholderMap({ placeholderMap: { PERSON_1: 'a' }, format: 'pdf' });
		assert.equal(parsed.set, undefined);
		assert.deepEqual(plain(parsed.table), { PERSON_1: 'a' });
	});

	test('a Protect output item with copied ID file fields uses its placeholderMap', () => {
		const parsed = parsePlaceholderMap({
			...v2(),
			placeholderMap: { PERSON_1: 'Janez Novak', PERSON_2: 'Ana Kos', OLD_1: '' },
		});
		assert.equal(parsed.set, undefined);
		assert.deepEqual(plain(parsed.table), { PERSON_1: 'Janez Novak', PERSON_2: 'Ana Kos' });
		assert.deepEqual(parsed.used, ['PERSON_1', 'PERSON_2', 'OLD_1']);
	});

	test('a Protect output item with a current idFile uses the idFile (groups kept)', () => {
		const file = v2();
		const flat = pm.parsePlaceholderMap(file);
		const item = { placeholderMap: { ...flat.table }, idFile: file };
		const parsed = parsePlaceholderMap(item);
		assert.ok(parsed.set);
		assert.deepEqual(plain(parsed.set), plain(flat.set));
		// The idFile alone (Include Placeholder Map output trimmed by hand) works too.
		assert.deepEqual(plain(parsePlaceholderMap({ idFile: file }).set), plain(flat.set));
		// An invalid idFile with no placeholderMap is refused with the ID file's own message.
		throwsMap(() => parsePlaceholderMap({ idFile: { ...file, version: 7 } }), 'format', /versions/);
	});

	for (const [label, overrides, re] of V2_ENTRIES_CASES) {
		test(`rejects ${label} (entries)`, () => {
			const data = v2(overrides);
			throwsMap(() => parsePlaceholderMap(data), 'entries', re);
			assert.throws(
				() => parsePlaceholderMap(data),
				(e) => e.message.startsWith(ID_FILE_ERRORS.entries),
			);
		});
	}
	for (const [label, overrides, re] of V2_DUPLICATE_CASES) {
		test(`rejects ${label} (duplicates)`, () => {
			const data = v2(overrides);
			throwsMap(() => parsePlaceholderMap(data), 'duplicates', re);
			assert.throws(
				() => parsePlaceholderMap(data),
				(e) => e.message.startsWith(ID_FILE_ERRORS.duplicates),
			);
		});
	}
	for (const [label, overrides, re] of V1_FORMAT_CASES) {
		test(`rejects ${label} (format)`, () =>
			throwsMap(() => parsePlaceholderMap(v2(overrides)), 'format', re));
	}

	test('no message ever repeats a value', () => {
		for (const [, overrides] of [...V2_ENTRIES_CASES, ...V2_DUPLICATE_CASES]) {
			const data = v2(overrides);
			let message = '';
			try {
				parsePlaceholderMap(data);
			} catch (e) {
				message = e.message;
			}
			assert.ok(message !== '');
			for (const value of valuesOf(data)) {
				assert.ok(!message.includes(value), `${message} contains a value`);
			}
		}
	});
});

describe('toIdFile (v2)', () => {
	test('writes the contract §3 example byte for byte (same keys, same order)', () => {
		const file = toIdFile(E1_SET, 'contract.json');
		assert.equal(JSON.stringify(file, null, 2), JSON.stringify(JSON.parse(E1_FILE), null, 2));
	});

	test('never writes skipped, ignored, locks or session flags', () => {
		const file = toIdFile(
			{
				...E1_SET,
				skipped: ['Skipped Value'],
				ignored: ['Ignored Value'],
				locked: ['PERSON_a7k2q'],
				dirty: true,
			},
			'contract',
		);
		const text = JSON.stringify(file);
		for (const word of [
			'Skipped Value',
			'Ignored Value',
			'locked',
			'dirty',
			'skipped',
			'ignored',
		]) {
			assert.ok(!text.includes(word), word);
		}
		assert.equal(JSON.stringify(file, null, 2), JSON.stringify(JSON.parse(E1_FILE), null, 2));
	});

	test('defaults: name from the current local time; every key is recorded as used', () => {
		const file = toIdFile({ ids: [rec('a', 'A_1', 'CUSTOM')], used: [], numbering: 'sequential' });
		assert.match(file.name, /^\d{8}T\d{6}-anonymizator-ids$/);
		assert.deepEqual(file.usedPlaceholders, ['[A_1]']);
		assert.deepEqual(file.nameParts, []);
		assert.deepEqual(file.revealOnly, []);
		assert.equal(file.numbering, 'sequential');
	});

	test('round trip: toIdFile -> JSON -> parsePlaceholderMap -> toIdFile', () => {
		const first = toIdFile(E1_SET, 'c.json');
		const { set } = parsePlaceholderMap(JSON.stringify(first));
		assert.deepEqual(toIdFile(set, 'c.json'), first);
	});

	test('keeps redacted numbering through a round trip', () => {
		const set = {
			ids: [rec('Acme', 'CUSTOM_ab1cd', 'CUSTOM', { mine: true })],
			used: [],
			numbering: 'redacted',
		};
		const file = toIdFile(set, 'r.json');
		assert.equal(file.numbering, 'redacted');
		assert.equal(parsePlaceholderMap(JSON.stringify(file)).set.numbering, 'redacted');
	});

	const refusals = [
		['an empty set', { ...E1_SET, ids: [] }, 'entries', /no IDs to save/],
		['a bad numbering', { ...E1_SET, numbering: 'x' }, 'entries', /numbering must be one of/],
		[
			'a bad used key',
			{ ...E1_SET, used: ['ok_no'] },
			'entries',
			/used placeholder 1 is not valid/,
		],
		[
			'a blank value',
			{ ...E1_SET, ids: [rec(' ', 'A_1', 'CUSTOM')] },
			'entries',
			/ID 1 has a missing or blank value/,
		],
		[
			'an untrimmed value',
			{ ...E1_SET, ids: [rec(' Ana', 'A_1', 'CUSTOM')], subKeys: {}, aliases: {} },
			'entries',
			/leading or trailing spaces/,
		],
		[
			'a bad key',
			{ ...E1_SET, ids: [rec('Ana', 'a_1', 'CUSTOM')] },
			'entries',
			/ID 1 has an invalid placeholder/,
		],
		['a bad type', { ...E1_SET, ids: [rec('Ana', 'A_1', 'person')] }, 'entries', /invalid type/],
		[
			'a missing main flag',
			{ ...E1_SET, ids: [{ value: 'Ana', key: 'A_1', type: 'CUSTOM', mine: false }] },
			'entries',
			/main value/,
		],
		[
			'a duplicate value',
			{
				...E1_SET,
				ids: [rec('Ana', 'A_1', 'CUSTOM'), rec('Ana', 'A_2', 'CUSTOM')],
				subKeys: {},
				aliases: {},
			},
			'duplicates',
			/"A_1" and "A_2" have the same value/,
		],
		[
			'a group with two mains',
			{
				...E1_SET,
				ids: [rec('a', 'A_1', 'CUSTOM'), rec('b', 'A_1', 'CUSTOM')],
				subKeys: {},
				aliases: {},
			},
			'entries',
			/exactly one main/,
		],
		[
			'a group with two types',
			{
				...E1_SET,
				ids: [rec('a', 'A_1', 'CUSTOM'), rec('b', 'A_1', 'PERSON', { main: false })],
				subKeys: {},
				aliases: {},
			},
			'entries',
			/different types/,
		],
		[
			'a group in a masked set',
			{ ...E1_SET, numbering: 'typed', aliases: {} },
			'entries',
			/"typed" numbering cannot have/,
		],
		[
			'aliases in a masked set',
			{ ...E1_SET, ids: [E1_SET.ids[0], E1_SET.ids[2]], numbering: 'redacted' },
			'entries',
			/reveal-only/,
		],
		[
			'a name part of a company',
			{
				...E1_SET,
				subKeys: { COMPANY_x7gs2_NAME: { of: 'COMPANY_x7gs2', value: 'ACME', rec: 'ACME d.o.o.' } },
			},
			'entries',
			/not a PERSON ID/,
		],
		[
			'a name part of nothing',
			{ ...E1_SET, subKeys: { P_NAME: { of: 'NOPE', value: 'x', rec: 'x' } } },
			'entries',
			/does not belong/,
		],
		[
			'a name part that is an ID',
			{
				...E1_SET,
				subKeys: { COMPANY_x7gs2: { of: 'PERSON_a7k2q', value: 'x', rec: 'Luka Zupan' } },
			},
			'entries',
			/both an ID and a name part/,
		],
		[
			'a name part from a value not in its group',
			{
				...E1_SET,
				subKeys: { PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Luka', rec: 'Somebody Else' } },
			},
			'entries',
			/would load: .*"from" that is not one of the values/,
		],
		[
			'an alias of nothing',
			{ ...E1_SET, aliases: { X_1: { value: 'x', owner: 'NOPE' } } },
			'entries',
			/does not belong/,
		],
		[
			'an alias that is a name part',
			{ ...E1_SET, aliases: { PERSON_a7k2q_NAME: { value: 'x', owner: 'PERSON_a7k2q' } } },
			'entries',
			/also an ID or a name part/,
		],
	];
	for (const [label, set, code, re] of refusals) {
		test(`refuses ${label}`, () => {
			throwsMap(() => toIdFile(set, 'x'), code, re);
			try {
				toIdFile(set, 'x');
			} catch (e) {
				assert.match(e.message, /^Cannot build an ID file/);
				for (const value of valuesOf(set)) assert.ok(!e.message.includes(value), e.message);
			}
		});
	}

	test('idSetProblem is null for a valid set', () => {
		assert.equal(idSetProblem(E1_SET), null);
		assert.equal(idSetProblem({ ...E1_SET, subKeys: undefined, aliases: undefined }), null);
	});
});

describe('idSetFromTable (the extension fromV1 rules) and the legacy v1 writer', () => {
	test('a flat table becomes a v2 set: name parts of found PERSONs, newest first, types from keys', () => {
		const set = idSetFromTable(STATE.table, 'random', { mine: STATE.mine, used: STATE.used });
		assert.deepEqual(plain(set), {
			ids: [
				rec('Modra Vila d.o.o.', 'CLIENT_x9y8z', 'CUSTOM', { mine: true }),
				rec('Ana Kovač Horvat', 'PERSON_a7k2q', 'PERSON'),
			],
			subKeys: {
				PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Ana', rec: 'Ana Kovač Horvat' },
				PERSON_a7k2q_SURNAME: {
					of: 'PERSON_a7k2q',
					value: 'Kovač Horvat',
					rec: 'Ana Kovač Horvat',
				},
			},
			aliases: {},
			used: STATE.used,
			numbering: 'random',
		});
		const file = toIdFile(set, 'n.json');
		assert.equal(file.version, 2);
		assert.deepEqual(plain(parsePlaceholderMap(file).table), {
			CLIENT_x9y8z: 'Modra Vila d.o.o.',
			PERSON_a7k2q: 'Ana Kovač Horvat',
			PERSON_a7k2q_NAME: 'Ana',
			PERSON_a7k2q_SURNAME: 'Kovač Horvat',
		});
		assert.equal(idSetFromTable({ A_1: 'a' }, 'bogus').numbering, 'random');
	});

	test('defaultIdFileName: local time, zero-padded', () => {
		assert.equal(
			defaultIdFileName(new Date(2026, 8, 30, 8, 18, 39)),
			'20260930T081839-anonymizator-ids.json',
		);
		assert.equal(
			defaultIdFileName(new Date(2027, 0, 2, 3, 4, 5)),
			'20270102T030405-anonymizator-ids.json',
		);
	});

	test('the legacy form toIdFile(table, numbering, name, extras) still writes v1', () => {
		const file = toIdFile(STATE.table, 'random', '20260930T081839-anonymizator-ids.json', {
			mine: STATE.mine,
			used: STATE.used,
		});
		assert.deepEqual(
			file,
			toIdFileV1(STATE.table, 'random', '20260930T081839-anonymizator-ids.json', STATE),
		);
		assert.equal(file.version, 1);
		assert.equal(file.name, '20260930T081839-anonymizator-ids');
		assert.deepEqual(file.ids, [
			{ value: 'Ana Kovač Horvat', placeholder: '[PERSON_a7k2q]', addedByYou: false },
			{ value: 'Ana', placeholder: '[PERSON_a7k2q_NAME]', addedByYou: false },
			{ value: 'Kovač Horvat', placeholder: '[PERSON_a7k2q_SURNAME]', addedByYou: false },
			{ value: 'Modra Vila d.o.o.', placeholder: '[CLIENT_x9y8z]', addedByYou: true },
		]);
		assert.ok(file.usedPlaceholders.includes('[EMAIL_ADDRESS_q1w2e]'));
		assert.ok(!JSON.stringify(file).includes('luka@example.si'));
		assert.match(toIdFile({ A_1: 'a' }, 'sequential').name, /^\d{8}T\d{6}-anonymizator-ids$/);
		assert.equal(toIdFile({ A_1: 'a' }, 'bogus').numbering, 'random');
	});

	test('the legacy v1 writer refuses what the extension would refuse', () => {
		throwsMap(() => toIdFile({}, 'random'), 'entries', /no placeholders to save/);
		throwsMap(() => toIdFile({ A_1: ' ' }, 'random'), 'entries', /"A_1" is missing or blank/);
		throwsMap(() => toIdFile({ a_1: 'x' }, 'random'), 'entries', /not a valid placeholder/);
		throwsMap(
			() => toIdFile({ A_1: 'x', A_2: ' x' }, 'random'),
			'duplicates',
			/"A_1" and "A_2" have the same value/,
		);
		throwsMap(
			() => toIdFile({ A_1: 'x' }, 'random', 'n', { used: ['A_12345678901'] }),
			'entries',
			/used placeholder/,
		);
	});

	test('legacy v1 round trip through our own parser', () => {
		const file = JSON.parse(
			JSON.stringify(
				toIdFile(STATE.table, 'random', 'set.json', { mine: STATE.mine, used: STATE.used }),
			),
		);
		const parsed = parsePlaceholderMap(file);
		assert.deepEqual(plain(parsed.table), STATE.table);
		assert.deepEqual(parsed.mine, STATE.mine);
		assert.deepEqual(new Set(parsed.used), new Set(STATE.used));
		assert.equal(parsed.numbering, 'random');
	});
});

test('continuing a map: sequential numbering resumes after tombstones and an ID file', () => {
	const parsed = parsePlaceholderMap(validFile());
	const text = 'Luka Zupan met Janez Novak';
	const res = protectText(
		text,
		[
			{ entity_type: 'PERSON', start: 0, end: 10 },
			{ entity_type: 'PERSON', start: 15, end: 26 },
		],
		parsed,
		'sequential',
	);
	assert.equal(res.text, '[PERSON_1] met [PERSON_3]');
	assert.deepEqual(plain(res.newEntries), {
		PERSON_3: 'Janez Novak',
		PERSON_3_NAME: 'Janez',
		PERSON_3_SURNAME: 'Novak',
	});
	const table = { ...parsed.table, ...res.newEntries };
	assert.equal(revealText(res.text, table), text);
});

/** Deterministic PRNG (mulberry32) for the generated interop cases. */
function prng(seed) {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

/** Random ID files, mostly near-valid, to compare accept/reject decisions with the extension. */
function generatedFiles(count, seed) {
	const rnd = prng(seed);
	const pick = (list) => list[Math.floor(rnd() * list.length)];
	const keys = [
		'PERSON_1',
		'PERSON_ab1cd',
		'EMAIL_x7gs2',
		'CLIENT',
		'IBAN_CODE_2',
		'COMPANY_q1w2e',
		'A_1',
	];
	const values = ['Ana', 'Ana Novak', ' Ana ', 'Luka Zupan', 'x@y.si', 'ACME d.o.o.', '', 'K101'];
	const types = [undefined, 'PERSON', 'CUSTOM', 'COMPANY', 'EMAIL_ADDRESS', 'bad'];
	const files = [];
	for (let n = 0; n < count; n++) {
		const ids = [];
		for (let i = 0, len = 1 + Math.floor(rnd() * 4); i < len; i++) {
			const entry = {
				value: pick(values),
				placeholder: `[${pick(keys)}]`,
				addedByYou: rnd() < 0.3,
			};
			const type = pick(types);
			if (type !== undefined) entry.type = type;
			if (rnd() < 0.3) entry.main = rnd() < 0.5;
			ids.push(entry);
		}
		const part = (withFrom) => {
			const p = {
				placeholder: `[${pick(keys)}_${pick(['NAME', 'SURNAME'])}]`,
				value: pick(values),
				of: `[${pick(keys)}]`,
			};
			if (withFrom) p.from = pick(values);
			return p;
		};
		const file = {
			format: 'anonymizator-id-file',
			version: rnd() < 0.3 ? 1 : 2,
			name: 'g',
			numbering: pick(['random', 'sequential', 'typed', 'redacted']),
			ids: rnd() < 0.05 ? [] : ids,
		};
		if (rnd() < 0.5) file.nameParts = rnd() < 0.5 ? [] : [part(rnd() < 0.5)];
		if (rnd() < 0.4) {
			file.revealOnly = [
				{ placeholder: `[${pick(keys)}]`, value: pick(values), of: `[${pick(keys)}]` },
			];
		}
		if (rnd() < 0.5) file.usedPlaceholders = [`[${pick(keys)}]`, ...(rnd() < 0.1 ? ['bad'] : [])];
		files.push(file);
	}
	return files;
}

describe(
	'interop with the extension (real sidepanel-idfile.js, id-model.js and id-rules.js)',
	{ skip: !hasExt && 'extension checkout not found (set ANON_EXT_DIR)' },
	() => {
		const loadExt = () => {
			const ctx = vm.createContext({ crypto: webcrypto });
			ctx.self = ctx;
			for (const file of EXT_FILES) {
				vm.runInContext(readFileSync(join(EXT_DIR, file), 'utf8'), ctx, { filename: file });
			}
			return ctx;
		};

		/** The extension's parse, as plain data or the refusal message. */
		function theirParse(ext, data) {
			try {
				return { ok: true, set: plain(ext.anonIdFile.parse(plain(data)).set) };
			} catch (e) {
				return { ok: false, message: e.message };
			}
		}

		function ourParse(data) {
			try {
				return { ok: true, parsed: parsePlaceholderMap(plain(data)) };
			} catch (e) {
				assert.ok(e instanceof PlaceholderMapError, String(e));
				return { ok: false, message: e.message };
			}
		}

		/** Same decision, same first sentence, same set; our table = their reveal table. */
		function assertSameParse(ext, data) {
			const theirs = theirParse(ext, data);
			const ours = ourParse(data);
			const label = JSON.stringify(data);
			assert.equal(ours.ok, theirs.ok, `${label}\n${ours.message ?? theirs.message}`);
			if (!theirs.ok) {
				assert.ok(
					ours.message.startsWith(theirs.message),
					`${label}\n${ours.message}\n${theirs.message}`,
				);
				return theirs;
			}
			assert.deepEqual(plain(ours.parsed.set), theirs.set, label);
			const model = ext.anonIdModel;
			const reveal = plain(model.revealTable({ ...theirs.set, numbering: 'random' }));
			assert.deepEqual(plain(ours.parsed.table), reveal, label);
			assert.deepEqual(
				new Set(ours.parsed.mine),
				new Set(theirs.set.ids.filter((r) => r.main && r.mine).map((r) => r.key)),
				label,
			);
			assert.deepEqual(ours.parsed.used, theirs.set.used, label);
			assert.equal(ours.parsed.numbering, theirs.set.numbering, label);
			return theirs;
		}

		test('every fixture: same accept/reject decision, first sentence and set', () => {
			const ext = loadExt();
			const withoutUsed = validFile();
			delete withoutUsed.usedPlaceholders;
			const cases = [
				validFile(),
				withoutUsed,
				JSON.parse(E1_FILE),
				...V1_FORMAT_CASES.map(([, o]) => validFile(o)),
				...V1_FORMAT_CASES.map(([, o]) => v2(o)),
				...V2_ENTRIES_CASES.map(([, o]) => v2(o)),
				...V2_DUPLICATE_CASES.map(([, o]) => v2(o)),
				validFile({ numbering: 'redacted' }),
				validFile({ ids: [] }),
				validFile({ ids: [null] }),
				...[
					'PERSON_1',
					'[person_1]',
					'[1_PERSON]',
					'[PERSON 1]',
					'[PERSON-1]',
					'[]',
					'[CASE_1234567890]',
					'[CASE_123456789]',
				].map((placeholder) => validFile({ ids: [{ value: 'a', placeholder, addedByYou: true }] })),
				validFile({ ids: [{ value: '  ', placeholder: '[A_1]' }] }),
				validFile({ ids: [{ value: ' K101 ', placeholder: '[A_1]' }] }),
				validFile({ ids: [{ value: 5, placeholder: '[A_1]' }] }),
				validFile({ usedPlaceholders: 'x' }),
				validFile({ usedPlaceholders: [1] }),
				validFile({ usedPlaceholders: ['nope'] }),
				validFile({ usedPlaceholders: ['[CASE_99999999999999999999]'] }),
				validFile({
					ids: [
						{ value: 'a', placeholder: '[A_1]' },
						{ value: 'b', placeholder: '[A_1]' },
					],
				}),
				validFile({
					ids: [
						{ value: 'a', placeholder: '[A_1]' },
						{ value: ' a', placeholder: '[A_2]' },
					],
				}),
				validFile({
					ids: [
						{ value: 'Acme', placeholder: '[CLIENT]', addedByYou: true },
						{ value: 'Acme', placeholder: '[CLIENT_NAME]', addedByYou: true },
					],
				}),
				validFile({
					ids: [
						{ value: 'Ana B', placeholder: '[PERSON_x]' },
						{ value: 'Ana', placeholder: '[PERSON_x_NAME]' },
						{ value: 'Ana C', placeholder: '[PERSON_y]' },
						{ value: 'Ana', placeholder: '[PERSON_y_NAME]' },
					],
				}),
			];
			for (const data of cases) assertSameParse(ext, data);
		});

		test('400 generated files: same decisions and sets as the extension', () => {
			const ext = loadExt();
			let accepted = 0;
			for (const data of generatedFiles(400, 20261021)) {
				if (assertSameParse(ext, data).ok) accepted += 1;
			}
			assert.ok(accepted > 20, `only ${accepted} generated files were valid`);
		});

		test('we parse what the extension serializes (E1, a renamed person, redacted)', () => {
			const ext = loadExt();
			const states = [
				E1_SET,
				{
					ids: [
						rec('Luka Zupan', 'CLIENT', 'PERSON'),
						rec('Modra Vila d.o.o.', 'COMPANY_ab12c', 'COMPANY'),
						rec('Modra Vila', 'COMPANY_cd34e', 'COMPANY'),
					],
					subKeys: {
						CLIENT_NAME: { of: 'CLIENT', value: 'Luka', rec: 'Luka Zupan' },
						CLIENT_SURNAME: { of: 'CLIENT', value: 'Zupan', rec: 'Luka Zupan' },
					},
					aliases: {
						PERSON_qw4gf: { value: 'Luka Zupan', owner: 'CLIENT' },
						PERSON_qw4gf_NAME: { value: 'Luka', owner: 'CLIENT' },
					},
					used: ['PERSON_qw4gf', 'PERSON_qw4gf_NAME', 'CLIENT', 'COMPANY_ab12c'],
					numbering: 'sequential',
				},
				{
					ids: [rec('Acme', 'CUSTOM_ab1cd', 'CUSTOM', { mine: true })],
					used: [],
					numbering: 'redacted',
				},
			];
			for (const state of states) {
				const theirFile = plain(
					ext.anonIdFile.serialize({ ...ext.anonIdModel.empty(), ...state }, 'set.json'),
				);
				const theirs = assertSameParse(ext, theirFile);
				assert.equal(theirs.ok, true);
				// And our writer produces the same file for the same set.
				assert.deepEqual(plain(toIdFile(state, 'set.json')), theirFile);
			}
		});

		test('the extension loads what we write, and IdRules.validateSet accepts the set', () => {
			const ext = loadExt();
			const sets = [
				E1_SET,
				idSetFromTable(STATE.table, 'random', { mine: STATE.mine, used: STATE.used }),
				parsePlaceholderMap(validFile()).set,
				{
					ids: [rec('Acme', 'CUSTOM_ab1cd', 'CUSTOM', { mine: true })],
					used: [],
					numbering: 'typed',
				},
			];
			for (const set of sets) {
				const file = JSON.parse(JSON.stringify(toIdFile(set, 'ours.json')));
				const { set: loaded } = ext.anonIdFile.parse(file);
				assert.equal(ext.IdRules.validateSet(loaded), true);
				assert.deepEqual(
					plain(loaded),
					plain({
						subKeys: {},
						aliases: {},
						...set,
						used: file.usedPlaceholders.map((p) => p.slice(1, -1)),
					}),
				);
				assert.deepEqual(plain(ext.anonIdFile.serialize(loaded, 'ours.json')), file);
			}
		});

		test('toIdFile refuses exactly the sets the extension refuses', () => {
			const ext = loadExt();
			const rnd = prng(7);
			const pick = (list) => list[Math.floor(rnd() * list.length)];
			let refused = 0;
			let written = 0;
			for (let n = 0; n < 400; n++) {
				const set = plain(E1_SET);
				const mutation = Math.floor(rnd() * 10);
				if (mutation === 0) set.ids[pick([0, 1, 2])].main = rnd() < 0.5;
				if (mutation === 1) set.ids[pick([0, 1, 2])].type = pick(['PERSON', 'COMPANY', 'x']);
				if (mutation === 2)
					set.ids[pick([0, 1, 2])].value = pick(['Luka Zupan', ' Ana', 'Ana', '']);
				if (mutation === 3)
					set.subKeys.PERSON_a7k2q_NAME.rec = pick(['Luka Zupan', 'Mr. Zupan', 'Nobody']);
				if (mutation === 4)
					set.subKeys.PERSON_a7k2q_NAME.of = pick(['PERSON_a7k2q', 'COMPANY_x7gs2', 'NOPE']);
				if (mutation === 5)
					set.aliases[pick(['CUSTOM_h3k9d', 'PERSON_a7k2q_NAME', 'COMPANY_x7gs2', 'Z_1'])] = {
						value: 'v',
						owner: pick(['PERSON_a7k2q', 'NOPE']),
					};
				if (mutation === 6) set.numbering = pick(['typed', 'redacted', 'sequential', 'nope']);
				if (mutation === 7) set.used.push(pick(['OK_1', 'bad', 'A_12345678901']));
				if (mutation === 8)
					set.ids[pick([0, 1, 2])].key = pick(['PERSON_a7k2q', 'COMPANY_x7gs2', 'NEW_1', 'bad']);
				if (mutation === 9) set.ids = set.ids.slice(pick([0, 2, 3]));
				let theirsOk = ext.IdRules.validateSet(plain(set));
				if (theirsOk) {
					try {
						ext.anonIdFile.parse(plain(ext.anonIdFile.serialize(plain(set), 'x.json')));
					} catch {
						theirsOk = false;
					}
				}
				let oursOk = true;
				try {
					toIdFile(set, 'x.json');
				} catch (e) {
					assert.ok(e instanceof PlaceholderMapError, String(e));
					oursOk = false;
				}
				assert.equal(oursOk, theirsOk, JSON.stringify(set));
				if (oursOk) written += 1;
				else refused += 1;
			}
			assert.ok(refused > 20 && written > 20, `${refused} refused, ${written} written`);
		});

		test('sequential numbering continues past tombstones like the extension', () => {
			const ext = loadExt();
			const file = toIdFile(
				idSetFromTable({ PERSON_1: 'Ana Kovač', CASE_1: 'K101' }, 'sequential', {
					used: ['PERSON_3'],
				}),
				'case',
			);
			const { set } = ext.anonIdFile.parse(plain(file));
			const state = { ...ext.anonIdModel.empty(), ...set };
			const theirs = ext.IdRules.nextKey(state, 'PERSON');
			const ours = protectText(
				'Bob',
				[{ entity_type: 'PERSON', start: 0, end: 3 }],
				parsePlaceholderMap(file),
				'sequential',
			);
			assert.equal(theirs, 'PERSON_4');
			assert.equal(ours.text, `[${theirs}]`);
		});
	},
);
