// Placeholder map normaliser and ID file v1 (incl. interop with the extension's real
// sidepanel/sidepanel-idfile.js and lib/id-set.js load rules). Never shipped.
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
	defaultIdFileName,
	subKeyParent,
	ID_FILE_ERRORS,
} = pm;

const EXT_DIR =
	process.env.ANON_EXT_DIR ??
	'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext';
const hasExt = existsSync(join(EXT_DIR, 'sidepanel/sidepanel-idfile.js'));
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

describe('ID file input (port of tests/idfile.test.js parse cases)', () => {
	test('turns a valid file into table, mine, used and numbering', () => {
		assert.deepEqual(plain(parsePlaceholderMap(validFile())), {
			table: { PERSON_1: 'Luka Zupan', CASE_1: 'K101' },
			used: ['PERSON_1', 'CASE_1', 'PERSON_2'],
			mine: ['CASE_1'],
			numbering: 'sequential',
		});
		assert.deepEqual(plain(parsePlaceholderMap(JSON.stringify(validFile())).table), {
			PERSON_1: 'Luka Zupan',
			CASE_1: 'K101',
		});
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

	const formatCases = [
		['another format', { format: 'anonymizator-key' }, /"format" must be/],
		['another version', { version: 2 }, /Only version 1/],
		['unknown numbering', { numbering: 'shuffled' }, /"numbering" must be one of/],
		['ids not a list', { ids: {} }, /"ids" must be a list/],
	];
	for (const [label, overrides, re] of formatCases) {
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

	test('rejects duplicate placeholders and values; PERSON sub-keys may share', () => {
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
							{ value: 'a', placeholder: '[A_2]' },
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

describe('toIdFile', () => {
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

	test('writes v1 with bracketed placeholders, who added each ID and used placeholders', () => {
		const file = toIdFile(STATE.table, 'random', '20260930T081839-anonymizator-ids.json', {
			mine: STATE.mine,
			used: STATE.used,
		});
		assert.equal(file.format, 'anonymizator-id-file');
		assert.equal(file.version, 1);
		assert.equal(file.name, '20260930T081839-anonymizator-ids');
		assert.equal(file.numbering, 'random');
		assert.deepEqual(file.ids, [
			{ value: 'Ana Kovač Horvat', placeholder: '[PERSON_a7k2q]', addedByYou: false },
			{ value: 'Ana', placeholder: '[PERSON_a7k2q_NAME]', addedByYou: false },
			{ value: 'Kovač Horvat', placeholder: '[PERSON_a7k2q_SURNAME]', addedByYou: false },
			{ value: 'Modra Vila d.o.o.', placeholder: '[CLIENT_x9y8z]', addedByYou: true },
		]);
		assert.ok(file.usedPlaceholders.includes('[EMAIL_ADDRESS_q1w2e]'));
		assert.ok(!JSON.stringify(file).includes('luka@example.si'));
	});

	test('defaults: name from the current time, every key used', () => {
		const file = toIdFile({ A_1: 'a' }, 'sequential');
		assert.match(file.name, /^\d{8}T\d{6}-anonymizator-ids$/);
		assert.deepEqual(file.usedPlaceholders, ['[A_1]']);
		assert.equal(toIdFile({ A_1: 'a' }, 'bogus').numbering, 'random');
	});

	test('refuses what the extension would refuse', () => {
		throwsMap(() => toIdFile({}, 'random'), 'entries', /no placeholders to save/);
		throwsMap(() => toIdFile({ A_1: ' ' }, 'random'), 'entries', /"A_1" is missing or blank/);
		throwsMap(() => toIdFile({ a_1: 'x' }, 'random'), 'entries', /not a valid placeholder/);
		throwsMap(
			() => toIdFile({ A_1: 'x', A_2: 'x' }, 'random'),
			'duplicates',
			/"A_1" and "A_2" have the same value/,
		);
		throwsMap(
			() => toIdFile({ A_1: 'x' }, 'random', 'n', { used: ['A_12345678901'] }),
			'entries',
			/used placeholder/,
		);
	});

	test('round trip through our own parser', () => {
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

describe(
	'interop with the extension (real sidepanel-idfile.js and id-set.js)',
	{ skip: !hasExt && 'extension checkout not found' },
	() => {
		const loadExt = () => {
			const store = {};
			const ctx = vm.createContext({
				crypto: webcrypto,
				chrome: {
					storage: {
						session: {
							get: async (key) => (key in store ? { [key]: store[key] } : {}),
							set: async (obj) => Object.assign(store, JSON.parse(JSON.stringify(obj))),
						},
					},
				},
			});
			ctx.self = ctx;
			for (const file of ['lib/anonymizer.js', 'lib/id-set.js', 'sidepanel/sidepanel-idfile.js']) {
				vm.runInContext(readFileSync(join(EXT_DIR, file), 'utf8'), ctx, { filename: file });
			}
			return ctx;
		};

		/** What the extension's Load IDs does: parse(JSON.parse(text)) then IdSet.load. */
		async function extensionLoad(ext, file) {
			const { set } = ext.anonIdFile.parse(JSON.parse(JSON.stringify(file)));
			const idSet = new ext.IdSet();
			const res = await idSet.load(set, `${file.name}.json`);
			return { set: plain(set), res: plain(res) };
		}

		test('the extension loads our ID file of a protect run (random, PERSON sub-keys)', async () => {
			const ext = loadExt();
			const text =
				'Janez Novak (ana.kovac@example.com) pays to SI56 1910 0000 0123 438. Janez agrees.';
			const spans = [
				{ entity_type: 'PERSON', start: 0, end: 11, score: 0.9 },
				{ entity_type: 'EMAIL_ADDRESS', start: 13, end: 34, score: 1 },
				{ entity_type: 'IBAN_CODE', start: 44, end: 67, score: 1 },
			];
			const res = protectText(text, spans, { table: {} }, 'random');
			// Within one call only detected spans and the EXISTING map are substituted.
			assert.match(res.text, /\. Janez agrees\.$/);
			const again = protectText('Janez agrees.', [], { table: res.newEntries }, 'random');
			assert.match(again.text, /^\[PERSON_[a-z0-9]{5}_NAME\] agrees\.$/);
			const file = toIdFile(res.newEntries, 'random', 'n8n-run.json');
			const { set, res: loaded } = await extensionLoad(ext, file);
			assert.equal(loaded.ok, true, JSON.stringify(loaded));
			assert.deepEqual(set.table, plain(res.newEntries));
			assert.deepEqual(set.mine, []);
			assert.equal(set.numbering, 'random');
			assert.equal(loaded.state.fileName, 'n8n-run.json');
			assert.equal(ext.revealText(res.text, set.table), text);
			const key = Object.keys(res.newEntries).find((k) => /^PERSON_[a-z0-9]{5}$/.test(k));
			assert.ok(
				file.ids.some((e) => e.placeholder === `[${key}_SURNAME]` && e.addedByYou === false),
			);
		});

		test('the extension loads our sequential file with tombstones, two Anas and own IDs', async () => {
			const ext = loadExt();
			const table = {
				PERSON_1: 'Ana Kovač',
				PERSON_1_NAME: 'Ana',
				PERSON_1_SURNAME: 'Kovač',
				PERSON_3: 'Ana Novak',
				PERSON_3_NAME: 'Ana',
				PERSON_3_SURNAME: 'Novak',
				CASE_1: 'K101',
			};
			const file = toIdFile(table, 'sequential', 'case', { mine: ['CASE_1'], used: ['PERSON_2'] });
			const { set, res } = await extensionLoad(ext, file);
			assert.equal(res.ok, true, JSON.stringify(res));
			assert.deepEqual(set.table, table);
			assert.deepEqual(set.mine, ['CASE_1']);
			assert.deepEqual(new Set(set.used), new Set(['PERSON_2', ...Object.keys(table)]));
			assert.equal(set.numbering, 'sequential');
			// The extension continues numbering past the tombstone, as we do.
			const idSet = new ext.IdSet();
			await idSet.load(ext.anonIdFile.parse(plain(file)).set, 'case.json');
			const theirs = plain(
				await idSet.anonymize('Bob', [{ entity_type: 'PERSON', start: 0, end: 3 }]),
			);
			const ours = protectText(
				'Bob',
				[{ entity_type: 'PERSON', start: 0, end: 3 }],
				parsePlaceholderMap(file),
				'sequential',
			);
			assert.equal(theirs.text, '[PERSON_4]');
			assert.equal(ours.text, theirs.text);
		});

		test('we parse what the extension serializes (STATE fixture)', () => {
			const ext = loadExt();
			const file = JSON.parse(
				JSON.stringify(ext.anonIdFile.serialize(STATE, '20260930T081839-anonymizator-ids.json')),
			);
			const parsed = parsePlaceholderMap(JSON.stringify(file));
			assert.deepEqual(plain(parsed.table), STATE.table);
			assert.deepEqual(parsed.mine, STATE.mine);
			assert.deepEqual(new Set(parsed.used), new Set(STATE.used));
			assert.equal(parsed.numbering, 'random');
			// And our serializer writes the same file for the same state.
			assert.deepEqual(
				plain(toIdFile(STATE.table, 'random', '20260930T081839-anonymizator-ids.json', STATE)),
				file,
			);
		});

		test('accept/reject decisions match the extension parse() on every fixture', () => {
			const ext = loadExt();
			const withoutUsed = validFile();
			delete withoutUsed.usedPlaceholders;
			const cases = [
				validFile(),
				withoutUsed,
				validFile({ format: 'anonymizator-key' }),
				validFile({ version: 2 }),
				validFile({ numbering: 'shuffled' }),
				validFile({ numbering: 'redacted' }),
				validFile({ ids: {} }),
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
						{ value: 'a', placeholder: '[A_2]' },
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
						{ value: 'Ana', placeholder: '[PERSON_x]', addedByYou: true },
						{ value: 'Ana', placeholder: '[PERSON_x_NAME]', addedByYou: true },
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
			for (const data of cases) {
				let theirs;
				try {
					theirs = { ok: true, set: plain(ext.anonIdFile.parse(plain(data)).set) };
				} catch (e) {
					theirs = { ok: false, message: e.message };
				}
				let ours;
				try {
					const p = parsePlaceholderMap(data);
					ours = {
						ok: true,
						set: { table: plain(p.table), mine: p.mine, used: p.used, numbering: p.numbering },
					};
				} catch (e) {
					assert.ok(e instanceof PlaceholderMapError, String(e));
					ours = { ok: false, message: e.message };
				}
				const label = JSON.stringify(data);
				assert.equal(ours.ok, theirs.ok, label);
				if (theirs.ok) assert.deepEqual(ours.set, theirs.set, label);
				else
					assert.ok(
						ours.message.startsWith(theirs.message),
						`${label}\n${ours.message}\n${theirs.message}`,
					);
			}
		});
	},
);
