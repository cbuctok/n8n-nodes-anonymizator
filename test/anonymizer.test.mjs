// Port of the extension's tests/anonymizer.test.js (and the pure IdSet cases) against the built
// dist/, plus a differential check against the extension's own lib/anonymizer.js. Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

const require = createRequire(import.meta.url);
const nodeCrypto = require('node:crypto');
const {
	KEY_RE,
	MAX_SUFFIX_DIGITS,
	REDACTED,
	isValidKey,
	splitPersonName,
	pgwCountersFromTable,
	pgwSpansFromTable,
	anonymizeFromSpans,
	mask,
	protectText,
	revealText,
	listPlaceholders,
	randomSuffix,
} = require('../dist/nodes/Anonymizator/shared/anonymizer.js');

const EXT_DIR =
	process.env.ANON_EXT_DIR ??
	'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext';
const hasExt = existsSync(join(EXT_DIR, 'lib/anonymizer.js'));

const span = (entity_type, start, end, score = 0.85) => ({ entity_type, start, end, score });
const seq = { sequential: true };
const plain = (x) => JSON.parse(JSON.stringify(x));

describe('anonymizeFromSpans', () => {
	test('splices placeholders by range with exact output offsets', () => {
		const res = anonymizeFromSpans('Hello John Smith', [span('PERSON', 6, 16)], {}, seq);
		assert.equal(res.text, 'Hello [PERSON_1]');
		assert.deepEqual(res.entities, [
			{ entity_type: 'PERSON', replacement: '[PERSON_1]', start: 6, end: 16, score: 0.85 },
		]);
		assert.equal(res.newEntries.PERSON_1, 'John Smith');
	});

	test('handles multiple spans of different types in one pass', () => {
		const res = anonymizeFromSpans(
			'Call John Smith at john@example.com now',
			[span('PERSON', 5, 15), span('EMAIL_ADDRESS', 19, 35)],
			{},
			seq,
		);
		assert.equal(res.text, 'Call [PERSON_1] at [EMAIL_ADDRESS_1] now');
		for (const e of res.entities) assert.equal(res.text.slice(e.start, e.end), e.replacement);
	});

	test('reuses the existing key for an already-mapped value (no new entry)', () => {
		const res = anonymizeFromSpans('Hi John Smith', [span('PERSON', 3, 13)], {
			PERSON_1: 'John Smith',
		});
		assert.equal(res.text, 'Hi [PERSON_1]');
		assert.deepEqual(res.newEntries, {});
	});

	test('sequential numbering continues from an existing map', () => {
		const table = { PERSON_2: 'Somebody Else', PERSON_2_NAME: 'Somebody' };
		const res = anonymizeFromSpans('Meet Ana Kovač', [span('PERSON', 5, 14)], table, seq);
		assert.equal(res.text, 'Meet [PERSON_3]');
		assert.equal(res.newEntries.PERSON_3, 'Ana Kovač');
		const res2 = anonymizeFromSpans(
			'Mail ana.kovac@example.com',
			[span('EMAIL_ADDRESS', 5, 26)],
			{ EMAIL_ADDRESS_7: 'x@example.com', PERSON_1: 'Janez Novak' },
			seq,
		);
		assert.equal(res2.text, 'Mail [EMAIL_ADDRESS_8]');
	});

	test('same value twice in one text gives the same placeholder, minted once', () => {
		const res = anonymizeFromSpans(
			'John Smith met John Smith',
			[span('PERSON', 0, 10), span('PERSON', 15, 25)],
			{},
			seq,
		);
		assert.equal(res.text, '[PERSON_1] met [PERSON_1]');
		assert.deepEqual(
			Object.keys(res.newEntries).filter((k) => /^PERSON_\d+$/.test(k)),
			['PERSON_1'],
		);
	});

	test('a re-detected first name reuses the NAME sub-key', () => {
		const table = { PERSON_1: 'John Smith', PERSON_1_NAME: 'John', PERSON_1_SURNAME: 'Smith' };
		const res = anonymizeFromSpans('Ask John about it', [span('PERSON', 4, 8)], table);
		assert.equal(res.text, 'Ask [PERSON_1_NAME] about it');
		assert.deepEqual(res.newEntries, {});
	});

	test('trims whitespace out of sloppy spans and adjusts offsets', () => {
		const res = anonymizeFromSpans('Hi  John Smith  ok', [span('PERSON', 2, 16)], {}, seq);
		assert.equal(res.text, 'Hi  [PERSON_1]  ok');
		assert.equal(res.newEntries.PERSON_1, 'John Smith');
		assert.deepEqual(res.entities[0], {
			entity_type: 'PERSON',
			replacement: '[PERSON_1]',
			start: 4,
			end: 14,
			score: 0.85,
		});
		// A whitespace-only span is dropped entirely.
		const res2 = anonymizeFromSpans('a   b', [span('PERSON', 1, 4)], {}, seq);
		assert.equal(res2.text, 'a   b');
		assert.deepEqual(res2.entities, []);
	});

	test('skips overlapping, empty, reversed and out-of-bounds spans defensively', () => {
		const res = anonymizeFromSpans(
			'John Smith here',
			[
				span('PERSON', 0, 10),
				span('URL', 5, 12),
				span('PERSON', 90, 95),
				span('PERSON', 11, 11),
				span('PERSON', 14, 12),
				span('PERSON', 11, 16),
			],
			{},
			seq,
		);
		assert.equal(res.text, '[PERSON_1] here');
		assert.equal(res.entities.length, 1);
	});

	test('does not mutate the input table', () => {
		const table = { PERSON_1: 'A B' };
		anonymizeFromSpans('New Guy', [span('PERSON', 0, 7)], table);
		assert.deepEqual(table, { PERSON_1: 'A B' });
	});

	test('score is rounded to two decimals, missing score gives 0', () => {
		const res = anonymizeFromSpans(
			'Ana and Bob',
			[span('PERSON', 0, 3, 0.8567), { entity_type: 'PERSON', start: 8, end: 11 }],
			{},
			seq,
		);
		assert.deepEqual(
			res.entities.map((e) => e.score),
			[0.86, 0],
		);
	});

	test('text that names an Object.prototype member is still minted', () => {
		const res = anonymizeFromSpans('see constructor', [span('CUSTOM', 4, 15)], {}, seq);
		assert.equal(res.text, 'see [CUSTOM_1]');
		assert.equal(res.newEntries.CUSTOM_1, 'constructor');
	});

	test('emoji before an entity: offsets stay UTF-16', () => {
		const text = '😀 Janez Novak';
		const res = anonymizeFromSpans(text, [span('PERSON', 3, 14)], {}, seq);
		assert.equal(res.text, '😀 [PERSON_1]');
		assert.equal(revealText(res.text, res.newEntries), text);
	});

	describe('custom mapping terms (table-driven spans)', () => {
		test('substitutes a mapped value the analyzer did not detect', () => {
			const res = anonymizeFromSpans('Plača gre na IBAN. Hvala!', [], { GREETING_1: 'Hvala' });
			assert.equal(res.text, 'Plača gre na IBAN. [GREETING_1]!');
			assert.deepEqual(res.newEntries, {});
		});

		test('substitutes concrete numbers, escaping regex specials', () => {
			const res = anonymizeFromSpans('Call +386 41 234 567 today', [], {
				PHONE_NUMBER_1: '+386 41 234 567',
			});
			assert.equal(res.text, 'Call [PHONE_NUMBER_1] today');
		});

		test('replaces every occurrence with the same key', () => {
			const res = anonymizeFromSpans('Orion ships when Orion is ready', [], { PROJECT_1: 'Orion' });
			assert.equal(res.text, '[PROJECT_1] ships when [PROJECT_1] is ready');
		});

		test('is word-bounded on Unicode letters: Ana vs Banana, Anače', () => {
			const res = anonymizeFromSpans('Banana for Ana, not Anače', [], { PERSON_1_NAME: 'Ana' });
			assert.equal(res.text, 'Banana for [PERSON_1_NAME], not Anače');
		});

		test('č/š/ž values match whole words only', () => {
			const table = { PERSON_1_SURNAME: 'Kovač', CITY_1: 'Šiška', X_1: 'Žan' };
			const res = anonymizeFromSpans(
				'Kovač iz Šiške in Žan, ne Kovačič ali Žana. Šiška!',
				[],
				table,
			);
			assert.equal(
				res.text,
				'[PERSON_1_SURNAME] iz Šiške in [X_1], ne Kovačič ali Žana. [CITY_1]!',
			);
		});

		test('an earlier-starting analyzer span wins over an inner table match', () => {
			const res = anonymizeFromSpans(
				'Janez Novak here',
				[span('PERSON', 0, 11)],
				{ SURNAME_1: 'Novak' },
				seq,
			);
			assert.equal(res.text, '[PERSON_1] here');
			assert.equal(res.newEntries.PERSON_1, 'Janez Novak');
		});

		test('on equal start the longer span wins', () => {
			const res = anonymizeFromSpans('John Smith', [span('PERSON', 0, 10)], { X_1: 'John' }, seq);
			assert.equal(res.text, '[PERSON_1]');
		});

		test('a padded table value still resolves to its key by the trimmed form', () => {
			const res = anonymizeFromSpans('Hi Janez Novak', [span('PERSON', 3, 14)], {
				PERSON_1: ' Janez Novak ',
			});
			assert.equal(res.text, 'Hi [PERSON_1]');
			assert.deepEqual(res.newEntries, {});
		});

		test('table-driven substitution round-trips through revealText', () => {
			const table = { GREETING_1: 'Hvala', PROJECT_1: 'Orion' };
			const text = 'Orion done. Hvala!';
			assert.equal(revealText(anonymizeFromSpans(text, [], table).text, table), text);
		});
	});
});

describe('pgwSpansFromTable', () => {
	test('derives the entity type from the key, CUSTOM otherwise', () => {
		assert.deepEqual(
			pgwSpansFromTable('Ana and Hvala', { PERSON_3_NAME: 'Ana', greeting: 'Hvala' }),
			[
				{ entity_type: 'PERSON', start: 0, end: 3, score: 1 },
				{ entity_type: 'CUSTOM', start: 8, end: 13, score: 1 },
			],
		);
	});

	test('skips empty or whitespace-only values (tombstones)', () => {
		assert.deepEqual(pgwSpansFromTable('anything', { A_1: '', B_1: '  ' }), []);
	});

	test('derives the type from a random-suffix key too', () => {
		assert.deepEqual(pgwSpansFromTable('Ana', { PERSON_a7k2q_NAME: 'Ana' }), [
			{ entity_type: 'PERSON', start: 0, end: 3, score: 1 },
		]);
	});
});

describe('PERSON sub-placeholders', () => {
	test('mints NAME and SURNAME for a two-token name', () => {
		const res = anonymizeFromSpans('John Smith', [span('PERSON', 0, 10)], {}, seq);
		assert.deepEqual(res.newEntries, {
			PERSON_1: 'John Smith',
			PERSON_1_NAME: 'John',
			PERSON_1_SURNAME: 'Smith',
		});
	});

	test('keeps SI/HR double surnames and DE particles intact', () => {
		const a = anonymizeFromSpans('Ana Kovač Horvat', [span('PERSON', 0, 16)], {}, seq);
		assert.equal(a.newEntries.PERSON_1_NAME, 'Ana');
		assert.equal(a.newEntries.PERSON_1_SURNAME, 'Kovač Horvat');
		const g = anonymizeFromSpans('Johann von Goethe', [span('PERSON', 0, 17)], {}, seq);
		assert.equal(g.newEntries.PERSON_1_SURNAME, 'von Goethe');
	});

	test('strips regional titles before splitting', () => {
		for (const [full, given, surname] of [
			['Herr Max Müller', 'Max', 'Müller'],
			['gospa Ana Novak', 'Ana', 'Novak'],
			['Dr. Ivana Horvat-Kovač', 'Ivana', 'Horvat-Kovač'],
			['g. Janez Novak', 'Janez', 'Novak'],
		]) {
			const res = anonymizeFromSpans(full, [span('PERSON', 0, full.length)], {}, seq);
			assert.equal(res.newEntries.PERSON_1_NAME, given, full);
			assert.equal(res.newEntries.PERSON_1_SURNAME, surname, full);
		}
	});

	test('no sub-keys for a single-token name; never overwrites an existing sub-key', () => {
		const res = anonymizeFromSpans('Madonna', [span('PERSON', 0, 7)], {}, seq);
		assert.deepEqual(res.newEntries, { PERSON_1: 'Madonna' });
		// PERSON_1_NAME already taken by an unrelated entry: it is kept, only SURNAME is added.
		const res2 = anonymizeFromSpans(
			'Janez Novak',
			[span('PERSON', 0, 11)],
			{ PERSON_1_NAME: 'Other' },
			seq,
		);
		assert.deepEqual(res2.newEntries, { PERSON_1: 'Janez Novak', PERSON_1_SURNAME: 'Novak' });
	});

	test('sub-keys hang off random keys too', () => {
		const res = anonymizeFromSpans('Hello John Smith', [span('PERSON', 6, 16)], {});
		assert.match(res.text, /^Hello \[PERSON_[a-z0-9]{5}\]$/);
		const key = Object.keys(res.newEntries).find((k) => /^PERSON_[a-z0-9]{5}$/.test(k));
		assert.ok(key);
		assert.equal(res.newEntries[key], 'John Smith');
		assert.equal(res.newEntries[`${key}_NAME`], 'John');
		assert.equal(res.newEntries[`${key}_SURNAME`], 'Smith');
	});
});

describe('random placeholders (default mode)', () => {
	test('a fresh random key for a new value even when numbered keys exist', () => {
		const res = anonymizeFromSpans('Meet Ana Kovač', [span('PERSON', 5, 14)], { PERSON_2: 'X' });
		assert.match(res.text, /^Meet \[PERSON_[a-z0-9]{5}\]$/);
		assert.ok(!res.text.includes('[PERSON_3]'));
	});

	test('still reuses existing keys (random and numbered) without minting', () => {
		const table = { PERSON_1: 'John Smith', EMAIL_ADDRESS_a7k2q: 'j@x.com' };
		const res = anonymizeFromSpans(
			'John Smith j@x.com',
			[span('PERSON', 0, 10), span('EMAIL_ADDRESS', 11, 18)],
			table,
		);
		assert.equal(res.text, '[PERSON_1] [EMAIL_ADDRESS_a7k2q]');
		assert.deepEqual(res.newEntries, {});
	});

	test('randomSuffix: lowercase a-z0-9, requested length, varied', () => {
		const seen = new Set();
		for (let i = 0; i < 200; i++) {
			const s = randomSuffix();
			assert.match(s, /^[a-z0-9]{5}$/);
			seen.add(s);
		}
		assert.ok(seen.size > 190);
		assert.match(randomSuffix(12), /^[a-z0-9]{12}$/);
	});

	test('round-trips through revealText', () => {
		const text = 'Contact Ana Kovač at ana@primer.si';
		const res = anonymizeFromSpans(
			text,
			[span('PERSON', 8, 18), span('EMAIL_ADDRESS', 22, 35)],
			{},
		);
		assert.equal(revealText(res.text, res.newEntries), text);
	});
});

describe('revealText', () => {
	test('a map with hundreds of thousands of keys reveals in linear time', () => {
		// A regex alternation of this many keys made V8 abort the process (is_int26 check).
		const table = {};
		for (let i = 0; i < 300000; i++) {
			const key = `PERSON_${String(i).padStart(5, '0')}`;
			table[key] = `Name${i} Surname${i}`;
			table[`${key}_NAME`] = `Name${i}`;
			table[`${key}_SURNAME`] = `Surname${i}`;
		}
		const started = Date.now();
		assert.equal(
			revealText('Dear [PERSON_00001], PERSON_00002_NAME said hi to [PERSON_x]', table),
			'Dear Name1 Surname1, Name2 said hi to [PERSON_x]',
		);
		assert.ok(Date.now() - started < 1000);
	});

	test('replaces bracketed and bare placeholders', () => {
		const table = { PERSON_1: 'John Smith', EMAIL_ADDRESS_1: 'j@x.com' };
		assert.equal(
			revealText('Hi [PERSON_1], mail EMAIL_ADDRESS_1', table),
			'Hi John Smith, mail j@x.com',
		);
	});

	test('longest key wins (PERSON_1_NAME over PERSON_1), bracketed and bare', () => {
		const table = { PERSON_1: 'John Smith', PERSON_1_NAME: 'John', PERSON_1_SURNAME: 'Smith' };
		assert.equal(revealText('[PERSON_1_NAME] aka [PERSON_1]', table), 'John aka John Smith');
		assert.equal(
			revealText('PERSON_1_SURNAME, PERSON_1_NAME (PERSON_1)', table),
			'Smith, John (John Smith)',
		);
	});

	test('round-trips with anonymizeFromSpans', () => {
		const text = 'Contact Ana Kovač Horvat at ana@primer.si';
		const res = anonymizeFromSpans(
			text,
			[span('PERSON', 8, 24), span('EMAIL_ADDRESS', 28, 41)],
			{},
		);
		assert.equal(revealText(res.text, res.newEntries), text);
	});

	test('no table: text unchanged; unknown placeholders left alone', () => {
		assert.equal(revealText('[PERSON_1]', {}), '[PERSON_1]');
		assert.equal(revealText('[PERSON_9]', { PERSON_1: 'X' }), '[PERSON_9]');
	});

	test('a $& in a value is inserted literally', () => {
		assert.equal(revealText('[A_1]', { A_1: 'price $& $1' }), 'price $& $1');
	});

	test('bare key inside a longer word is not replaced', () => {
		assert.equal(
			revealText('XPERSON_1 PERSON_1x PERSON_1', { PERSON_1: 'Ana' }),
			'XPERSON_1 PERSON_1x Ana',
		);
	});
});

describe('splitPersonName', () => {
	test('null for single tokens and empty input', () => {
		assert.equal(splitPersonName('Madonna'), null);
		assert.equal(splitPersonName(''), null);
		assert.equal(splitPersonName('Dr.'), null);
	});

	test('a dot-required title without the dot is a name', () => {
		assert.deepEqual(splitPersonName('Ga Novak'), { given: 'Ga', surname: 'Novak' });
		assert.deepEqual(splitPersonName('ga. Ana Novak'), { given: 'Ana', surname: 'Novak' });
	});

	test('a title alone with one name keeps the last token', () => {
		assert.equal(splitPersonName('Mr. Smith'), null);
	});
});

describe('pgwCountersFromTable', () => {
	test('max per type, sub-keys ignored', () => {
		assert.deepEqual(
			plain(
				pgwCountersFromTable({
					PERSON_2: 'a',
					PERSON_1: 'b',
					PERSON_2_NAME: 'c',
					EMAIL_ADDRESS_7: 'd',
					'not a key': 'e',
				}),
			),
			{ PERSON: 2, EMAIL_ADDRESS: 7 },
		);
	});

	test('suffixes longer than 9 digits are ignored (no endless minting)', () => {
		assert.deepEqual(
			plain(pgwCountersFromTable({ PERSON_99999999999999999999: 'x', PERSON_4: 'y' })),
			{
				PERSON: 4,
			},
		);
		const res = anonymizeFromSpans(
			'Bob',
			[span('PERSON', 0, 3)],
			{ PERSON_99999999999999999999: 'x' },
			seq,
		);
		assert.equal(res.text, '[PERSON_1]');
	});

	test('a spent 9-digit counter falls back to a random suffix', () => {
		const res = anonymizeFromSpans('Bob', [span('PERSON', 0, 3)], { PERSON_999999999: 'x' }, seq);
		assert.match(res.text, /^\[PERSON_[a-z0-9]{5}\]$/);
		assert.ok(Object.keys(res.newEntries).every(isValidKey));
	});
});

describe('isValidKey', () => {
	test('KEY_RE shape and at most 9 suffix digits', () => {
		assert.equal(MAX_SUFFIX_DIGITS, 9);
		assert.ok(KEY_RE.test('PERSON_a7k2q'));
		for (const ok of ['PERSON_1', 'PERSON_a7k2q_NAME', 'CLIENT', 'Client_id', 'CUSTOM_999999999']) {
			assert.equal(isValidKey(ok), true, ok);
		}
		for (const bad of [
			'CUSTOM_1234567890',
			'CUSTOM_100000000000000000000',
			'1CASE',
			'person_1',
			'PERSON 1',
			'PERSON-1',
			'[PERSON_1]',
			'',
			'__proto__',
			42,
			null,
		]) {
			assert.equal(isValidKey(bad), false, String(bad));
		}
	});
});

describe('mask and protectText (pure IdSet.anonymize)', () => {
	const spansFor = (text, pairs) => {
		const out = [];
		for (const [value, type] of pairs) {
			let i = text.indexOf(value);
			while (i !== -1) {
				out.push({ entity_type: type, start: i, end: i + value.length, score: 0.9 });
				i = text.indexOf(value, i + value.length);
			}
		}
		return out.sort((a, b) => a.start - b.start);
	};

	test('sequential: mints table entries in order, incl. PERSON sub-keys', () => {
		const text = 'Ana Novak met Bob';
		const res = protectText(
			text,
			spansFor(text, [
				['Ana Novak', 'PERSON'],
				['Bob', 'PERSON'],
			]),
			{ table: {} },
			'sequential',
		);
		assert.equal(res.text, '[PERSON_1] met [PERSON_2]');
		assert.deepEqual(res.newEntries, {
			PERSON_1: 'Ana Novak',
			PERSON_1_NAME: 'Ana',
			PERSON_1_SURNAME: 'Novak',
			PERSON_2: 'Bob',
		});
		assert.deepEqual(Object.keys(res.newEntries), [
			'PERSON_1',
			'PERSON_1_NAME',
			'PERSON_1_SURNAME',
			'PERSON_2',
		]);
	});

	test('tombstones: a removed number is never reused and never written', () => {
		const res = protectText(
			'Cene',
			[span('PERSON', 0, 4)],
			{ table: { PERSON_1: 'Ana' }, used: ['PERSON_1', 'PERSON_2'] },
			'sequential',
		);
		assert.equal(res.text, '[PERSON_3]');
		assert.deepEqual(res.newEntries, { PERSON_3: 'Cene' });
		const low = protectText(
			'Cene',
			[span('PERSON', 0, 4)],
			{ table: { PERSON_2: 'Bob' }, used: ['PERSON_1', 'PERSON_2'] },
			'sequential',
		);
		assert.equal(low.text, '[PERSON_3]');
	});

	test('random mode re-draws a suffix that is already a table key or tombstone', (t) => {
		// The compiled module calls randomInt through the shared node:crypto object, so mocking
		// the method there controls the suffixes: 'aaaaa', then 'bbbbb', then 'ccccc'.
		let draws = [...Array(5).fill(0), ...Array(5).fill(1), ...Array(5).fill(2)];
		t.mock.method(nodeCrypto, 'randomInt', () => draws.shift());
		const res = protectText(
			'Ana',
			[span('PERSON', 0, 3)],
			{ table: { PERSON_aaaaa: 'Bob' }, used: ['PERSON_aaaaa'] },
			'random',
		);
		assert.equal(res.text, '[PERSON_bbbbb]');
		assert.equal(res.newEntries.PERSON_bbbbb, 'Ana');
		assert.equal(res.newEntries.PERSON_aaaaa, undefined);

		draws = [...Array(5).fill(0), ...Array(5).fill(1), ...Array(5).fill(2)];
		const tomb = protectText(
			'Ana',
			[span('PERSON', 0, 3)],
			{ table: {}, used: ['PERSON_aaaaa'] },
			'random',
		);
		assert.equal(tomb.text, '[PERSON_bbbbb]');
	});

	test('random mode re-draws a suffix minted earlier in the same call', (t) => {
		let draws = [...Array(5).fill(0), ...Array(5).fill(0), ...Array(5).fill(1)];
		t.mock.method(nodeCrypto, 'randomInt', () => draws.shift());
		const res = protectText(
			'Ana Bob',
			[span('EMAIL_ADDRESS', 0, 3), span('EMAIL_ADDRESS', 4, 7)],
			{ table: {} },
			'random',
		);
		assert.equal(res.text, '[EMAIL_ADDRESS_aaaaa] [EMAIL_ADDRESS_bbbbb]');
		assert.deepEqual(plain(res.newEntries), {
			EMAIL_ADDRESS_aaaaa: 'Ana',
			EMAIL_ADDRESS_bbbbb: 'Bob',
		});
		draws = [];
	});

	test('typed: every ID becomes its type, user IDs included, nothing minted', () => {
		const text = 'Ana called 041 555 111; Ana again.';
		const res = protectText(
			text,
			spansFor(text, [
				['Ana', 'PERSON'],
				['041 555 111', 'PHONE_NUMBER'],
			]),
			{ table: {} },
			'typed',
		);
		assert.equal(res.text, '[PERSON] called [PHONE_NUMBER]; [PERSON] again.');
		for (const e of res.entities)
			assert.equal(res.text.slice(e.start, e.end), `[${e.entity_type}]`);
		assert.deepEqual(res.newEntries, {});
		assert.equal(
			protectText('Acme hired Bob.', [], { table: { CLIENT_a7k2q: 'Acme' } }, 'typed').text,
			'[CLIENT] hired Bob.',
		);
		// A user key without the TYPE_suffix shape reports as CUSTOM.
		assert.equal(
			protectText('Acme hired Bob.', [], { table: { CLIENT: 'Acme' } }, 'typed').text,
			'[CUSTOM] hired Bob.',
		);
	});

	test('redacted: every ID becomes [REDACTED] with exact offsets', () => {
		const text = 'Ana wrote to Bob; Ana again at ana@x.si.';
		const res = protectText(
			text,
			spansFor(text, [
				['Ana', 'PERSON'],
				['Bob', 'PERSON'],
				['ana@x.si', 'EMAIL_ADDRESS'],
			]),
			{ table: {} },
			'redacted',
		);
		assert.equal(res.text, '[REDACTED] wrote to [REDACTED]; [REDACTED] again at [REDACTED].');
		assert.deepEqual(
			res.entities.map((e) => e.entity_type),
			['PERSON', 'PERSON', 'PERSON', 'EMAIL_ADDRESS'],
		);
		for (const e of res.entities) {
			assert.equal(e.replacement, REDACTED);
			assert.equal(res.text.slice(e.start, e.end), REDACTED);
		}
		assert.deepEqual(res.newEntries, {});
		assert.equal(
			protectText('Acme hired Ana.', [], { table: { CLIENT: 'Acme' } }, 'redacted').text,
			'[REDACTED] hired Ana.',
		);
	});

	test('mask on an empty entity list returns the text unchanged', () => {
		assert.deepEqual(mask({ text: 'abc', entities: [] }, 'typed'), { text: 'abc', entities: [] });
	});
});

test('listPlaceholders: distinct bracketed tokens in order', () => {
	assert.deepEqual(listPlaceholders('[B_1] x [A_a7k2q] [B_1] [lower] [REDACTED] [1X]'), [
		'[B_1]',
		'[A_a7k2q]',
		'[REDACTED]',
	]);
	assert.deepEqual(listPlaceholders('none'), []);
});

describe(
	'parity with the extension lib/anonymizer.js',
	{ skip: !hasExt && 'extension checkout not found' },
	() => {
		const loadExt = () => {
			const ctx = vm.createContext({ crypto: webcrypto });
			ctx.self = ctx;
			vm.runInContext(readFileSync(join(EXT_DIR, 'lib/anonymizer.js'), 'utf8'), ctx);
			return ctx;
		};

		test('sequential mode: identical text, entities and newEntries on generated cases', () => {
			const ext = loadExt();
			const words = [
				'Janez Novak',
				'Ana',
				'Kovač',
				'ana.kovac@example.com',
				'Dr. Ivana Horvat',
				'😀',
				'Banana',
				'Šiška',
				'g. Janez Novak',
				'SI56 1910 0000 0123 438',
			];
			const types = ['PERSON', 'EMAIL_ADDRESS', 'IBAN_CODE', 'LOCATION'];
			let state = 12345;
			const rnd = (n) => {
				state = (state * 1103515245 + 12345) % 2147483648;
				return state % n;
			};
			for (let round = 0; round < 400; round++) {
				const tokens = [];
				for (let i = 0; i < 2 + rnd(6); i++) tokens.push(words[rnd(words.length)]);
				const text = tokens.join(rnd(2) ? ' ' : ', ');
				const spans = [];
				let pos = 0;
				for (const t of tokens) {
					const at = text.indexOf(t, pos);
					if (rnd(3))
						spans.push({
							entity_type: types[rnd(types.length)],
							start: at - rnd(2),
							end: at + t.length + rnd(2),
							score: rnd(100) / 97,
						});
					pos = at + t.length;
				}
				if (rnd(4) === 0)
					spans.push({ entity_type: 'PERSON', start: rnd(text.length), end: rnd(text.length + 5) });
				const table = {};
				if (rnd(2)) table.PERSON_2 = 'Ana';
				if (rnd(2)) table.PERSON_2_NAME = 'Janez';
				if (rnd(3) === 0) table.CITY_1 = 'Šiška';
				if (rnd(3) === 0) table.X_4 = '';
				const mine = anonymizeFromSpans(text, spans, table, seq);
				const theirs = ext.anonymizeFromSpans(text, plain(spans), plain(table), {
					sequential: true,
				});
				assert.deepEqual(plain(mine), plain(theirs), JSON.stringify({ text, spans, table }));
				assert.equal(
					revealText(mine.text, { ...table, ...mine.newEntries }),
					ext.revealText(mine.text, { ...table, ...mine.newEntries }),
				);
			}
		});

		test('splitPersonName and pgwSpansFromTable agree', () => {
			const ext = loadExt();
			for (const name of [
				'Herr Max Müller',
				'Ga Novak',
				'ga. Ana Novak',
				'Mr. Smith',
				'  a  b  c ',
				'Priv-Doz. Hans Weber',
				'Gđa Ana',
				'gđa. Ana Kovač',
			]) {
				assert.deepEqual(plain(splitPersonName(name)), plain(ext.splitPersonName(name)), name);
			}
			const table = { PERSON_3_NAME: 'Ana', greeting: 'Hvala', A_1: '', P_1: '(x)', S_1: 'Šiška' };
			const text = 'Ana, Banana, Hvala (x) Šiška Šiške';
			assert.deepEqual(
				plain(pgwSpansFromTable(text, table)),
				plain(ext.pgwSpansFromTable(text, table)),
			);
		});
	},
);
