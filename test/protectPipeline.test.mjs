// The Protect pipeline (shared/protectPipeline.ts) against dist/: the pure cases of the
// extension's tests/id-set.test.js (anonymize, masked sets, own placeholders, reserved keys,
// Additionally protect) and tests/id-names.test.js (companies), plus a differential run of the
// whole pipeline against the extension's real anonIdEdits.anonymize (node:vm). Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { loadExt, plain, prng, SKIP_EXT, timed } from './engine-ext.mjs';

const require = createRequire(import.meta.url);
const P = require('../dist/nodes/Anonymizator/shared/protectPipeline.js');
const possibleModule = require('../dist/nodes/Anonymizator/shared/possible.js');
const { revealText } = require('../dist/nodes/Anonymizator/shared/anonymizer.js');

const rec = (value, key, type, extra = {}) => ({
	value,
	key,
	type,
	mine: false,
	main: true,
	...extra,
});

/** A set from partial fields; `used` always covers live keys, name parts and aliases. */
function seed(fields = {}, numbering = 'random') {
	const s = { ...P.emptyState(numbering), ...fields };
	s.used = [
		...new Set([
			...(fields.used || []),
			...s.ids.map((r) => r.key),
			...Object.keys(s.subKeys),
			...Object.keys(s.aliases),
		]),
	];
	return s;
}

/** Analyzer spans for every occurrence of each [value, type] pair in text. */
function spansFor(text, pairs) {
	const spans = [];
	for (const [value, type] of pairs) {
		for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + value.length)) {
			spans.push({ entity_type: type, start: at, end: at + value.length, score: 0.9 });
		}
	}
	return spans.sort((a, b) => a.start - b.start);
}

/** A span over the nth (0-based) occurrence of `value` in `text`. */
function at(text, value, type, nth = 0) {
	let index = -1;
	for (let i = 0; i <= nth; i++) index = text.indexOf(value, index + 1);
	if (index < 0) throw new Error(`${value} #${nth} not in text`);
	return { entity_type: type, start: index, end: index + value.length, score: 0.9 };
}

const run = (s, text, pairs, options) => P.protect(s, text, spansFor(text, pairs), options);
const byValue = (s, value) => s.ids.find((r) => r.value === value);
const valuesOf = (s) => s.ids.map((r) => [r.value, r.type, r.mine]);
const skipping = (...values) => ({ isSkipped: (v) => values.includes(v) });
const reveal = (out, s) => revealText(out.text, P.revealTable(s));

function expectExactOffsets(out) {
	for (const e of out.entities) assert.equal(out.text.slice(e.start, e.end), e.placeholder);
}

// E1 of the extension's contract: a group with name parts, an alias and a tombstone.
const E1 = () =>
	seed({
		ids: [
			rec('Luka Zupan', 'PERSON_a7k2q', 'PERSON'),
			rec('Mr. Zupan', 'PERSON_a7k2q', 'PERSON', { mine: true, main: false }),
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
			'CUSTOM_q1w2e',
		],
	});

describe('protect: records, prefixes, tombstones', () => {
	test('stores found IDs as records (newest first) with their name parts', () => {
		const s = P.emptyState('sequential');
		const out = run(s, 'Ana Novak met Bob', [
			['Ana Novak', 'PERSON'],
			['Bob', 'PERSON'],
		]);
		assert.equal(out.text, '[PERSON_1] met [PERSON_2]');
		assert.deepEqual(s.ids, [
			rec('Ana Novak', 'PERSON_1', 'PERSON'),
			rec('Bob', 'PERSON_2', 'PERSON'),
		]);
		assert.deepEqual(s.subKeys, {
			PERSON_1_NAME: { of: 'PERSON_1', value: 'Ana', rec: 'Ana Novak' },
			PERSON_1_SURNAME: { of: 'PERSON_1', value: 'Novak', rec: 'Ana Novak' },
		});
		assert.deepEqual(s.used, ['PERSON_1', 'PERSON_1_NAME', 'PERSON_1_SURNAME', 'PERSON_2']);
		assert.deepEqual(out.minted, ['PERSON_1', 'PERSON_1_NAME', 'PERSON_1_SURNAME', 'PERSON_2']);
		assert.deepEqual(
			out.entities.map((e) => [e.entityType, e.key, e.placeholder, e.value, e.score]),
			[
				['PERSON', 'PERSON_1', '[PERSON_1]', 'Ana Novak', 0.9],
				['PERSON', 'PERSON_2', '[PERSON_2]', 'Bob', 0.9],
			],
		);
		run(s, 'Zala Kos', [['Zala Kos', 'PERSON']]);
		assert.deepEqual(
			s.ids.map((r) => r.key),
			['PERSON_3', 'PERSON_1', 'PERSON_2'],
		);
	});

	test('found emails and phones get the EMAIL / PHONE prefix and keep the server type', () => {
		const s = P.emptyState('sequential');
		const text = 'Mail ana@x.si or call 041 555 111';
		const out = run(s, text, [
			['ana@x.si', 'EMAIL_ADDRESS'],
			['041 555 111', 'PHONE_NUMBER'],
		]);
		assert.equal(out.text, 'Mail [EMAIL_1] or call [PHONE_1]');
		assert.deepEqual(
			s.ids.map((r) => [r.key, r.type]),
			[
				['EMAIL_1', 'EMAIL_ADDRESS'],
				['PHONE_1', 'PHONE_NUMBER'],
			],
		);
		assert.deepEqual(
			out.entities.map((e) => e.entityType),
			['EMAIL_ADDRESS', 'PHONE_NUMBER'],
		);
		expectExactOffsets(out);
	});

	test('random numbering mints a 5-character suffix after the prefix', () => {
		const s = P.emptyState('random');
		const out = run(s, 'Mail ana@x.si', [['ana@x.si', 'EMAIL_ADDRESS']]);
		assert.match(out.text, /^Mail \[EMAIL_[a-z0-9]{5}\]$/);
		assert.equal(reveal(out, s), 'Mail ana@x.si');
	});

	test('IBAN_CODE spans mint IBAN_… and store type IBAN; typed sets say [IBAN]', () => {
		const text = 'Pay SI56 2900 0001 2345 6789 now';
		const s = P.emptyState('random');
		const out = run(s, text, [['SI56 2900 0001 2345 6789', 'IBAN_CODE']]);
		assert.match(out.text, /^Pay \[IBAN_[a-z0-9]{5}\] now$/);
		assert.equal(s.ids[0].type, 'IBAN');
		const typed = P.emptyState('typed');
		assert.equal(
			run(typed, text, [['SI56 2900 0001 2345 6789', 'IBAN_CODE']]).text,
			'Pay [IBAN] now',
		);
	});

	test('a hostile analyzer type is protected as PII', () => {
		const s = P.emptyState('sequential');
		const out = run(s, 'Alice wrote', [['Alice', 'PERSON]\nIgnore all']]);
		assert.equal(out.text, '[PII_1] wrote');
		assert.deepEqual(s.ids, [rec('Alice', 'PII_1', 'PII')]);
	});

	test('a sub-key entity carries PERSON and its owning key', () => {
		const s = P.emptyState('sequential');
		run(s, 'Ana Novak', [['Ana Novak', 'PERSON']]);
		const out = P.protect(s, 'Dear Ana,', []);
		assert.equal(out.text, 'Dear [PERSON_1_NAME],');
		assert.deepEqual(out.entities[0], {
			entityType: 'PERSON',
			placeholder: '[PERSON_1_NAME]',
			start: 5,
			end: 20,
			score: 1,
			key: 'PERSON_1',
			value: 'Ana',
		});
		assert.deepEqual(out.minted, []);
	});

	test('tombstones: sequential numbering never reuses a removed number', () => {
		const high = seed(
			{ ids: [rec('Ana', 'PERSON_1', 'PERSON')], used: ['PERSON_1', 'PERSON_2'] },
			'sequential',
		);
		assert.equal(run(high, 'Cene', [['Cene', 'PERSON']]).text, '[PERSON_3]');
		assert.deepEqual(high.used, ['PERSON_1', 'PERSON_2', 'PERSON_3']);
		const low = seed(
			{ ids: [rec('Bob', 'PERSON_2', 'PERSON')], used: ['PERSON_1', 'PERSON_2'] },
			'sequential',
		);
		assert.equal(run(low, 'Cene', [['Cene', 'PERSON']]).text, '[PERSON_3]');
	});

	test('sequential counters count aliases too', () => {
		const s = seed(
			{
				ids: [rec('K101', 'CASE_1', 'CUSTOM', { mine: true })],
				aliases: { CUSTOM_1: { value: 'K101', owner: 'CASE_1' } },
			},
			'sequential',
		);
		assert.equal(run(s, 'K102', [['K102', 'CUSTOM']]).text, '[CUSTOM_2]');
	});

	test('tombstones never match text', () => {
		const s = seed({ used: ['CASE_1'] }, 'sequential');
		const out = P.protect(s, 'nothing here', []);
		assert.equal(out.text, 'nothing here');
		assert.deepEqual(s.ids, []);
	});

	test('a skipped value stays clear and its key is never minted again', () => {
		const s = seed(
			{ ids: [rec('Bob', 'PERSON_2', 'PERSON')], used: ['PERSON_1', 'PERSON_2'] },
			'sequential',
		);
		const out = run(
			s,
			' Ana Novak and Bob and Cene',
			[
				['Ana Novak', 'PERSON'],
				['Bob', 'PERSON'],
				['Cene', 'PERSON'],
			],
			skipping('Ana Novak'),
		);
		assert.equal(out.text, ' Ana Novak and [PERSON_2] and [PERSON_3]');
	});

	test('skipped matching uses the trimmed span text', () => {
		const text = 'Hi Ana ';
		const out = P.protect(
			P.emptyState('sequential'),
			text,
			[{ entity_type: 'PERSON', start: 2, end: 7 }],
			skipping('Ana'),
		);
		assert.equal(out.text, text);
	});
});

describe('protect: groups (E1)', () => {
	test('protectTable: main records, synthetic member keys, name parts, then tombstones and aliases', () => {
		const table = P.protectTable(E1());
		assert.deepEqual(table, {
			PERSON_a7k2q: 'Luka Zupan',
			'~1': 'Mr. Zupan',
			PERSON_a7k2q_NAME: 'Luka',
			PERSON_a7k2q_SURNAME: 'Zupan',
			CUSTOM_h3k9d: '',
			CUSTOM_q1w2e: '',
		});
		assert.deepEqual(Object.keys(table), [
			'PERSON_a7k2q',
			'~1',
			'PERSON_a7k2q_NAME',
			'PERSON_a7k2q_SURNAME',
			'CUSTOM_h3k9d',
			'CUSTOM_q1w2e',
		]);
	});

	test('member values become the group key; nothing new is stored', () => {
		const s = E1();
		const text = 'Mr. Zupan called Luka Zupan.';
		const out = P.protect(s, text, [
			{ entity_type: 'PERSON', start: 0, end: 9, score: 0.9 },
			{ entity_type: 'PERSON', start: 17, end: 27, score: 0.9 },
		]);
		assert.equal(out.text, '[PERSON_a7k2q] called [PERSON_a7k2q].');
		assert.deepEqual(
			out.entities.map((e) => [e.placeholder, e.key, e.entityType, e.value]),
			[
				['[PERSON_a7k2q]', 'PERSON_a7k2q', 'PERSON', 'Mr. Zupan'],
				['[PERSON_a7k2q]', 'PERSON_a7k2q', 'PERSON', 'Luka Zupan'],
			],
		);
		expectExactOffsets(out);
		assert.deepEqual(out.minted, []);
		assert.deepEqual(s, E1());
		assert.equal(
			revealText('[PERSON_a7k2q] and [CUSTOM_h3k9d]', P.revealTable(s)),
			'Luka Zupan and Mr. Zupan',
		);
	});

	test('entities carry the original value: main, group member, name part and new IDs', () => {
		const s = E1();
		const text = 'Mr. Zupan called Luka Zupan. Luka and Ana Novak.';
		const out = run(s, text, [
			['Mr. Zupan', 'PERSON'],
			['Luka Zupan', 'PERSON'],
			['Ana Novak', 'PERSON'],
		]);
		const got = out.entities.map((e) => [e.placeholder, e.value]);
		assert.deepEqual(got.slice(0, 3), [
			['[PERSON_a7k2q]', 'Mr. Zupan'],
			['[PERSON_a7k2q]', 'Luka Zupan'],
			['[PERSON_a7k2q_NAME]', 'Luka'],
		]);
		assert.match(got[3][0], /^\[PERSON_[a-z0-9]{5}\]$/);
		assert.equal(got[3][1], 'Ana Novak');
	});
});

describe('protect: masked sets', () => {
	const text = 'Ana Novak signed for ACME d.o.o.';
	const spans = [{ entity_type: 'PERSON', start: 0, end: 9, score: 0.9 }];

	test('typed: labels by type, found IDs are stored with random internal keys', () => {
		const s = seed(
			{ ids: [rec('ACME d.o.o.', 'COMPANY_ab1cd', 'COMPANY', { mine: true })] },
			'typed',
		);
		const out = P.protect(s, text, spans);
		assert.equal(out.text, '[PERSON] signed for [COMPANY]');
		const found = byValue(s, 'Ana Novak');
		assert.deepEqual({ ...found, key: 'x' }, rec('Ana Novak', 'x', 'PERSON'));
		assert.match(found.key, /^PERSON_[a-z0-9]{5}$/);
		assert.deepEqual(Object.keys(s.subKeys), [`${found.key}_NAME`, `${found.key}_SURNAME`]);
		expectExactOffsets(out);
		assert.deepEqual(
			out.entities.map((e) => e.key),
			[found.key, 'COMPANY_ab1cd'],
		);
		assert.deepEqual(P.revealTable(s), {});
	});

	test('redacted: every ID is [REDACTED], with exact offsets', () => {
		const s = seed(
			{ ids: [rec('ACME d.o.o.', 'COMPANY_ab1cd', 'COMPANY', { mine: true })] },
			'redacted',
		);
		const out = P.protect(s, text, spans);
		assert.equal(out.text, '[REDACTED] signed for [REDACTED]');
		assert.deepEqual(
			out.entities.map((e) => e.entityType),
			['PERSON', 'COMPANY'],
		);
		expectExactOffsets(out);
		assert.equal(s.ids.length, 2);
	});

	test('typed: a name part keeps its own value under the [PERSON] label', () => {
		const s = P.emptyState('typed');
		run(s, 'Ana Novak signed.', [['Ana Novak', 'PERSON']]);
		const out = P.protect(s, 'Ana Novak signed. Ana agreed.', []);
		assert.equal(out.text, '[PERSON] signed. [PERSON] agreed.');
		assert.deepEqual(
			out.entities.map((e) => e.value),
			['Ana Novak', 'Ana'],
		);
	});

	test('typed: emails and phones show their prefix', () => {
		const s = P.emptyState('typed');
		const t = 'Mail ana@x.si or call 041 555 111';
		const out = run(s, t, [
			['ana@x.si', 'EMAIL_ADDRESS'],
			['041 555 111', 'PHONE_NUMBER'],
		]);
		assert.equal(out.text, 'Mail [EMAIL] or call [PHONE]');
	});
});

describe('protect: own placeholders are never re-protected', () => {
	const KEPT =
		'[PERSON_1] [PERSON_a7k2q] [PERSON_1_NAME] [IBAN_CODE_3] [PERSON] [REDACTED] [CLIENT]';

	for (const [mode, label] of [
		['random', '[NUMBER]'],
		['sequential', '[NUMBER]'],
		['typed', '[NUMBER]'],
		['redacted', '[REDACTED]'],
	]) {
		test(`${mode}: a value "1" leaves this set's placeholders intact, real data in brackets is protected`, () => {
			const s = P.fromFlatMap(
				{
					table: {
						PERSON_1: 'Ana Novak',
						PERSON_1_NAME: 'Ana',
						PERSON_a7k2q: 'Bo Kos',
						NUMBER: '1',
						CLIENT: 'Acme',
						TITLE: 'ZUPAN',
						CASE: 'K101',
					},
					mine: ['NUMBER', 'CLIENT', 'TITLE', 'CASE'],
					used: [
						'PERSON_1',
						'PERSON_1_NAME',
						'PERSON_a7k2q',
						'IBAN_CODE_3',
						'NUMBER',
						'CLIENT',
						'TITLE',
						'CASE',
					],
				},
				mode,
			);
			const text = `${KEPT} 1 [Luka] [ZUPAN] [K101] [1]`;
			const out = P.protect(s, text, spansFor(text, [['Luka', 'PERSON']]));
			if (mode === 'typed') {
				// A flat key "NUMBER" types as CUSTOM (no TYPE_suffix shape).
				assert.ok(out.text.startsWith(`${KEPT} [CUSTOM] [`), out.text);
			} else {
				assert.ok(out.text.startsWith(`${KEPT} ${label} [`), out.text);
			}
			for (const real of ['Luka', 'ZUPAN', 'K101', '[1]']) assert.ok(!out.text.includes(real));
			assert.doesNotMatch(out.text, /_\[/);
			expectExactOffsets(out);
		});
	}

	test('a value "1" never rewrites [PERSON_1]', () => {
		const s = seed({ ids: [rec('1', 'CUSTOM_1', 'CUSTOM', { mine: true })] }, 'sequential');
		assert.equal(P.protect(s, 'see [PERSON_1] and 1', []).text, 'see [PERSON_1] and [CUSTOM_1]');
	});

	test('an alias token and a sub-key token are left as they are', () => {
		const s = E1();
		s.ids = [
			rec('h3k9d', 'CUSTOM_zz1aa', 'CUSTOM', { mine: true }),
			rec('NAME', 'CUSTOM_zz2bb', 'CUSTOM', { mine: true }),
			...s.ids,
		];
		s.used.push('CUSTOM_zz1aa', 'CUSTOM_zz2bb');
		const out = P.protect(s, '[CUSTOM_h3k9d] [PERSON_a7k2q_NAME] h3k9d', []);
		assert.equal(out.text, '[CUSTOM_h3k9d] [PERSON_a7k2q_NAME] [CUSTOM_zz1aa]');
	});

	test('a token that only looks like a placeholder is still protected (empty set)', () => {
		const text =
			'Assign to [LOCATION_tokyo] and [PERSON_maria], IBAN [IBAN_SI56290000012345678], [NL_BSN_ab12c].';
		const out = run(P.emptyState('random'), text, [
			['tokyo', 'LOCATION'],
			['maria', 'PERSON'],
			['SI56290000012345678', 'IBAN'],
			['ab12c', 'PII'],
		]);
		for (const real of ['tokyo', 'maria', 'SI56290000012345678', 'ab12c']) {
			assert.ok(!out.text.includes(real), real);
		}
	});

	test('placeholders minted by another set are not rewritten (digit in the suffix)', () => {
		const s = seed({ ids: [rec('7', 'SEVEN', 'CUSTOM', { mine: true })] });
		const text = '[PERSON_7] and [PERSON_a7k2q] ([PERSON_a7k2q_NAME]) owe 7 [EMAIL_x7gs2]';
		assert.equal(
			P.protect(s, text, []).text,
			'[PERSON_7] and [PERSON_a7k2q] ([PERSON_a7k2q_NAME]) owe [SEVEN] [EMAIL_x7gs2]',
		);
	});

	test('[TYPE] and [REDACTED] count as own only in a masked set', () => {
		const text = 'see [PERSON] and [REDACTED]';
		const random = seed({ ids: [rec('PERSON', 'WORD', 'CUSTOM', { mine: true })] });
		assert.match(
			run(random, text, [['REDACTED', 'PII']]).text,
			/^see \[\[WORD\]\] and \[\[PII_[a-z0-9]{5}\]\]$/,
		);
		const typed = seed({ ids: [rec('PERSON', 'CUSTOM_ab1cd', 'CUSTOM', { mine: true })] }, 'typed');
		assert.equal(run(typed, text, [['REDACTED', 'PII']]).text, text);
	});

	test('re-protecting protected text changes nothing (sequential, value "1")', () => {
		const s = seed({ ids: [rec('1', 'NUMBER_1', 'NUMBER', { mine: true })] }, 'sequential');
		const first = run(s, 'Ana Novak has 1 cat', [['Ana Novak', 'PERSON']]);
		assert.equal(first.text, '[PERSON_1] has [NUMBER_1] cat');
		assert.equal(P.protect(s, first.text, []).text, first.text);
	});

	test('a removed (tombstoned) user key still counts as own', () => {
		const s = seed({ ids: [rec('7', 'SEVEN', 'CUSTOM', { mine: true })], used: ['CLIENT_7'] });
		assert.equal(P.protect(s, '[CLIENT_7] 7', []).text, '[CLIENT_7] [SEVEN]');
	});
});

describe('protect: a minted key is never one the text already spells', () => {
	for (const [name, text, protectedText] of [
		['bracketed', 'see [PERSON_1] and Ana', 'see [PERSON_1] and [PERSON_2]'],
		['bare', 'PERSON_1 in the log, Ana', 'PERSON_1 in the log, [PERSON_2]'],
		['a sub-key spelling', 'PERSON_1_NAME: Ana Novak', 'PERSON_1_NAME: [PERSON_1]'],
		['made a word by the splice', 'PERSON_1Ana', 'PERSON_1[PERSON_2]'],
	]) {
		test(name, () => {
			const s = P.emptyState('sequential');
			const value = text.includes('Ana Novak') ? 'Ana Novak' : 'Ana';
			const out = run(s, text, [[value, 'PERSON']]);
			assert.equal(out.text, protectedText);
			assert.equal(reveal(out, s), text);
		});
	}

	test('the reserved words are not stored in the set', () => {
		const s = P.emptyState('sequential');
		run(s, '[PERSON_1] Ana', [['Ana', 'PERSON']]);
		assert.equal(run(s, 'Bo', [['Bo', 'PERSON']]).text, '[PERSON_3]');
		assert.ok(!s.used.includes('PERSON_1'));
	});

	test('mintedInClear finds a minted key outside its placeholder only', () => {
		assert.deepEqual(
			P.mintedInClear({
				text: 'PERSON_1[PERSON_1] [PERSON_2]',
				entities: [
					{ start: 8, end: 18 },
					{ start: 19, end: 29 },
				],
				newEntries: { PERSON_1: 'a', PERSON_2: 'b' },
			}),
			['PERSON_1'],
		);
		assert.deepEqual(P.mintedInClear({ text: 'x', entities: [], newEntries: {} }), []);
	});
});

describe('protect: cost follows the text, not the set', () => {
	test('a set of 10,000 NUMBER IDs keeps a short item fast', () => {
		// One invoice list under All Numbers mints an ID per number; every later item paid about
		// 1 ms per ID for the table scan (twice with Additionally Protect on).
		const s = P.emptyState('sequential');
		for (let i = 0; i < 10000; i++) {
			s.ids.push({
				value: `K${i}`,
				key: `NUMBER_${i + 1}`,
				type: 'NUMBER',
				mine: false,
				main: true,
			});
			s.used.push(`NUMBER_${i + 1}`);
		}
		for (const extra of [undefined, { NUMBER: true }]) {
			const out = timed(() =>
				P.protect(
					s,
					'Order K77 for Ana and 12',
					spansFor('Order K77 for Ana and 12', [['Ana', 'PERSON']]),
					{
						extra,
						findPossible: false,
					},
				),
			);
			assert.ok(out.ms < 3000, `${JSON.stringify(extra)}: ${out.ms} ms`);
			assert.match(
				out.value.text,
				/^Order \[NUMBER_78\] for \[PERSON_1\] and (12|\[NUMBER_10001\])$/,
			);
		}
	});

	test('a crafted long word does not make the key scan quadratic', () => {
		// "_1_X" repeated: the old /\b[A-Z][A-Z0-9_]*_[a-z0-9]+(?:_[A-Z][A-Z0-9_]*)?\b/ backtracked
		// at every "_1" (11 s and more for 119k characters, all synchronous).
		const text = `Ticket X${'_1_X'.repeat(29750)}a from Janez Novak`;
		assert.ok(text.length < 120000);
		const out = timed(() =>
			P.protect(P.emptyState('sequential'), text, spansFor(text, [['Janez Novak', 'PERSON']])),
		);
		assert.ok(out.ms < 3000, `${out.ms} ms`);
		assert.ok(out.value.text.endsWith(' from [PERSON_1]'));
		// Many words just under the length the scan still tests.
		const many = `${`X${'_1_X'.repeat(20)}a `.repeat(1400)}from Janez Novak`;
		const short = timed(() =>
			P.protect(P.emptyState('sequential'), many, spansFor(many, [['Janez Novak', 'PERSON']])),
		);
		assert.ok(short.ms < 3000, `${short.ms} ms`);
		assert.ok(short.value.text.endsWith(' from [PERSON_1]'));
	});

	test('the key scan still reserves every key-shaped word, the longest mintable included', () => {
		const longest = `${'A'.repeat(64)}_123456789_SURNAME`;
		for (const word of ['PERSON_1', 'PERSON_1_NAME', 'X_a7k2q', longest, `${'B'.repeat(64)}_12`]) {
			const table = {};
			P.anonymizeReserved(`see ${word}, ok`, [], table, { sequential: true });
			assert.ok(Object.prototype.hasOwnProperty.call(table, word), word);
			assert.equal(table[word], '');
		}
		const table = {};
		P.anonymizeReserved(
			'person_1 PERSON_A Person_1 PERSON_1x_ PERSON__1 é_1 PERSON_1é',
			[],
			table,
			{},
		);
		assert.deepEqual(Object.keys(table), ['PERSON__1', 'PERSON_1']);
	});

	test('the key scan reserves the same words as the old whole-text regex', () => {
		const OLD = /\b[A-Z][A-Z0-9_]*_[a-z0-9]+(?:_[A-Z][A-Z0-9_]*)?\b/g;
		const heads = ['PERSON', 'X', 'A1', 'é', 'p', '', 'AB_C'];
		const joins = ['_', '__', '', '-'];
		const suffixes = ['1', 'a7k2q', 'A', 'x9', ''];
		const tails = ['', '_NAME', '_', 'x', '_1_X', 'é', '_SURNAME'];
		const gaps = [' ', '', '[', '] ', '-', ', '];
		const pick = (list) => list[rnd(list.length)];
		const rnd = prng(1818);
		let reserved = 0;
		for (let round = 0; round < 2000; round++) {
			let text = '';
			for (let i = 0; i < 1 + rnd(6); i++) {
				text += pick(heads) + pick(joins) + pick(suffixes) + pick(tails) + pick(gaps);
			}
			const want = [];
			for (const m of text.matchAll(OLD)) if (!want.includes(m[0])) want.push(m[0]);
			const table = {};
			P.anonymizeReserved(text, [], table, {});
			assert.deepEqual(Object.keys(table), want, text);
			reserved += want.length;
		}
		assert.ok(reserved > 300, `reserved ${reserved}`);
	});
});

describe('protect: companies by legal form', () => {
	const BRIEF =
		'Contract brief\n\nPlease prepare a contract between Luka Zupan and Modra Vila d.o.o. for case K101.\n\n' +
		'Email: luka.zupan@modravila.si\nPhone: +386 41 123 456\n...\n' +
		'Modra Vila starts Project Apollo on 1 March 2027. Mr. Zupan will sign in person.';
	const BRIEF_SPANS = [
		at(BRIEF, 'Luka Zupan', 'PERSON'),
		at(BRIEF, 'Modra Vila', 'PERSON', 0),
		at(BRIEF, 'Email', 'PERSON'),
		at(BRIEF, 'luka.zupan@modravila.si', 'EMAIL_ADDRESS'),
		at(BRIEF, '+386 41 123 456', 'PHONE_NUMBER'),
		at(BRIEF, 'Modra Vila', 'PERSON', 1),
		at(BRIEF, 'Project Apollo', 'PERSON'),
		at(BRIEF, 'Zupan', 'PERSON', 1),
	];

	test('the beta brief: one COMPANY with its form, the bare name its own COMPANY, Mr. Zupan the surname part', () => {
		const s = P.emptyState('random');
		const out = P.protect(s, BRIEF, BRIEF_SPANS);
		const luka = byValue(s, 'Luka Zupan');
		const company = byValue(s, 'Modra Vila d.o.o.');
		const bare = byValue(s, 'Modra Vila');
		assert.equal(company.type, 'COMPANY');
		assert.equal(bare.type, 'COMPANY');
		assert.match(company.key, /^COMPANY_[a-z0-9]{5}$/);
		assert.notEqual(bare.key, company.key);
		assert.ok(out.text.includes(`between [${luka.key}] and [${company.key}] for case K101.`));
		assert.ok(!out.text.includes('d.o.o.'));
		assert.ok(out.text.includes(`[${bare.key}] starts`));
		assert.ok(out.text.includes(`Mr. [${luka.key}_SURNAME] will sign`));
		// Only persons have name parts.
		assert.ok(
			Object.values(s.subKeys).every((p) => s.ids.find((r) => r.key === p.of).type === 'PERSON'),
		);
		assert.ok(!Object.keys(s.subKeys).some((k) => k.startsWith('COMPANY_')));
		assert.equal(reveal(out, s), BRIEF);
	});

	test('re-protecting the same text keeps every placeholder', () => {
		const s = P.emptyState('random');
		const first = P.protect(s, BRIEF, BRIEF_SPANS);
		const count = s.ids.length;
		const again = P.protect(s, BRIEF, BRIEF_SPANS);
		assert.equal(again.text, first.text);
		assert.equal(s.ids.length, count);
	});

	test('a later text with only the bare name is typed COMPANY from the set', () => {
		const s = P.emptyState('random');
		const t1 = 'Hire Modra Vila d.o.o. now.';
		P.protect(s, t1, [at(t1, 'Modra Vila', 'PERSON')]);
		const text = 'Modra Vila starts Project Apollo.';
		P.protect(s, text, [at(text, 'Modra Vila', 'PERSON'), at(text, 'Project Apollo', 'PERSON')]);
		assert.equal(byValue(s, 'Modra Vila').type, 'COMPANY');
		assert.equal(byValue(s, 'Project Apollo').type, 'PERSON');
		const bareKey = byValue(s, 'Modra Vila').key;
		assert.ok(!Object.values(s.subKeys).some((p) => p.of === bareKey));
	});

	test('a company in the set matches its whole name again', () => {
		const s = P.emptyState('random');
		const t1 = 'Hire Modra Vila d.o.o. now.';
		P.protect(s, t1, [at(t1, 'Modra Vila', 'PERSON')]);
		const key = byValue(s, 'Modra Vila d.o.o.').key;
		const t2 = 'Pay Modra Vila d.o.o. today.';
		assert.equal(P.protect(s, t2, [at(t2, 'Modra Vila', 'PERSON')]).text, `Pay [${key}] today.`);
		assert.equal(s.ids.length, 1);
	});

	test('a masked set shows [COMPANY], with no name parts', () => {
		const s = P.emptyState('typed');
		const t = 'Hire Modra Vila d.o.o. now.';
		assert.equal(P.protect(s, t, [at(t, 'Modra Vila', 'PERSON')]).text, 'Hire [COMPANY] now.');
		assert.deepEqual(s.subKeys, {});
	});
});

describe('protect: Additionally protect', () => {
	const ALL_EXTRA = { NUMBER: true, AMOUNT: true, COMPANY: true };
	const extra = (s, text, pairs, opts, more = {}) => run(s, text, pairs, { extra: opts, ...more });

	test('a PERSON "Modra" inside the extra "Modra Vila d.o.o." gives one COMPANY', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'We pay Modra Vila d.o.o. now', [['Modra', 'PERSON']], { COMPANY: true });
		assert.deepEqual(valuesOf(s), [['Modra Vila d.o.o.', 'COMPANY', false]]);
		assert.match(out.text, /^We pay \[COMPANY_[a-z0-9]{5}\] now$/);
		assert.deepEqual(s.subKeys, {});
	});

	test('"Vila d.o.o." (companySpans) inside the extra span gives one COMPANY', () => {
		const s = P.emptyState('random');
		extra(s, 'We pay Modra Vila d.o.o. now', [['Vila', 'PERSON']], { COMPANY: true });
		assert.deepEqual(valuesOf(s), [['Modra Vila d.o.o.', 'COMPANY', false]]);
	});

	test('a DATE "15.5." inside "15.5.2026" gives one NUMBER', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'Due on 15.5.2026.', [['15.5.', 'DATE']], { NUMBER: true });
		assert.deepEqual(valuesOf(s), [['15.5.2026', 'NUMBER', false]]);
		assert.match(out.text, /^Due on \[NUMBER_[a-z0-9]{5}\]\.$/);
	});

	test('an ID "1" inside "1.000" gives one NUMBER "1.000"', () => {
		const s = seed({ ids: [rec('1', 'ONE', 'CUSTOM', { mine: true })] });
		const out = extra(s, 'It costs 1.000 and 1.', [], { NUMBER: true });
		assert.match(out.text, /^It costs \[NUMBER_[a-z0-9]{5}\] and \[ONE\]\.$/);
		assert.deepEqual(valuesOf(s)[0], ['1.000', 'NUMBER', false]);
	});

	test('a span with exactly the same range wins over the extra one', () => {
		const s = P.emptyState('random');
		extra(s, 'Call 041-123-456.', [['041-123-456', 'PHONE_NUMBER']], { NUMBER: true });
		assert.deepEqual(valuesOf(s), [['041-123-456', 'PHONE_NUMBER', false]]);
	});

	test('a crossing gateway span wins and the outside pieces stay protected', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'Ana K-101 here', [['Ana K', 'PERSON']], { NUMBER: true });
		assert.deepEqual(
			valuesOf(s)
				.map((v) => v.slice(0, 2))
				.sort(),
			[
				['101', 'NUMBER'],
				['Ana K', 'PERSON'],
			],
		);
		assert.match(out.text, /^\[PERSON_[a-z0-9]{5}\]-\[NUMBER_[a-z0-9]{5}\] here$/);
	});

	test('a skipped "Modra" with COMPANY on still protects "Modra Vila d.o.o."', () => {
		const s = P.emptyState('random');
		extra(
			s,
			'We pay Modra Vila d.o.o. now',
			[['Modra', 'PERSON']],
			{ COMPANY: true },
			skipping('Modra'),
		);
		assert.deepEqual(valuesOf(s), [['Modra Vila d.o.o.', 'COMPANY', false]]);
	});

	test('a skipped extra value stays clear', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'Case K101 and K102', [], { NUMBER: true }, skipping('K101'));
		assert.match(out.text, /^Case K101 and \[NUMBER_[a-z0-9]{5}\]$/);
	});

	test('options off: nothing extra', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'Modra Vila d.o.o. owes 4.800 EUR for K101', [], {});
		assert.equal(out.text, 'Modra Vila d.o.o. owes 4.800 EUR for K101');
		assert.deepEqual(s.ids, []);
		assert.equal(P.protect(s, 'K101', []).text, 'K101');
	});

	test('extra-found records are found (mine: false) with their types', () => {
		const s = P.emptyState('random');
		const out = extra(s, 'Modra Vila d.o.o. owes 4.800 EUR for K101', [], ALL_EXTRA);
		assert.deepEqual(valuesOf(s), [
			['Modra Vila d.o.o.', 'COMPANY', false],
			['4.800 EUR', 'AMOUNT', false],
			['K101', 'NUMBER', false],
		]);
		assert.match(out.text, /^\[COMPANY_\w+\] owes \[AMOUNT_\w+\] for \[NUMBER_\w+\]$/);
	});

	for (const [numbering, text] of [
		['typed', '[COMPANY] owes [AMOUNT] for [NUMBER]'],
		['redacted', '[REDACTED] owes [REDACTED] for [REDACTED]'],
	]) {
		test(`masked set (${numbering}): stored, shown as labels`, () => {
			const s = P.emptyState(numbering);
			const out = extra(s, 'Modra Vila d.o.o. owes 4.800 EUR for K101', [], ALL_EXTRA);
			assert.equal(out.text, text);
			assert.deepEqual(s.ids.map((r) => r.type).sort(), ['AMOUNT', 'COMPANY', 'NUMBER']);
		});
	}

	test('sequential numbering mints counters for the extra types', () => {
		const s = P.emptyState('sequential');
		assert.equal(extra(s, 'K101 and K102', [], { NUMBER: true }).text, '[NUMBER_1] and [NUMBER_2]');
	});

	test('never re-protects own placeholders: a NUMBER does not eat [PERSON_1]', () => {
		const s = P.emptyState('sequential');
		extra(s, 'Luka Zupan', [['Luka Zupan', 'PERSON']], {});
		assert.equal(
			extra(s, '[PERSON_1] paid 12', [], { NUMBER: true }).text,
			'[PERSON_1] paid [NUMBER_1]',
		);
	});
});

describe('protect: possible IDs', () => {
	test('replies with possible and possibleMore, never a score', () => {
		const s = P.emptyState('random');
		const out = run(s, 'Luka Zupan said hi to Luki', [['Luka Zupan', 'PERSON']]);
		assert.deepEqual(
			out.possible.map((p) => [p.value, p.kind, p.type]),
			[['Luki', 'case-form', 'PERSON']],
		);
		assert.equal(out.possibleMore, false);
		assert.doesNotMatch(JSON.stringify(out.possible), /score|confidence/);
	});

	test('detected values are listed where they stay in clear', () => {
		const original = 'Modra Vila starts Project Apollo. Ask Modra Vila.';
		const detected = P.detectedValues(original, [
			{ start: 0, end: 10, entity_type: 'ORGANIZATION' },
			{ start: 18, end: 32, entity_type: 'MISC' },
		]);
		assert.deepEqual(detected, [
			{ value: 'Modra Vila', type: 'ORGANIZATION' },
			{ value: 'Project Apollo', type: 'MISC' },
		]);
		const out = P.protect(P.emptyState('random'), original, [], { detected });
		assert.deepEqual(
			out.possible.map((p) => [p.value, p.kind, p.type, p.of, original.slice(p.start, p.end)]),
			[
				['Modra Vila', 'detected', 'COMPANY', null, 'Modra Vila'],
				['Project Apollo', 'detected', null, null, 'Project Apollo'],
				['Modra Vila', 'detected', 'COMPANY', null, 'Modra Vila'],
			],
		);
	});

	test('skipped values are never listed', () => {
		const out = run(
			P.emptyState('random'),
			'Luka Zupan said hi to Luki',
			[['Luka Zupan', 'PERSON']],
			skipping('Luki'),
		);
		assert.deepEqual(out.possible, []);
	});
});

describe('protect: findPossible option', () => {
	/** Counts the calls protect makes to possible.findPossible (CommonJS export, patched). */
	function counting(fn) {
		const original = possibleModule.findPossible;
		let calls = 0;
		possibleModule.findPossible = (...args) => {
			calls++;
			return original(...args);
		};
		try {
			return { value: fn(), calls: () => calls };
		} finally {
			possibleModule.findPossible = original;
		}
	}

	test('default (absent or true) lists the possible IDs as before', () => {
		for (const options of [{}, { findPossible: true }, undefined]) {
			const c = counting(() =>
				run(
					P.emptyState('random'),
					'Luka Zupan said hi to Luki',
					[['Luka Zupan', 'PERSON']],
					options,
				),
			);
			assert.deepEqual(
				c.value.possible.map((p) => p.value),
				['Luki'],
			);
			assert.equal(c.calls(), 1);
		}
	});

	test('findPossible: false skips the scan and returns no possibles', () => {
		const s = P.emptyState('random');
		const c = counting(() =>
			run(s, 'Luka Zupan said hi to Luki', [['Luka Zupan', 'PERSON']], {
				findPossible: false,
				detected: [{ value: 'Luki', type: 'PERSON' }],
			}),
		);
		assert.equal(c.calls(), 0);
		assert.deepEqual(c.value.possible, []);
		assert.equal(c.value.possibleMore, false);
		assert.match(c.value.text, /^\[PERSON_[a-z0-9]{5}\] said hi to Luki$/);
		assert.equal(s.ids.length, 1);
	});

	test('findPossible: false keeps a large set cheap on a long text', () => {
		const s = P.emptyState('random');
		for (let i = 0; i < 3000; i++) {
			s.ids.push({
				value: `Ime${i} Priimek${i}`,
				key: `PERSON_${i + 1}`,
				type: 'PERSON',
				mine: false,
				main: true,
			});
			s.used.push(`PERSON_${i + 1}`);
		}
		const text = 'Lorem Ipsum dolor sit Amet, consectetur Adipiscing elit. '.repeat(2000);
		const off = timed(() => P.protect(s, text, [], { findPossible: false }));
		assert.equal(off.value.text, text);
		assert.ok(off.ms < 3000, `${off.ms} ms`);
	});
});

describe('fromFlatMap and revealTable', () => {
	test('a flat map keeps revealing; protect continues it', () => {
		const table = {
			PERSON_2: 'Ana Novak',
			PERSON_2_NAME: 'Ana',
			PERSON_2_SURNAME: 'Novak',
			CASE: 'K101',
		};
		const s = P.fromFlatMap({ table, used: ['PERSON_7'], mine: ['CASE'] }, 'sequential');
		assert.deepEqual(P.revealTable(s), table);
		const out = run(s, 'Ana Novak, Ana, K101 and Bo Kos', [['Bo Kos', 'PERSON']]);
		assert.equal(out.text, '[PERSON_2], [PERSON_2_NAME], [CASE] and [PERSON_8]');
		assert.equal(reveal(out, s), 'Ana Novak, Ana, K101 and Bo Kos');
	});

	test('emptyState', () => {
		assert.deepEqual(P.emptyState('typed'), {
			numbering: 'typed',
			ids: [],
			subKeys: {},
			aliases: {},
			used: [],
		});
	});
});

describe('parity with the extension anonIdEdits.anonymize', { skip: SKIP_EXT }, () => {
	const WORDS = [
		['Luka Zupan', ['PERSON', 'LOCATION']],
		['Mr. Zupan', ['PERSON']],
		['Luki', ['PERSON', null]],
		['Modra Vila d.o.o.', ['PERSON', null]],
		['Modra Vila', ['PERSON', 'LOCATION', null]],
		['ana@x.si', ['EMAIL_ADDRESS']],
		['041-555-111', ['PHONE_NUMBER', null]],
		['SI56 2900 0001 2345 6789', ['IBAN_CODE', 'IBAN']],
		['4.800 EUR', ['AMOUNT', null]],
		['K101', [null, 'CUSTOM']],
		['15.5.2026', ['DATE_TIME', null]],
		['[PERSON_1]', [null]],
		['PERSON_2', [null]],
		['Ana', ['PERSON']],
		['Ana Novak', ['PERSON']],
		['1', [null]],
		['constructor', ['bad type', null]],
		['Zala Kos s.p.', ['PERSON']],
		['Apollo', [null]],
		['😀', [null]],
	];

	const extEntity = (e) => ({
		entityType: e.entity_type,
		placeholder: e.replacement,
		start: e.start,
		end: e.end,
		score: e.score,
		key: e.key,
		value: e.value,
	});
	const content = (s) => ({
		numbering: s.numbering,
		ids: s.ids,
		subKeys: s.subKeys,
		aliases: s.aliases,
		used: s.used,
	});

	/** Renames every key both runs minted to its position in `used`, so random suffixes compare. */
	function canonical(value, used) {
		const names = new Map(used.map((k, i) => [k, `K${i}`]));
		const rename = (str) => str.replace(/[A-Za-z0-9_]+/g, (w) => names.get(w) ?? w);
		return JSON.parse(rename(JSON.stringify(value)));
	}

	function generate(rnd) {
		const tokens = [];
		for (let i = 0; i < 1 + rnd(7); i++) tokens.push(WORDS[rnd(WORDS.length)]);
		const text = tokens.map(([w]) => w).join([' ', ', ', ' and ', '\n'][rnd(4)]);
		const spans = [];
		let pos = 0;
		for (const [word, types] of tokens) {
			const start = text.indexOf(word, pos);
			pos = start + word.length;
			const type = types[rnd(types.length)];
			if (type === null) continue;
			spans.push({
				entity_type: type,
				start: start - (rnd(5) === 0 ? 1 : 0),
				end: pos + (rnd(5) === 0 ? 1 : 0),
				score: rnd(100) / 100,
			});
		}
		return { text, spans };
	}

	for (const numbering of ['sequential', 'random', 'typed', 'redacted']) {
		test(`${numbering}: same text, entities, possibles and set on generated runs`, () => {
			const ext = loadExt();
			const rnd = prng(numbering.length * 1000 + 17);
			const stats = {
				steps: 0,
				texts: new Set(),
				extraOn: 0,
				twoExtra: 0,
				detected: 0,
				skipped: 0,
			};
			const starts = new Set();
			for (let round = 0; round < 120; round++) {
				const start = rnd(3);
				const mine =
					start === 0
						? P.emptyState(numbering)
						: start === 1
							? {
									...E1(),
									numbering,
									aliases: numbering === 'typed' || numbering === 'redacted' ? {} : E1().aliases,
								}
							: P.fromFlatMap(
									{
										table: { PERSON_3: 'Ana Novak', PERSON_3_NAME: 'Ana', CASE: 'K101' },
										mine: ['CASE'],
										used: ['PERSON_9'],
									},
									numbering,
								);
				starts.add(start);
				const skipped = rnd(3) === 0 ? ['Luki', 'K101'] : [];
				if (skipped.length > 0) stats.skipped++;
				const theirs = { ...ext.anonIdModel.empty(), ...plain(mine), skipped, ignored: [] };
				for (let step = 0; step < 4; step++) {
					const { text, spans } = generate(rnd);
					const options = {
						extra: { NUMBER: !!rnd(2), AMOUNT: !!rnd(2), COMPANY: !!rnd(2) },
						detected: rnd(2)
							? [
									{ value: 'Apollo', type: 'MISC' },
									{ value: 'Modra Vila', type: 'ORGANIZATION' },
								]
							: undefined,
					};
					const extraCount = Object.values(options.extra).filter(Boolean).length;
					stats.steps++;
					stats.texts.add(text);
					if (extraCount > 0) stats.extraOn++;
					if (extraCount >= 2) stats.twoExtra++;
					if (options.detected) stats.detected++;
					const usedBefore = theirs.used.length;
					const a = P.protect(mine, text, plain(spans), {
						...options,
						isSkipped: (v) => skipped.includes(v),
					});
					const b = ext.anonIdEdits.anonymize(theirs, text, plain(spans), plain(options));
					const got = {
						text: a.text,
						entities: a.entities,
						possible: a.possible,
						possibleMore: a.possibleMore,
						minted: a.minted,
						set: content(mine),
					};
					const want = {
						text: b.text,
						entities: b.entities.map(extEntity),
						possible: b.possible,
						possibleMore: b.possibleMore,
						minted: theirs.used.slice(usedBefore),
						set: content(theirs),
					};
					const context = JSON.stringify({ numbering, round, step, text, spans });
					if (numbering === 'sequential') {
						assert.deepEqual(plain(got), plain(want), context);
					} else {
						assert.equal(mine.used.length, theirs.used.length, context);
						assert.deepEqual(
							canonical(plain(got), mine.used),
							canonical(plain(want), theirs.used),
							context,
						);
					}
				}
			}
			// The corpus must actually vary (a degenerate PRNG once left Additionally Protect on in
			// 17 of 1920 steps, never two options at once).
			assert.equal(starts.size, 3);
			assert.ok(stats.texts.size > 300, `distinct texts ${stats.texts.size}`);
			assert.ok(stats.extraOn > 340, `steps with extra ${stats.extraOn}`);
			assert.ok(stats.twoExtra > 180, `steps with two or more extra ${stats.twoExtra}`);
			assert.ok(stats.detected > 180, `steps with detected ${stats.detected}`);
			assert.ok(stats.skipped > 20, `rounds with skipped ${stats.skipped}`);
		});
	}
});
