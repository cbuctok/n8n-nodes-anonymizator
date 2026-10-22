// Port of the extension's tests/id-possible.test.js against dist/, plus differential checks that
// run the extension's real lib/id-possible.js (node:vm) on the same inputs. Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { loadExt, plain, prng, SKIP_EXT, timed } from './engine-ext.mjs';

const require = createRequire(import.meta.url);
const P = require('../dist/nodes/Anonymizator/shared/possible.js');
const { extraSpans } = require('../dist/nodes/Anonymizator/shared/extraDetect.js');
const { emptyContent } = require('../dist/nodes/Anonymizator/shared/idModel.js');

const NBSP = '\u00A0';

const rec = (value, key, type, extra = {}) => ({
	value,
	key,
	type,
	mine: false,
	main: true,
	...extra,
});
/** A set; `skipped` / `ignored` (extension state fields) become the isExcluded test. */
const state = (fields = {}) => ({ ...emptyContent('random'), ...fields });
const excludedBy = (s) => {
	const values = new Set([...(s.skipped || []), ...(s.ignored || [])]);
	return (v) => values.has(v);
};
const find = (s, text, entities = [], options = {}) =>
	P.findPossible(s, text, entities, { ...options, isExcluded: s ? excludedBy(s) : undefined });

const LUKA_FOUND = () =>
	state({
		ids: [rec('Luka Zupan', 'PERSON_a7k2q', 'PERSON')],
		subKeys: {
			PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Luka', rec: 'Luka Zupan' },
			PERSON_a7k2q_SURNAME: { of: 'PERSON_a7k2q', value: 'Zupan', rec: 'Luka Zupan' },
		},
	});
const LUKA_MINE = () =>
	state({ ids: [rec('Luka Zupan', 'PERSON_a7k2q', 'PERSON', { mine: true })] });
const person = (value, key = 'PERSON_b1') => state({ ids: [rec(value, key, 'PERSON')] });

/** [value, kind] of every possible. */
const flagged = (s, text, entities = [], options) =>
	find(s, text, entities, options).possible.map((p) => [p.value, p.kind]);

describe('possible helpers', () => {
	test('caseStem drops one final vowel, lower-cased; empty under 3 letters', () => {
		assert.equal(P.caseStem('Luka'), 'luk');
		assert.equal(P.caseStem('Zupan'), 'zupan');
		assert.equal(P.caseStem('Marko'), 'mark');
		assert.equal(P.caseStem('Ana'), '');
		assert.equal(P.caseStem('Jo'), '');
	});

	test('isCaseForm follows the endings and the length rule', () => {
		assert.equal(P.isCaseForm('Luki', 'Luka'), true);
		assert.equal(P.isCaseForm('Zupanu', 'Zupan'), true);
		assert.equal(P.isCaseForm('Zupanom', 'Zupan'), true);
		assert.equal(P.isCaseForm('Zupanjem', 'Zupan'), true);
		assert.equal(P.isCaseForm('Luka', 'Luka'), false);
		assert.equal(P.isCaseForm('Lukas', 'Luka'), false);
		assert.equal(P.isCaseForm('Lukasz', 'Luka'), false);
		assert.equal(P.isCaseForm('luki', 'Luka'), false);
		assert.equal(P.isCaseForm('Luki', 'luka'), false);
		assert.equal(P.isCaseForm('Petra', 'Peter'), false);
	});

	test('the kinds, the endings and the cap', () => {
		assert.deepEqual(P.POSSIBLE_KINDS, [
			'company-name',
			'surname',
			'title-surname',
			'case-form',
			'number',
			'amount',
			'company',
			'detected',
		]);
		assert.deepEqual(P.ENDINGS, ['a', 'e', 'i', 'o', 'u', 'om', 'em', 'ja', 'ju', 'jem']);
		assert.equal(P.MAX_POSSIBLE, 50);
		assert.equal(P.MAX_DETECTED, 200);
	});
});

describe('findPossible: flagged', () => {
	test('Luka Zupan found: "Pošlji Luki in g. Zupanu"', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), 'Pošlji Luki in g. Zupanu'), [
			['Luki', 'case-form'],
			['g. Zupanu', 'case-form'],
		]);
	});

	test('Luka Zupan added by you: "Mr. Zupan agreed" gives title-surname', () => {
		const out = find(LUKA_MINE(), 'Mr. Zupan agreed', []);
		assert.deepEqual(out.possible, [
			{
				start: 0,
				end: 9,
				value: 'Mr. Zupan',
				kind: 'title-surname',
				type: 'PERSON',
				of: 'PERSON_a7k2q',
			},
		]);
		assert.equal(out.more, false);
	});

	test('Luka Zupan added by you: "Zupan agreed" gives surname', () => {
		assert.deepEqual(flagged(LUKA_MINE(), 'Zupan agreed'), [['Zupan', 'surname']]);
	});

	test('a Slovene title: "g. Zupan" gives title-surname', () => {
		assert.deepEqual(flagged(LUKA_MINE(), 'Hvala, g. Zupan.'), [['g. Zupan', 'title-surname']]);
	});

	test('Modra Vila d.o.o.: "Modra Vila said" gives company-name', () => {
		const s = state({ ids: [rec('Modra Vila d.o.o.', 'COMPANY_x1', 'COMPANY')] });
		assert.deepEqual(find(s, 'Modra Vila said', []).possible, [
			{
				start: 0,
				end: 10,
				value: 'Modra Vila',
				kind: 'company-name',
				type: 'COMPANY',
				of: 'COMPANY_x1',
			},
		]);
	});

	test('Marko Horvat: "z Markom Horvatom" is one merged span', () => {
		assert.deepEqual(flagged(person('Marko Horvat'), 'z Markom Horvatom'), [
			['Markom Horvatom', 'case-form'],
		]);
		assert.deepEqual(flagged(person('Marko Horvat'), `z Markom${NBSP}Horvatom`), [
			[`Markom${NBSP}Horvatom`, 'case-form'],
		]);
	});

	test('Luka Zupan added by you: "Luke Zupan" merges case-form + surname', () => {
		assert.deepEqual(flagged(LUKA_MINE(), 'to Luke Zupan.'), [['Luke Zupan', 'case-form']]);
	});

	test('Janez Novak: "Janeza"', () => {
		assert.deepEqual(flagged(person('Janez Novak'), 'pri Janeza'), [['Janeza', 'case-form']]);
	});

	test('tolerated false positives: "Luke", "Miru"', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), 'Luke Skywalker'), [['Luke', 'case-form']]);
		assert.deepEqual(flagged(person('Mira Kranjc'), 'v Miru'), [['Miru', 'case-form']]);
	});

	test('single-word PERSON values and every sub-key value are sources', () => {
		assert.deepEqual(flagged(person('Zupan'), 'Zupana'), [['Zupana', 'case-form']]);
		assert.deepEqual(flagged(LUKA_FOUND(), 'Zupanom'), [['Zupanom', 'case-form']]);
	});

	test('a title before a case form extends the span; the kind stays case-form', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), 'za ga. Zupanovo'), []);
		assert.deepEqual(flagged(LUKA_FOUND(), 'Mr. Zupanu'), [['Mr. Zupanu', 'case-form']]);
	});
});

describe('findPossible: never flagged', () => {
	for (const [value, text] of [
		['Ana Kovač', 'Ano in Ani'],
		['Jan Novak', 'Jana'],
		['Rok Kos', 'Roka, Kosa, Kosi'],
		['Luka Zupan', 'Lukas and Lukasz'],
		['Luka Zupan', 'luki'],
		['Peter Kos', 'Petra'],
	]) {
		test(`${value}: ${text}`, () => {
			assert.deepEqual(flagged(person(value), text), []);
		});
	}

	test('"Luka" itself is the token (and protected anyway)', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), 'Luka'), []);
	});

	test('an excluded (ignored / skipped) value is never highlighted', () => {
		const s = LUKA_FOUND();
		s.ignored = ['Luke'];
		assert.deepEqual(flagged(s, 'Luke'), []);
		const t = LUKA_FOUND();
		t.skipped = ['Luki'];
		assert.deepEqual(flagged(t, 'Luki'), []);
	});

	test('record and sub-key values are excluded', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), 'Zupan'), []);
		const s = state({
			ids: [
				rec('Luka Zupan', 'PERSON_1', 'PERSON', { mine: true }),
				rec('Zupan', 'CUSTOM_1', 'CUSTOM', { mine: true }),
			],
		});
		assert.deepEqual(flagged(s, 'Zupan'), []);
	});

	test('inside a placeholder', () => {
		assert.deepEqual(flagged(LUKA_FOUND(), '[PERSON_a7k2q_NAME] and [Luki] and [Zupanu]'), []);
	});

	test('inside an entity range', () => {
		const text = 'xx Luki yy';
		assert.deepEqual(flagged(LUKA_FOUND(), text, [{ start: 3, end: 7 }]), []);
		assert.deepEqual(flagged(LUKA_FOUND(), text, [{ start: 0, end: 4 }]), []);
	});

	test('Modra Vila d.o.o. written whole, or in lower case', () => {
		const s = state({ ids: [rec('Modra Vila d.o.o.', 'COMPANY_x1', 'COMPANY')] });
		assert.deepEqual(flagged(s, 'Modra Vila d.o.o. pays'), []);
		assert.deepEqual(flagged(s, 'Modra Vila, d.o.o. pays'), []);
		assert.deepEqual(flagged(s, 'modra vila pays'), []);
	});

	test('a short company name (< 3) is never flagged', () => {
		const s = state({ ids: [rec('AB d.o.o.', 'COMPANY_x1', 'COMPANY')] });
		assert.deepEqual(flagged(s, 'AB said'), []);
	});

	test('"Zupan" as one-word CUSTOM: not a PERSON token', () => {
		const s = state({ ids: [rec('Zupan', 'CUSTOM_1', 'CUSTOM', { mine: true })] });
		assert.deepEqual(flagged(s, 'Zupana'), []);
	});

	test('given names alone are never flagged by the surname rule', () => {
		assert.deepEqual(flagged(LUKA_MINE(), 'Luka said'), []);
	});

	test('whole words only', () => {
		assert.deepEqual(flagged(LUKA_MINE(), 'Zupanić and xZupan and Zupan2'), []);
	});
});

describe('findPossible: extra spans, cap, shape', () => {
	test('extra spans become possibles with of: null and their kind', () => {
		const text = 'pay 4.800 EUR to Modra Vila d.o.o. for K101';
		const extra = extraSpans(text, { NUMBER: true, AMOUNT: true, COMPANY: true });
		const out = find(emptyContent('random'), text, [], { extra });
		assert.deepEqual(
			out.possible.map((p) => [p.value, p.kind, p.type, p.of]),
			[
				['4.800 EUR', 'amount', 'AMOUNT', null],
				['Modra Vila d.o.o.', 'company', 'COMPANY', null],
				['K101', 'number', 'NUMBER', null],
			],
		);
	});

	test('extra spans follow the exclusions and never overlap a variant or an entity', () => {
		const s = LUKA_FOUND();
		s.ignored = ['K101'];
		const text = 'Luki K101 K102 [PERSON_1]';
		const extra = [
			{ entity_type: 'NUMBER', start: 5, end: 9 },
			{ entity_type: 'NUMBER', start: 10, end: 14 },
			{ entity_type: 'NUMBER', start: 23, end: 24 },
			{ entity_type: 'NUMBER', start: 0, end: 4 },
			{ entity_type: 'DATE', start: 10, end: 14 },
		];
		assert.deepEqual(flagged(s, text, [], { extra }), [
			['Luki', 'case-form'],
			['K102', 'number'],
		]);
	});

	test('caps at MAX and sets more', () => {
		const text = Array.from({ length: 60 }, () => 'Luki').join(' , ');
		const out = find(LUKA_FOUND(), text, []);
		assert.equal(out.possible.length, 50);
		assert.equal(out.more, true);
		assert.equal(find(LUKA_FOUND(), 'Luki', []).more, false);
	});

	test('never carries a score or a confidence field', () => {
		const text = 'Mr. Zupan, Luke, Modra Vila and 12';
		const s = state({
			ids: [
				rec('Luka Zupan', 'PERSON_1', 'PERSON', { mine: true }),
				rec('Modra Vila d.o.o.', 'COMPANY_1', 'COMPANY'),
			],
		});
		const out = find(s, text, [], { extra: extraSpans(text, { NUMBER: true }) });
		assert.ok(out.possible.length > 2);
		for (const p of out.possible) {
			assert.deepEqual(Object.keys(p).sort(), ['end', 'kind', 'of', 'start', 'type', 'value']);
			assert.doesNotMatch(JSON.stringify(p), /score|confidence/i);
		}
	});

	test('possibles are sorted and never overlap', () => {
		const out = find(LUKA_MINE(), 'Mr. Zupan and Luke Zupan and Luki', []);
		for (let i = 1; i < out.possible.length; i++) {
			assert.ok(out.possible[i].start >= out.possible[i - 1].end);
		}
	});

	test('empty or missing input finds nothing', () => {
		assert.deepEqual(find(LUKA_FOUND(), '', []), { possible: [], more: false });
		assert.deepEqual(find(null, 'Luki', []), { possible: [], more: false });
	});
});

describe('gateway possible values (detected)', () => {
	test('detectedValues: distinct trimmed values of the spans, first type wins', () => {
		const text = 'Modra Vila and Modra Vila, Acme ';
		const spans = [
			{ start: 0, end: 10, entity_type: 'ORGANIZATION' },
			{ start: 15, end: 25, entity_type: 'MISC' },
			{ start: 27, end: 32, entity_type: 'ORGANIZATION' },
			{ start: 1.5, end: 3, entity_type: 'ORGANIZATION' },
		];
		assert.deepEqual(P.detectedValues(text, spans), [
			{ value: 'Modra Vila', type: 'ORGANIZATION' },
			{ value: 'Acme', type: 'ORGANIZATION' },
		]);
		assert.deepEqual(P.detectedValues(text, null), []);
	});

	test('detectedValues stops at MAX_DETECTED distinct values', () => {
		const words = Array.from({ length: 250 }, (_, i) => `W${i}`);
		const text = words.join(' ');
		let at = 0;
		const spans = words.map((w) => {
			const s = { start: at, end: at + w.length, entity_type: 'PERSON' };
			at += w.length + 1;
			return s;
		});
		assert.equal(P.detectedValues(text, spans).length, 200);
	});

	test('find lists whole-word occurrences as kind detected, typed by DETECTED_TYPES', () => {
		const detected = [
			{ value: 'Modra Vila', type: 'ORGANIZATION' },
			{ value: 'Apollo', type: 'MISC' },
		];
		assert.deepEqual(find(state(), 'Modra Vila, Modra Vilas, Apollo.', [], { detected }).possible, [
			{ start: 0, end: 10, value: 'Modra Vila', kind: 'detected', type: 'COMPANY', of: null },
			{ start: 25, end: 31, value: 'Apollo', kind: 'detected', type: null, of: null },
		]);
	});

	test('never inside an entity or a placeholder, never an ID or an excluded value', () => {
		const detected = [{ value: 'Modra Vila', type: 'ORGANIZATION' }];
		const text = '[COMPANY_1] Modra Vila';
		assert.deepEqual(flagged(state(), text, [{ start: 12, end: 22 }], { detected }), []);
		assert.deepEqual(flagged(state({ ignored: ['Modra Vila'] }), text, [], { detected }), []);
		assert.deepEqual(
			flagged(state({ ids: [rec('Modra Vila', 'COMPANY_1', 'COMPANY')] }), text, [], { detected }),
			[],
		);
		assert.deepEqual(flagged(state(), text, [], { detected }), [['Modra Vila', 'detected']]);
	});
});

describe('findPossible: cost with a large set', () => {
	// A set that grew over many items (Share Map Across Items, an Existing Placeholder Map): the
	// case-form rule asked every PERSON token about every capitalised word (seconds per item).
	/** i in base 26, as lower-case letters (name tokens must be letters only). */
	const letters = (i) => {
		let out = '';
		do {
			out = String.fromCharCode(97 + (i % 26)) + out;
			i = Math.floor(i / 26);
		} while (i > 0);
		return out;
	};
	const bigSet = (n) =>
		state({
			ids: Array.from({ length: n }, (_, i) =>
				rec(`Ime${letters(i)} Priimek${letters(i)}`, `PERSON_${i + 1}`, 'PERSON'),
			),
		});
	const prose =
		'Lorem Ipsum Dolor Sitamet Consectetur Adipiscing Elitsed Doeius Tempor Incididunt ';

	test('500 PERSON IDs on 120k characters of capitalised words', () => {
		const s = bigSet(500);
		// letters(7) = 'h': "Priimekh" is a surname, "Priimekhom" and "Imehom" case forms.
		const text = `${prose.repeat(1450)}Priimekh met Priimekhom and Imehom.`;
		const out = timed(() => find(s, text));
		assert.ok(out.ms < 3000, `${out.ms} ms`);
		assert.deepEqual(
			out.value.possible.map((p) => [p.value, p.kind, p.of]),
			[
				['Priimekh', 'surname', 'PERSON_8'],
				['Priimekhom', 'case-form', 'PERSON_8'],
				['Imehom', 'case-form', 'PERSON_8'],
			],
		);
	});

	test('the first matching name token still wins on a shared stem', () => {
		const s = state({
			ids: [
				rec('Luka Horvat', 'PERSON_1', 'PERSON'),
				rec('Lukas Horvata', 'PERSON_2', 'PERSON'),
				rec('Luke Novak', 'PERSON_3', 'PERSON'),
			],
		});
		assert.deepEqual(
			find(s, 'Luki, Lukasa, Horvatu, Horvati').possible.map((p) => [p.value, p.of]),
			[
				['Luki', 'PERSON_1'],
				['Lukasa', 'PERSON_2'],
				['Horvatu', 'PERSON_1'],
				['Horvati', 'PERSON_1'],
			],
		);
	});
});

describe('parity with the extension lib/id-possible.js', { skip: SKIP_EXT }, () => {
	test('find agrees on generated large sets with shared stems', () => {
		const ext = loadExt();
		const rnd = prng(4711);
		const given = [
			'Luka',
			'Luke',
			'Lukas',
			'Marko',
			'Marka',
			'Ana',
			'Ivana',
			'Jože',
			'Tina',
			'Črt',
		];
		const family = ['Horvat', 'Horvata', 'Zupan', 'Zupana', 'Novak', 'Kovač', 'Šuštar', 'Modra'];
		const words = [
			'Luki',
			'Luko',
			'Lukasu',
			'Markom',
			'Marku',
			'Horvatu',
			'Horvatom',
			'Zupanu',
			'Novaku',
			'Kovaču',
			'Šuštarja',
			'g. Zupanu',
			'Mr. Horvat',
			'Ivani',
			'Jožetu',
			'Tini',
			'Modra Vila',
			'Novak',
			'Apollo',
		];
		let flaggedRounds = 0;
		for (let round = 0; round < 200; round++) {
			const ids = [];
			for (let i = 0; i < 1 + rnd(40); i++) {
				const value =
					rnd(5) === 0
						? family[rnd(family.length)]
						: `${given[rnd(given.length)]} ${family[rnd(family.length)]}`;
				ids.push(rec(value, `PERSON_${i + 1}`, rnd(8) === 0 ? 'COMPANY' : 'PERSON'));
			}
			const s = state({ ids });
			const parts = [];
			for (let i = 0; i < 1 + rnd(12); i++) parts.push(words[rnd(words.length)]);
			const text = parts.join([' ', ', ', NBSP][rnd(3)]);
			const detected = rnd(2) ? [{ value: 'Apollo', type: 'MISC' }] : undefined;
			const mine = find(s, text, [], { detected });
			const theirs = ext.anonPossible.find({ ...ext.anonIdModel.empty(), ...plain(s) }, text, [], {
				detected,
			});
			assert.deepEqual(plain(mine), plain(theirs), JSON.stringify({ text, ids }));
			if (mine.possible.length > 0) flaggedRounds++;
		}
		assert.ok(flaggedRounds > 120, `rounds with possibles ${flaggedRounds}`);
	});

	test('find and detectedValues agree on generated texts and sets', () => {
		const ext = loadExt();
		const rnd = prng(31337);
		const sets = [
			LUKA_FOUND(),
			LUKA_MINE(),
			person('Marko Horvat'),
			person('Zupan'),
			state({
				ids: [
					rec('Modra Vila d.o.o.', 'COMPANY_x1', 'COMPANY'),
					rec('Ana Kovač Horvat', 'PERSON_2', 'PERSON'),
				],
				ignored: ['Luke'],
				skipped: ['Horvatom'],
			}),
		];
		const words = [
			'Luki',
			'g. Zupanu',
			'Mr. Zupan',
			'Zupan',
			'Luke',
			'Markom',
			'Horvatom',
			'Modra Vila',
			'Modra Vila d.o.o.',
			'[PERSON_1]',
			'Kovač Horvat',
			'Ani',
			'Apollo',
			'K101',
			'4.800 EUR',
			'Dr. Horvat',
		];
		const texts = new Set();
		const setsUsed = new Set();
		let withExtra = 0;
		let withDetected = 0;
		let withEntities = 0;
		let flaggedRounds = 0;
		for (let round = 0; round < 400; round++) {
			const s = sets[rnd(sets.length)];
			const parts = [];
			for (let i = 0; i < 1 + rnd(9); i++) parts.push(words[rnd(words.length)]);
			const text = parts.join([' ', ', ', NBSP][rnd(3)]);
			const entities = rnd(3) === 0 ? [{ start: 0, end: rnd(text.length + 1) }] : [];
			const extra = rnd(2) ? extraSpans(text, { NUMBER: true, AMOUNT: true }) : undefined;
			const detected = rnd(2)
				? [
						{ value: 'Apollo', type: 'MISC' },
						{ value: 'Modra Vila', type: 'ORGANIZATION' },
					]
				: undefined;
			texts.add(text);
			setsUsed.add(s);
			if (extra) withExtra++;
			if (detected) withDetected++;
			if (entities.length > 0) withEntities++;
			const extState = { ...ext.anonIdModel.empty(), ...plain(s) };
			const theirs = ext.anonPossible.find(extState, text, plain(entities), {
				extra: extra && plain(extra),
				detected,
			});
			const mine = find(s, text, entities, { extra, detected });
			assert.deepEqual(plain(mine), plain(theirs), JSON.stringify({ text, set: s.ids }));
			if (mine.possible.length > 0) flaggedRounds++;
			const spans = [{ start: 0, end: Math.min(6, text.length), entity_type: 'ORGANIZATION' }];
			assert.deepEqual(
				plain(P.detectedValues(text, spans)),
				plain(ext.anonPossible.detectedValues(text, spans)),
			);
		}
		// The corpus must actually vary (a degenerate PRNG once fixed most of these choices).
		assert.ok(texts.size > 300, `distinct texts ${texts.size}`);
		assert.equal(setsUsed.size, sets.length);
		assert.ok(withExtra > 120, `rounds with extra ${withExtra}`);
		assert.ok(withDetected > 120, `rounds with detected ${withDetected}`);
		assert.ok(withEntities > 80, `rounds with entities ${withEntities}`);
		assert.ok(flaggedRounds > 120, `rounds with possibles ${flaggedRounds}`);
	});
});
