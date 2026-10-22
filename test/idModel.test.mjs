// Port of the extension's tests/id-model.test.js, the companySpans cases of tests/id-names.test.js
// and the own-placeholder cases of tests/id-set.test.js against dist/, plus differential checks
// that run the extension's real lib/id-model.js, id-rules.js and id-names.js (node:vm). Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { loadExt, plain, prng, SKIP_EXT } from './engine-ext.mjs';

const require = createRequire(import.meta.url);
const M = require('../dist/nodes/Anonymizator/shared/idModel.js');

const rec = (value, key, type, extra = {}) => ({
	value,
	key,
	type,
	mine: false,
	main: true,
	...extra,
});
const state = (fields = {}) => ({ ...M.emptyContent('random'), ...fields });

// E1 of the extension's contract: a group with name parts, an alias and a tombstone.
const E1 = () =>
	state({
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

/** A span over the nth (0-based) occurrence of `value` in `text`. */
function at(text, value, type, nth = 0) {
	let index = -1;
	for (let i = 0; i <= nth; i++) index = text.indexOf(value, index + 1);
	if (index < 0) throw new Error(`${value} #${nth} not in text`);
	return { entity_type: type, start: index, end: index + value.length, score: 0.9 };
}

describe('guessType', () => {
	for (const [value, type] of [
		['luka.zupan@modravila.si', 'EMAIL_ADDRESS'],
		['SI56 2900 0001 2345 6789', 'IBAN'],
		['Modra Vila d.o.o.', 'COMPANY'],
		['ACME Corporation', 'COMPANY'],
		['4.800 EUR', 'AMOUNT'],
		['€ 120', 'AMOUNT'],
		['+386 41 123 456', 'PHONE_NUMBER'],
		['041 123 456', 'PHONE_NUMBER'],
		['1234567', 'NUMBER'],
		['4.800', 'NUMBER'],
		['K101', 'CUSTOM'],
		['Luka Zupan', 'CUSTOM'],
		['Project Apollo', 'CUSTOM'],
	]) {
		test(`${value} is ${type}`, () => {
			assert.equal(M.guessType(value), type);
		});
	}

	test('trims, and handles odd input', () => {
		assert.equal(M.guessType('  ana@x.si  '), 'EMAIL_ADDRESS');
		assert.equal(M.guessType(''), 'CUSTOM');
		assert.equal(M.guessType(42), 'CUSTOM');
		assert.equal(M.guessType('Acme GmbH'), 'COMPANY');
		assert.equal(M.guessType('Ahoj s.p.'), 'COMPANY');
		assert.equal(M.guessType('$ 12,50'), 'AMOUNT');
		assert.equal(M.guessType('12 CHF'), 'AMOUNT');
		assert.equal(M.guessType('123'), 'NUMBER');
		assert.equal(M.guessType('00386 41 123 456'), 'PHONE_NUMBER');
		assert.equal(M.guessType('+386 41 123 456 789 012 3'), 'CUSTOM');
	});

	test('a date is not a phone; a legal form needs a word before it; AG only in capitals', () => {
		assert.equal(M.guessType('2024-10-09'), 'CUSTOM');
		assert.equal(M.guessType('09/10/2024'), 'CUSTOM');
		assert.equal(M.guessType('9-10-24'), 'CUSTOM');
		assert.equal(M.guessType('Ltd'), 'CUSTOM');
		assert.equal(M.guessType('d.o.o.'), 'CUSTOM');
		assert.equal(M.guessType('Hans Ag'), 'CUSTOM');
		assert.equal(M.guessType('Siemens AG'), 'COMPANY');
		assert.equal(M.guessType('Acme ltd'), 'COMPANY');
		assert.equal(M.guessType('Modra Vila D.O.O.'), 'COMPANY');
		assert.equal(M.guessType('Müller KG'), 'COMPANY');
	});
});

describe('types and keys', () => {
	test('prefixFor / typeFromPrefix round-trip EMAIL and PHONE', () => {
		assert.equal(M.prefixFor('EMAIL_ADDRESS'), 'EMAIL');
		assert.equal(M.prefixFor('PHONE_NUMBER'), 'PHONE');
		assert.equal(M.prefixFor('PERSON'), 'PERSON');
		assert.equal(M.prefixFor('IBAN_CODE'), 'IBAN');
		assert.equal(M.typeFromPrefix(M.prefixFor('IBAN_CODE')), 'IBAN');
		assert.equal(M.prefixFor('toString'), 'toString');
		assert.equal(M.typeFromPrefix('EMAIL'), 'EMAIL_ADDRESS');
		assert.equal(M.typeFromPrefix('PHONE'), 'PHONE_NUMBER');
		assert.equal(M.typeFromPrefix('NL_BSN'), 'NL_BSN');
		assert.equal(M.typeFromPrefix('bad type'), 'CUSTOM');
		assert.equal(M.typeFromPrefix(undefined), 'CUSTOM');
		assert.equal(M.typeFromPrefix('constructor'), 'CUSTOM');
		for (const t of M.TYPES) assert.equal(M.typeFromPrefix(M.prefixFor(t.code)), t.code);
	});

	test('TYPES lists the editor options in order', () => {
		assert.deepEqual(
			M.TYPES.map((t) => t.label),
			[
				'Name',
				'Company',
				'Email address',
				'Phone number',
				'Bank account (IBAN)',
				'Number',
				'Amount',
				'Other',
			],
		);
	});

	test('typeFromKey reads v1 keys', () => {
		assert.equal(M.typeFromKey('EMAIL_x7gs2'), 'EMAIL_ADDRESS');
		assert.equal(M.typeFromKey('EMAIL_ADDRESS_x7gs2'), 'EMAIL_ADDRESS');
		assert.equal(M.typeFromKey('IBAN_CODE_1'), 'IBAN');
		assert.equal(M.typeFromKey('PERSON_a7k2q'), 'PERSON');
		assert.equal(M.typeFromKey('PHONE_NUMBER_3'), 'PHONE_NUMBER');
		assert.equal(M.typeFromKey('CLIENT_a7k2q'), 'CUSTOM');
		assert.equal(M.typeFromKey('CASE'), 'CUSTOM');
		assert.equal(M.typeFromKey('PERSON_1_NAME'), 'CUSTOM');
	});

	test('namePart is the prefix part of a key', () => {
		assert.equal(M.namePart('EMAIL_x7gs2'), 'EMAIL');
		assert.equal(M.namePart('IBAN_CODE_1'), 'IBAN_CODE');
		assert.equal(M.namePart('COMPANY_x7gs2'), 'COMPANY');
		assert.equal(M.namePart('CLIENT'), 'CLIENT');
		assert.equal(M.namePart('Case_No'), 'Case_No');
	});

	test('legalFormAt reads a whole legal form at a position', () => {
		assert.equal(M.legalFormAt('Vila d.o.o. x', 5), 6);
		assert.equal(M.legalFormAt('Vila D.O.O.', 5), 6);
		assert.equal(M.legalFormAt('Vila d.o.o', 5), 0);
		assert.equal(M.legalFormAt('Hans Ag', 5), 0);
		assert.equal(M.legalFormAt('ACME AGB', 5), 0);
		assert.equal(M.legalFormAt('ACME Ltd.', 5), 4);
	});

	test('companyName() and legalSuffixLength()', () => {
		assert.equal(M.companyName('Modra Vila d.o.o.'), 'Modra Vila');
		assert.equal(M.companyName('ACME, Inc.'), 'ACME');
		assert.equal(M.companyName('ACME'), '');
		assert.equal(M.companyName('GmbH'), '');
		assert.equal(M.companyName(7), '');
		assert.equal(M.legalSuffixLength('ACME GmbH', 4), 5);
		assert.equal(M.legalSuffixLength('ACME\nGmbH', 4), 0);
	});
});

describe('set helpers', () => {
	test('revealTable: live main, sub-keys and aliases; nothing for tombstones', () => {
		assert.deepEqual(M.revealTable(E1()), {
			PERSON_a7k2q: 'Luka Zupan',
			PERSON_a7k2q_NAME: 'Luka',
			PERSON_a7k2q_SURNAME: 'Zupan',
			CUSTOM_h3k9d: 'Mr. Zupan',
		});
	});

	test('revealTable: a renamed key keeps revealing through its alias', () => {
		const s = state({
			ids: [rec('Luka Zupan', 'CLIENT_a7k2q', 'PERSON')],
			aliases: { PERSON_a7k2q: { value: 'Luka Zupan', owner: 'CLIENT_a7k2q' } },
			used: ['PERSON_a7k2q', 'CLIENT_a7k2q'],
		});
		assert.deepEqual(M.revealTable(s), {
			CLIENT_a7k2q: 'Luka Zupan',
			PERSON_a7k2q: 'Luka Zupan',
		});
	});

	test('revealTable of a masked set is empty', () => {
		assert.deepEqual(M.revealTable({ ...E1(), numbering: 'typed', aliases: {} }), {});
		assert.deepEqual(M.revealTable({ ...E1(), numbering: 'redacted', aliases: {} }), {});
	});

	test('displayPlaceholder in all four modes', () => {
		const s = state({
			ids: [rec('ana@x.si', 'EMAIL_x7gs2', 'EMAIL_ADDRESS')],
			used: ['EMAIL_x7gs2'],
		});
		assert.equal(M.displayPlaceholder(s, 'EMAIL_x7gs2'), '[EMAIL_x7gs2]');
		assert.equal(
			M.displayPlaceholder({ ...s, numbering: 'sequential' }, 'EMAIL_x7gs2'),
			'[EMAIL_x7gs2]',
		);
		assert.equal(M.displayPlaceholder({ ...s, numbering: 'typed' }, 'EMAIL_x7gs2'), '[EMAIL]');
		assert.equal(
			M.displayPlaceholder({ ...s, numbering: 'redacted' }, 'EMAIL_x7gs2'),
			'[REDACTED]',
		);
		assert.equal(
			M.displayPlaceholder({ ...E1(), numbering: 'typed' }, 'PERSON_a7k2q_NAME'),
			'[PERSON]',
		);
		assert.equal(M.displayPlaceholder({ ...E1(), numbering: 'typed' }, 'CUSTOM_h3k9d'), '[PERSON]');
	});

	test('ownKeys: used ∪ live ∪ sub-keys ∪ aliases', () => {
		const s = { ...E1(), used: ['CUSTOM_q1w2e'] };
		assert.deepEqual([...M.ownKeys(s)].sort(), [
			'CUSTOM_h3k9d',
			'CUSTOM_q1w2e',
			'PERSON_a7k2q',
			'PERSON_a7k2q_NAME',
			'PERSON_a7k2q_SURNAME',
		]);
		assert.deepEqual([...M.liveKeys(E1())], ['PERSON_a7k2q']);
	});
});

describe('fromV1', () => {
	test('sub-key rule, types from keys, newest first', () => {
		assert.deepEqual(
			M.fromV1(
				{
					table: { CLIENT: 'Acme', CLIENT_NAME: 'Acme d.o.o.', EMAIL_ADDRESS_1: 'a@b.si' },
					mine: ['CLIENT'],
					used: ['GONE'],
				},
				'random',
			),
			{
				numbering: 'random',
				ids: [
					rec('a@b.si', 'EMAIL_ADDRESS_1', 'EMAIL_ADDRESS'),
					rec('Acme d.o.o.', 'CLIENT_NAME', 'CUSTOM'),
					rec('Acme', 'CLIENT', 'CUSTOM', { mine: true }),
				],
				subKeys: {},
				aliases: {},
				used: ['GONE', 'CLIENT', 'CLIENT_NAME', 'EMAIL_ADDRESS_1'],
			},
		);
	});

	test('a found PERSON keeps its name parts; a hand-added one does not', () => {
		const table = {
			PERSON_a7k2q: 'Ana Novak',
			PERSON_a7k2q_NAME: 'Ana',
			PERSON_a7k2q_SURNAME: 'Novak',
			PERSON_mine1: 'Bo Kos',
			PERSON_mine1_NAME: 'Bo',
		};
		const set = M.fromV1({ table, mine: ['PERSON_mine1'], used: [] }, 'sequential');
		assert.deepEqual(set.subKeys, {
			PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Ana', rec: 'Ana Novak' },
			PERSON_a7k2q_SURNAME: { of: 'PERSON_a7k2q', value: 'Novak', rec: 'Ana Novak' },
		});
		assert.deepEqual(
			set.ids.map((r) => [r.key, r.type, r.mine]),
			[
				['PERSON_mine1_NAME', 'CUSTOM', false],
				['PERSON_mine1', 'PERSON', true],
				['PERSON_a7k2q', 'PERSON', false],
			],
		);
		assert.deepEqual(M.revealTable(set), table);
	});

	test('values are trimmed; blank values are tombstones (used only)', () => {
		const set = M.fromV1({ table: { CASE_1: '  K101 ', GONE_1: '  ' }, used: ['OLD_2'] }, 'random');
		// CASE_1 parses as TYPE_suffix, so its type is CASE (flatTypeFromKey; the extension: CUSTOM).
		assert.deepEqual(set.ids, [rec('K101', 'CASE_1', 'CASE')]);
		assert.deepEqual(set.used, ['OLD_2', 'CASE_1', 'GONE_1']);
	});

	test('deviation: a value under two keys keeps the first key; the second becomes an alias', () => {
		const set = M.fromV1(
			{ table: { PERSON_1: 'Ana', CUSTOM_7: 'Ana', PERSON_2: 'Bo' } },
			'sequential',
		);
		assert.deepEqual(
			set.ids.map((r) => r.key),
			['PERSON_2', 'PERSON_1'],
		);
		assert.deepEqual(set.aliases, { CUSTOM_7: { value: 'Ana', owner: 'PERSON_1' } });
		assert.deepEqual(M.revealTable(set), { PERSON_1: 'Ana', CUSTOM_7: 'Ana', PERSON_2: 'Bo' });
	});

	test('deviation: a name part of a person who is an alias is its own record, so it is protected', () => {
		const set = M.fromV1(
			{ table: { CUSTOM_1: 'Ana Novak', PERSON_2: 'Ana Novak', PERSON_2_NAME: 'Ana' } },
			'random',
		);
		assert.deepEqual(set.subKeys, {});
		assert.deepEqual(set.aliases, { PERSON_2: { value: 'Ana Novak', owner: 'CUSTOM_1' } });
		assert.deepEqual(
			set.ids.map((r) => [r.key, r.value, r.type]),
			[
				['PERSON_2_NAME', 'Ana', 'PERSON'],
				['CUSTOM_1', 'Ana Novak', 'CUSTOM'],
			],
		);
		assert.deepEqual(M.revealTable(set), {
			CUSTOM_1: 'Ana Novak',
			PERSON_2: 'Ana Novak',
			PERSON_2_NAME: 'Ana',
		});
		assert.deepEqual(M.fromV1({ table: { CUSTOM_1: 'A', PERSON_2: 'A' } }, 'typed').aliases, {});
	});

	test('a name part of an aliased PERSON joins the PERSON record holding its value', () => {
		const set = M.fromV1(
			{
				table: {
					PERSON_1: 'Janez Novak',
					PERSON_2: 'Janez Novak',
					PERSON_2_NAME: 'Janez',
					PERSON_2_SURNAME: 'Novak',
				},
			},
			'redacted',
		);
		assert.deepEqual(set.subKeys, {
			PERSON_2_NAME: { of: 'PERSON_1', value: 'Janez', rec: 'Janez Novak' },
			PERSON_2_SURNAME: { of: 'PERSON_1', value: 'Novak', rec: 'Janez Novak' },
		});
		assert.deepEqual(set.aliases, {}); // masked: only the full-name alias is dropped
	});

	test('a key with name parts is a PERSON whatever its suffix; a part repeating a record value is an alias', () => {
		const set = M.fromV1(
			{
				table: {
					PERSON_CEO: 'Janez Novak',
					PERSON_CEO_NAME: 'Janez',
					PERSON_CEO_SURNAME: 'Novak',
					PERSON_X: 'Ana',
					PERSON_Y: '',
					PERSON_Y_NAME: 'Ana',
					PERSON_Y_SURNAME: 'Kos',
				},
			},
			'random',
		);
		assert.deepEqual(
			set.ids.map((r) => [r.key, r.type]),
			[
				['PERSON_Y_SURNAME', 'PERSON'],
				['PERSON_X', 'CUSTOM'],
				['PERSON_CEO', 'PERSON'],
			],
		);
		assert.deepEqual(Object.keys(set.subKeys), ['PERSON_CEO_NAME', 'PERSON_CEO_SURNAME']);
		assert.deepEqual(set.aliases, { PERSON_Y_NAME: { value: 'Ana', owner: 'PERSON_X' } });
	});

	test('deviation: a TYPE_suffix key keeps any entity type code as its type', () => {
		const set = M.fromV1(
			{
				table: {
					IT_FISCAL_CODE_0u1qg: 'RSSMRA85T10A562S',
					SOCIAL_HANDLE_1: '@janez_n',
					EMAIL_x7gs2: 'a@b.si',
					CLIENT: 'Acme',
				},
			},
			'random',
		);
		assert.deepEqual(
			set.ids.map((r) => [r.key, r.type]),
			[
				['CLIENT', 'CUSTOM'],
				['EMAIL_x7gs2', 'EMAIL_ADDRESS'],
				['SOCIAL_HANDLE_1', 'SOCIAL_HANDLE'],
				['IT_FISCAL_CODE_0u1qg', 'IT_FISCAL_CODE'],
			],
		);
		assert.equal(M.flatTypeFromKey('IBAN_CODE_3'), 'IBAN');
		assert.equal(M.flatTypeFromKey('PERSON_CEO'), 'CUSTOM');
	});

	test('invalid keys and non-string values are ignored', () => {
		const set = M.fromV1({ table: { 'bad key': 'x', CASE_1: 7, OK_1: 'y' } }, 'random');
		assert.deepEqual(
			set.ids.map((r) => r.key),
			['OK_1'],
		);
		assert.deepEqual(set.used, ['CASE_1', 'OK_1']); // every valid table key counts as used
	});
});

describe('extraBlockTest', () => {
	test('blocks every own placeholder plus foreign-minted ones of any type code', () => {
		const block = M.extraBlockTest(M.emptyContent('random'));
		const own = M.ownPlaceholderTest(M.emptyContent('random'));
		for (const token of [
			'[SOCIAL_HANDLE_1]',
			'[IT_FISCAL_CODE_a1b2c]',
			'[NL_BSN_123456789]',
			'[PERSON_1]',
			'[PERSON_ab12c_SURNAME]',
		]) {
			assert.equal(block(token), true, token);
		}
		assert.equal(own('[SOCIAL_HANDLE_1]'), false); // gateway spans keep the extension's test
		for (const token of [
			'[SOCIAL_HANDLE_abcde]', // no digit: may be a word
			'[ITEM_1_NAME]', // name parts only for PERSON
			'[ITEM_1234567890]',
			'[item_1]',
			'SOCIAL_HANDLE_1',
		]) {
			assert.equal(block(token), false, token);
		}
	});
});

describe('ownPlaceholderTest', () => {
	test("accepts only this set's keys (and masked labels in a masked set)", () => {
		const s = {
			...M.emptyContent('random'),
			ids: [rec('Acme', 'CLIENT', 'CUSTOM'), rec('Ana', 'PERSON_a7k2q', 'PERSON')],
			subKeys: { PERSON_a7k2q_NAME: { of: 'PERSON_a7k2q', value: 'Ana', rec: 'Ana' } },
			aliases: { OLD_KEY: { value: 'Acme', owner: 'CLIENT' } },
			used: ['CLIENT', 'PERSON_a7k2q', 'PERSON_a7k2q_NAME', 'GONE', 'US_SSN_2', 'OLD_KEY'],
		};
		const own = M.ownPlaceholderTest(s);
		for (const token of [
			'[PERSON_a7k2q]',
			'[PERSON_a7k2q_NAME]',
			'[US_SSN_2]',
			'[CLIENT]',
			'[GONE]',
			'[OLD_KEY]',
		]) {
			assert.equal(own(token), true, token);
		}
		for (const token of [
			'[PERSON_maria]',
			'[LOCATION_tokyo]',
			'[PERSON]',
			'[PII]',
			'[REDACTED]',
			'[Luka]',
			'[K101]',
			'[1]',
			'[client]',
			'CLIENT',
			'[CLIENT',
			'[]',
			'[toString]',
			'[constructor]',
		]) {
			assert.equal(own(token), false, token);
		}
		const empty = M.ownPlaceholderTest(M.emptyContent('random'));
		for (const token of [
			'[PERSON_1]',
			'[PERSON_123456789]',
			'[PERSON_a7k2q]',
			'[PERSON_12345]',
			'[EMAIL_ADDRESS_ab12c]',
			'[US_SSN_2]',
			'[IBAN_CODE_x9yyy]',
			'[PERSON_a7k2q_NAME]',
			'[PERSON_3_SURNAME]',
			'[CUSTOM_4]',
			'[PII_0abcd]',
			'[EMAIL_x7gs2]',
			'[PHONE_1]',
			'[COMPANY_ab1cd]',
			'[AMOUNT_2]',
			'[NUMBER_3]',
		]) {
			assert.equal(empty(token), true, token);
		}
		for (const token of [
			'[PERSON_maria]',
			'[PERSON_janez]',
			'[LOCATION_tokyo]',
			'[PERSON_1234567890]',
			'[PERSON_A7K2Q]',
			'[PERSON_a7k2]',
			'[PERSON_a7k2qx]',
			'[NL_BSN_ab12c]',
			'[ACME_1]',
			'[LOCATION_ab12c_NAME]',
			'[PERSON_]',
		]) {
			assert.equal(empty(token), false, token);
		}
		for (const mode of ['typed', 'redacted']) {
			const masked = M.ownPlaceholderTest({ ...s, aliases: {}, numbering: mode });
			for (const token of [
				'[PERSON]',
				'[PII]',
				'[CUSTOM]',
				'[REDACTED]',
				'[CLIENT]',
				'[EMAIL]',
				'[COMPANY]',
			]) {
				assert.equal(masked(token), true, token);
			}
			for (const token of ['[PERSON_maria]', '[NL_BSN]', '[ACME]', '[redacted]']) {
				assert.equal(masked(token), false, token);
			}
		}
	});
});

describe('companySpans', () => {
	for (const form of M.LEGAL_FORMS) {
		test(`recognises ${form} after a detected name`, () => {
			const text = `We met ACME Holding ${form} yesterday.`;
			const spans = M.companySpans(M.emptyContent('random'), text, [
				at(text, 'ACME Holding', 'PERSON'),
			]);
			assert.equal(spans.length, 1);
			assert.equal(spans[0].entity_type, 'COMPANY');
			assert.equal(text.slice(spans[0].start, spans[0].end), `ACME Holding ${form}`);
			assert.equal(M.guessType(`ACME Holding ${form}`), 'COMPANY');
		});
	}

	for (const [name, text, value, expected] of [
		['comma', 'ACME, Inc. signed.', 'ACME', 'ACME, Inc.'],
		['tab', 'ACME\tGmbH signed.', 'ACME', 'ACME\tGmbH'],
		['several spaces', 'ACME   LLC signed.', 'ACME', 'ACME   LLC'],
		['Slovene form in capitals', 'Modra Vila D.O.O. signed.', 'Modra Vila', 'Modra Vila D.O.O.'],
		['Polish form', 'Kowalski z.o.o. signed.', 'Kowalski', 'Kowalski z.o.o.'],
		['at the end of the text', 'Signed by ACME Ltd', 'ACME', 'ACME Ltd'],
		['dotted form at the end of a sentence', 'Signed by ACME Ltd.', 'ACME', 'ACME Ltd.'],
		['Italian forms', 'Rossi S.p.A. signed.', 'Rossi', 'Rossi S.p.A.'],
	]) {
		test(`extends the span: ${name}`, () => {
			const [span] = M.companySpans(M.emptyContent('random'), text, [at(text, value, 'PERSON')]);
			assert.equal(span.entity_type, 'COMPANY');
			assert.equal(text.slice(span.start, span.end), expected);
		});
	}

	test('a LOCATION followed by a legal form is a COMPANY too', () => {
		const text = 'Ljubljana d.d. reported.';
		const [span] = M.companySpans(M.emptyContent('random'), text, [
			at(text, 'Ljubljana', 'LOCATION'),
		]);
		assert.deepEqual(
			[span.entity_type, span.start, span.end],
			['COMPANY', 0, 'Ljubljana d.d.'.length],
		);
	});

	test('a detected span with trailing whitespace is trimmed before the form is looked for', () => {
		const text = 'Modra Vila d.o.o. signed.';
		const [span] = M.companySpans(M.emptyContent('random'), text, [
			{ entity_type: 'PERSON', start: 0, end: 11 },
		]);
		assert.equal(text.slice(span.start, span.end), 'Modra Vila d.o.o.');
	});

	for (const [name, text, value] of [
		['a line break before the form', 'Modra Vila\nd.o.o. signed.', 'Modra Vila'],
		['a missing final dot', 'Modra Vila d.o.o signed.', 'Modra Vila'],
		['a longer word', 'ACME Incorporated signed.', 'ACME'],
		['letters after the form', 'ACME Ltdx signed.', 'ACME'],
		['the form glued to the name', 'ACMEGmbH signed.', 'ACMEGmbH'],
		['an exact form in the wrong case', 'ACME gmbh signed.', 'ACME'],
		['AG in lower case', 'Hans ag signed.', 'Hans'],
		['a dot form spelled without dots', 'Rossi SpA signed.', 'Rossi'],
		['no space before the form', 'ACME,Inc. signed.', 'ACME'],
	]) {
		test(`leaves PERSON alone with ${name}`, () => {
			const [span] = M.companySpans(M.emptyContent('random'), text, [at(text, value, 'PERSON')]);
			assert.equal(span.entity_type, 'PERSON');
			assert.equal(text.slice(span.start, span.end), value);
		});
	}

	test('other types are never turned into a company', () => {
		const text = 'Mail acme@x.si GmbH and 123 Ltd';
		const spans = [at(text, 'acme@x.si', 'EMAIL_ADDRESS'), at(text, '123', 'NUMBER')];
		assert.deepEqual(M.companySpans(M.emptyContent('random'), text, spans), spans);
	});

	test('only the exact bare name becomes a COMPANY, not a part of it or another name', () => {
		const text = 'Modra Vila d.o.o. and Modra and Modra Vilas and Modra Vila.';
		const spans = M.companySpans(M.emptyContent('random'), text, [
			at(text, 'Modra Vila', 'PERSON', 0),
			at(text, 'Modra', 'PERSON', 1),
			at(text, 'Modra Vilas', 'PERSON'),
			at(text, 'Modra Vila', 'PERSON', 2),
		]);
		assert.deepEqual(
			spans.map((s) => [text.slice(s.start, s.end), s.entity_type]),
			[
				['Modra Vila d.o.o.', 'COMPANY'],
				['Modra', 'PERSON'],
				['Modra Vilas', 'PERSON'],
				['Modra Vila', 'COMPANY'],
			],
		);
	});

	test('the bare name of a COMPANY already in the set becomes a COMPANY', () => {
		const s = state({ ids: [rec('Modra Vila d.o.o.', 'COMPANY_x1', 'COMPANY')] });
		const text = 'Modra Vila starts.';
		assert.equal(
			M.companySpans(s, text, [at(text, 'Modra Vila', 'PERSON')])[0].entity_type,
			'COMPANY',
		);
	});

	test('malformed spans pass through untouched', () => {
		const text = 'ACME d.o.o.';
		const bad = [
			{ entity_type: 'PERSON', start: 'x', end: 4 },
			{ entity_type: 'PERSON', start: 3, end: 99 },
		];
		assert.deepEqual(M.companySpans(M.emptyContent('random'), text, bad), bad);
		assert.deepEqual(M.companySpans(M.emptyContent('random'), text, null), []);
	});
});

describe(
	'parity with the extension lib/id-model.js, id-rules.js, id-names.js',
	{ skip: SKIP_EXT },
	() => {
		test('KNOWN_TYPES, TYPES, PREFIXES, LEGAL_FORMS and PLACEHOLDER_TYPES match', () => {
			const ext = loadExt();
			assert.deepEqual([...M.KNOWN_TYPES], plain(ext.anonIdModel.KNOWN_TYPES));
			assert.deepEqual([...M.KNOWN_TYPES], plain(ext.IdRules.PLACEHOLDER_TYPES));
			assert.deepEqual(plain(M.TYPES), plain(ext.anonIdModel.TYPES));
			assert.deepEqual(plain(M.PREFIXES), plain(ext.anonIdModel.PREFIXES));
			assert.deepEqual([...M.LEGAL_FORMS], plain(ext.anonIdModel.LEGAL_FORMS));
			assert.equal(String(M.FOREIGN_MINTED_RE), String(ext.IdRules.FOREIGN_MINTED_RE));
		});

		test('guessType, typeFromKey, namePart, companyName agree', () => {
			const ext = loadExt();
			for (const value of [
				'luka.zupan@modravila.si',
				'SI56 2900 0001 2345 6789',
				'Modra Vila d.o.o.',
				'Hans Ag',
				'Acme ltd',
				'4.800 EUR',
				'€ 120',
				'+386 41 123 456',
				'9-10-24',
				'4.800',
				'K101',
				'',
				'  ACME, Inc. ',
				'EMAIL_ADDRESS_x7gs2',
				'IBAN_CODE_1',
				'PERSON_1_NAME',
				'CLIENT',
				'NL_BSN_ab12c',
			]) {
				assert.equal(M.guessType(value), ext.anonIdModel.guessType(value), value);
				assert.equal(M.typeFromKey(value), ext.anonIdModel.typeFromKey(value), value);
				assert.equal(M.namePart(value), ext.anonIdModel.namePart(value), value);
				assert.equal(M.companyName(value), ext.anonIdModel.companyName(value), value);
			}
		});

		test('fromV1 agrees with anonIdModel.normalize of a v1 state (no duplicate values)', () => {
			const ext = loadExt();
			const cases = [
				{
					table: { CLIENT: 'Acme', CLIENT_NAME: 'Acme d.o.o.', EMAIL_ADDRESS_1: 'a@b.si' },
					mine: ['CLIENT'],
					used: ['GONE'],
				},
				{
					table: {
						PERSON_a7k2q: 'Ana Novak',
						PERSON_a7k2q_NAME: 'Ana',
						PERSON_a7k2q_SURNAME: 'Novak',
						PERSON_mine1: 'Bo Kos',
						PERSON_mine1_NAME: 'Bo',
						IBAN_CODE_3: 'SI56 1910 0000 0123 438',
					},
					mine: ['PERSON_mine1'],
					used: ['PERSON_9', 'bad key'],
				},
				{ table: { CASE_1: '  K101 ', GONE_1: '  ', 'bad key': 'x', N_1: 7 }, used: ['OLD_2'] },
				{
					table: { PERSON_1: ' Ana Novak ', PERSON_1_NAME: 'Ana', PERSON_1_SURNAME: '' },
					used: [],
				},
			];
			for (const numbering of ['random', 'sequential', 'typed', 'redacted']) {
				for (const flat of cases) {
					const mine = M.fromV1(flat, numbering);
					const theirs = ext.anonIdModel.normalize({ ...plain(flat), numbering });
					// Deliberate deviation: a TYPE_suffix key keeps its TYPE (CASE_1 → CASE, not CUSTOM).
					const ids = theirs.ids.map((r) =>
						r.type === 'CUSTOM' ? { ...r, type: M.flatTypeFromKey(r.key) } : r,
					);
					assert.deepEqual(
						plain(mine),
						plain({
							numbering: theirs.numbering,
							ids,
							subKeys: theirs.subKeys,
							aliases: theirs.aliases,
							used: theirs.used,
						}),
						JSON.stringify({ flat, numbering }),
					);
				}
			}
		});

		test('ownPlaceholderTest agrees on generated tokens', () => {
			const ext = loadExt();
			const rnd = prng(99);
			const pieces = ['PERSON', 'EMAIL', 'US_SSN', 'NL_BSN', 'CLIENT', 'ACME', 'PII', 'REDACTED'];
			const suffixes = [
				'',
				'_1',
				'_a7k2q',
				'_maria',
				'_12345',
				'_1234567890',
				'_ab12c_NAME',
				'_3_SURNAME',
			];
			for (const numbering of ['random', 'sequential', 'typed', 'redacted']) {
				const s = {
					...E1(),
					numbering,
					aliases: numbering === 'typed' || numbering === 'redacted' ? {} : E1().aliases,
				};
				const mine = M.ownPlaceholderTest(s);
				const theirs = ext.IdRules.ownPlaceholderTest({ ...ext.anonIdModel.empty(), ...plain(s) });
				for (let i = 0; i < 300; i++) {
					const token = `[${pieces[rnd(pieces.length)]}${suffixes[rnd(suffixes.length)]}]`;
					assert.equal(mine(token), theirs(token), `${numbering} ${token}`);
				}
			}
		});

		test('companySpans agrees on generated spans', () => {
			const ext = loadExt();
			const rnd = prng(2026);
			const text =
				'Modra Vila d.o.o. and Modra Vila, ACME, Inc. met Ljubljana d.d. and Hans ag.\nRossi S.p.A.';
			const set = state({ ids: [rec('ACME, Inc.', 'COMPANY_1', 'COMPANY')] });
			for (let i = 0; i < 300; i++) {
				const spans = [];
				for (let j = 0; j < 1 + rnd(5); j++) {
					const start = rnd(text.length);
					spans.push({
						entity_type: ['PERSON', 'LOCATION', 'EMAIL_ADDRESS'][rnd(3)],
						start,
						end: start + 1 + rnd(14),
						score: 0.5,
					});
				}
				assert.deepEqual(
					plain(M.companySpans(set, text, spans)),
					plain(
						ext.anonIdNames.companySpans(
							{ ...ext.anonIdModel.empty(), ...plain(set) },
							text,
							plain(spans),
						),
					),
				);
			}
		});
	},
);
