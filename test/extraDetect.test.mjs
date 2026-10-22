// Port of the extension's tests/extra-detect.test.js against dist/, plus differential checks that
// run the extension's real lib/extra-detect.js (node:vm) on the same inputs. Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { loadExt, plain, prng, SKIP_EXT } from './engine-ext.mjs';

const require = createRequire(import.meta.url);
const X = require('../dist/nodes/Anonymizator/shared/extraDetect.js');

const NBSP = '\u00A0';
const NNBSP = '\u202F';
const ALL = { NUMBER: true, AMOUNT: true, COMPANY: true };
const ONLY = (type) => ({ [type]: true });

/** "TYPE:text" for every span, in order. */
const found = (text, options = ALL, context) =>
	X.extraSpans(text, options, context).map((s) => `${s.entity_type}:${text.slice(s.start, s.end)}`);
const values = (text, type) =>
	X.extraSpans(text, ONLY(type)).map((s) => text.slice(s.start, s.end));

describe('extraSpans basics', () => {
	test('the three options', () => {
		assert.deepEqual(X.EXTRA_OPTIONS, ['NUMBER', 'AMOUNT', 'COMPANY']);
	});

	test('normalizeExtraOptions: missing or non-boolean is false', () => {
		const off = { NUMBER: false, AMOUNT: false, COMPANY: false };
		assert.deepEqual(X.normalizeExtraOptions(undefined), off);
		assert.deepEqual(X.normalizeExtraOptions(null), off);
		assert.deepEqual(X.normalizeExtraOptions([true]), off);
		assert.deepEqual(
			X.normalizeExtraOptions({ NUMBER: true, AMOUNT: 'yes', COMPANY: 1, OTHER: true }),
			{ NUMBER: true, AMOUNT: false, COMPANY: false },
		);
	});

	test('all options off (or none given) finds nothing', () => {
		const text = 'Modra Vila d.o.o. owes 4.800 EUR for K101';
		assert.deepEqual(X.extraSpans(text, {}), []);
		assert.deepEqual(X.extraSpans(text, undefined), []);
		assert.deepEqual(X.extraSpans(text, { NUMBER: false, AMOUNT: false, COMPANY: false }), []);
		assert.deepEqual(X.extraSpans('', ALL), []);
	});

	test('spans are sorted, do not overlap, score 1, and offsets are UTF-16', () => {
		const text = '😀 Modra Vila d.o.o. paid 4.800 EUR on 15.5.2026 for K101.';
		const spans = X.extraSpans(text, ALL);
		for (let i = 1; i < spans.length; i++) assert.ok(spans[i].start >= spans[i - 1].end);
		for (const s of spans) assert.equal(s.score, 1);
		assert.deepEqual(found(text), [
			'COMPANY:Modra Vila d.o.o.',
			'AMOUNT:4.800 EUR',
			'NUMBER:15.5.2026',
			'NUMBER:K101',
		]);
	});
});

describe('NUMBER: every token that holds a digit', () => {
	for (const token of [
		'1.000',
		'4.800,00',
		'0,5',
		'2026',
		'2024-10-09',
		'2024-10-09T10:00',
		'15/2026',
		'041-123-456',
		'K101',
		'K-101',
		'K101/2024',
		'INV-2024-118',
		'AB-123-45',
		'5-letni',
		'v2.1',
		'COVID-19',
		'A4',
		'H2O',
		'1st',
		'4.800,00kg',
		`1${NBSP}000`,
		`1${NNBSP}000`,
		"1'000",
		'12:30',
		'a\u20101',
	]) {
		test(`${JSON.stringify(token)} is one whole span`, () => {
			assert.deepEqual(values(`see ${token} here`, 'NUMBER'), [token]);
		});
	}

	test('a sentence-final dot, comma or colon stays outside', () => {
		assert.deepEqual(values('on 15.5.2026.', 'NUMBER'), ['15.5.2026']);
		assert.deepEqual(values('case 15/2026, then', 'NUMBER'), ['15/2026']);
		assert.deepEqual(values('number 7: done', 'NUMBER'), ['7']);
	});

	test('the 5 in "člen 5" and the 10 in "10 %"', () => {
		assert.deepEqual(values('člen 5 in 10 %', 'NUMBER'), ['5', '10']);
	});

	test('a plain space splits: "1 000" is two spans', () => {
		assert.deepEqual(values('1 000', 'NUMBER'), ['1', '000']);
	});

	test('a leading sign stays outside', () => {
		assert.deepEqual(values('-5 and +386', 'NUMBER'), ['5', '386']);
	});

	test('_ @ [ ] end a token; letter-only words never match', () => {
		assert.deepEqual(values('abc_12 x@9 [K7] word Ljubljana', 'NUMBER'), ['12', '9', 'K7']);
		assert.deepEqual(values('Luka Zupan, Ljubljana.', 'NUMBER'), []);
	});

	test('known side effect: in info@acme2.si the token acme2.si matches', () => {
		assert.deepEqual(values('info@acme2.si', 'NUMBER'), ['acme2.si']);
	});

	test('never inside an own placeholder: an intersecting token is dropped whole', () => {
		const own = (t) => t === '[PERSON_1]' || t === '[PERSON_a7k2q]';
		const text = 'x [PERSON_1] y [PERSON_a7k2q] z [K101] 12';
		assert.deepEqual(found(text, ONLY('NUMBER'), { isOwnPlaceholder: own }), [
			'NUMBER:K101',
			'NUMBER:12',
		]);
		assert.ok(found(text, ONLY('NUMBER')).includes('NUMBER:a7k2q'));
	});

	test('brackets end a token: a number next to a placeholder is its own token', () => {
		const own = (t) => t === '[PERSON_1]';
		assert.deepEqual(found('[PERSON_1]x', ONLY('NUMBER'), { isOwnPlaceholder: own }), []);
		assert.deepEqual(found('9[PERSON_1]7', ONLY('NUMBER'), { isOwnPlaceholder: own }), [
			'NUMBER:9',
			'NUMBER:7',
		]);
	});

	test('an AMOUNT inside an own placeholder is dropped whole', () => {
		const own = (t) => t === '[€5]';
		assert.deepEqual(found('[€5] and EUR 5', ONLY('AMOUNT'), { isOwnPlaceholder: own }), [
			'AMOUNT:EUR 5',
		]);
		assert.deepEqual(found('[€5] and EUR 5', ONLY('AMOUNT')), ['AMOUNT:€5', 'AMOUNT:EUR 5']);
	});
});

describe('AMOUNT: a whole numeric run with a currency', () => {
	for (const amount of [
		'4.800,00 EUR',
		'4.800 EUR',
		'EUR 4.800',
		'€4.800,00',
		'4.800 €',
		'$1,250.50',
		'1.250,50 USD',
		'CHF 300',
		'£20',
		'15 EUR',
		`4.800${NBSP}EUR`,
		`€${NBSP}120`,
		'1.000.000 GBP',
	]) {
		test(JSON.stringify(amount), () => {
			assert.deepEqual(values(`Pay ${amount} now`, 'AMOUNT'), [amount]);
		});
	}

	for (const text of [
		'4.800 evrov',
		'eur 50',
		'EURO 5',
		'USDT 5',
		'€',
		'5 %',
		'1250.505 EUR',
		'4.800,00EURO',
		'XEUR 5',
		'5 EURx',
	]) {
		test(`${JSON.stringify(text)} is no amount`, () => {
			assert.deepEqual(values(`a ${text} b`, 'AMOUNT'), []);
		});
	}

	test('a run that fails as a whole is never cut to a part (no backtracking)', () => {
		assert.deepEqual(found('1250.505 EUR', { AMOUNT: true }), []);
		assert.deepEqual(found('1250.505 EUR', ALL), ['NUMBER:1250.505']);
		assert.deepEqual(found('12.5.2026 EUR', ALL), ['NUMBER:12.5.2026']);
	});

	test('neither end touches a letter or digit', () => {
		assert.deepEqual(values('K4.800 EUR', 'AMOUNT'), []);
		assert.deepEqual(values('EUR 4.800x', 'AMOUNT'), []);
	});

	test('wins over NUMBER for its digits', () => {
		assert.deepEqual(found('4.800,00 EUR and 7'), ['AMOUNT:4.800,00 EUR', 'NUMBER:7']);
	});

	test('a currency-first amount at the very start of the text', () => {
		assert.deepEqual(found('€5 due', ONLY('AMOUNT')), ['AMOUNT:€5']);
		assert.equal(X.extraSpans('€5 due', ONLY('AMOUNT'))[0].start, 0);
		assert.deepEqual(values('EUR 4.800 due', 'AMOUNT'), ['EUR 4.800']);
		assert.deepEqual(found('€5 due', ALL), ['AMOUNT:€5']);
	});
});

describe('COMPANY: names with a legal suffix only', () => {
	for (const [text, company] of [
		['Modra Vila d.o.o.', 'Modra Vila d.o.o.'],
		['Triglav, d.d.', 'Triglav, d.d.'],
		['ACME Corporation', 'ACME Corporation'],
		['Novak & Co GmbH', 'Novak & Co GmbH'],
		['3D Tisk d.o.o.', '3D Tisk d.o.o.'],
		['Janez Novak s.p.', 'Janez Novak s.p.'],
		['Podjetje Modra Vila d.o.o.', 'Modra Vila d.o.o.'],
		['The Big Shop Ltd.', 'Big Shop Ltd.'],
		['Modra Vila D.O.O.', 'Modra Vila D.O.O.'],
		['One Two Three Four Five AG', 'Two Three Four Five AG'],
		['case K101. Modra Vila d.o.o. is', 'Modra Vila d.o.o.'],
	]) {
		test(JSON.stringify(text), () => {
			assert.deepEqual(values(text, 'COMPANY'), [company]);
		});
	}

	for (const text of [
		'd.o.o. alone',
		'modra vila d.o.o.',
		'Hans Ag',
		'Modra Vila\nd.o.o.',
		'Modra Vila d.o.o',
		'Firma GmbH',
	]) {
		test(`${JSON.stringify(text)} is no company`, () => {
			assert.deepEqual(values(text, 'COMPANY'), []);
		});
	}

	test('runs first: its digits are not numbers, its amount-like parts not amounts', () => {
		assert.deepEqual(found('3D Tisk d.o.o. and 7'), ['COMPANY:3D Tisk d.o.o.', 'NUMBER:7']);
	});

	test('a name never reaches into a placeholder (brackets end the name)', () => {
		const own = (t) => t === '[PERSON_1]';
		assert.deepEqual(found('[PERSON_1] Vila d.o.o.', ONLY('COMPANY'), { isOwnPlaceholder: own }), [
			'COMPANY:Vila d.o.o.',
		]);
	});
});

describe('mergeExtra', () => {
	const sp = (text, value, type, nth = 0) => {
		let at = -1;
		for (let i = 0; i <= nth; i++) at = text.indexOf(value, at + 1);
		return { entity_type: type, start: at, end: at + value.length, score: 0.9 };
	};
	const show = (text, merged) => ({
		gateway: merged.gateway.map((s) => `${s.entity_type}:${text.slice(s.start, s.end)}`),
		extra: merged.extra.map((s) => `${s.entity_type}:${text.slice(s.start, s.end)}`),
	});

	test('no overlap keeps both; a span wholly inside the extra one is dropped', () => {
		const text = 'We pay Modra Vila d.o.o. and Ana';
		const extra = X.extraSpans(text, ONLY('COMPANY'));
		const merged = X.mergeExtra(
			text,
			[sp(text, 'Modra', 'PERSON'), sp(text, 'Ana', 'PERSON')],
			[],
			extra,
		);
		assert.deepEqual(show(text, merged), {
			gateway: ['PERSON:Ana'],
			extra: ['COMPANY:Modra Vila d.o.o.'],
		});
	});

	test('the same range wins over the extra span (the gateway type is kept)', () => {
		const text = 'Call 041-123-456.';
		const merged = X.mergeExtra(
			text,
			[sp(text, '041-123-456', 'PHONE_NUMBER')],
			[],
			X.extraSpans(text, ONLY('NUMBER')),
		);
		assert.deepEqual(show(text, merged), { gateway: ['PHONE_NUMBER:041-123-456'], extra: [] });
	});

	test('a crossing span wins and the outside pieces are kept, trimmed', () => {
		const text = 'Ana K-101 here';
		const merged = X.mergeExtra(
			text,
			[sp(text, 'Ana K', 'PERSON')],
			[],
			X.extraSpans(text, ONLY('NUMBER')),
		);
		assert.deepEqual(show(text, merged), { gateway: ['PERSON:Ana K'], extra: ['NUMBER:101'] });
	});

	test('a table match inside the extra span is not dropped from the gateway list', () => {
		const text = 'It costs 1.000 and 1.';
		const merged = X.mergeExtra(
			text,
			[],
			[{ entity_type: 'CUSTOM', start: 9, end: 10, score: 1 }],
			X.extraSpans(text, ONLY('NUMBER')),
		);
		assert.deepEqual(show(text, merged), { gateway: [], extra: ['NUMBER:1.000', 'NUMBER:1'] });
	});
});

describe('parity with the extension lib/extra-detect.js', { skip: SKIP_EXT }, () => {
	const FRAGMENTS = [
		'Modra Vila d.o.o.',
		'The Big Shop Ltd.',
		'Novak & Co GmbH',
		'4.800,00 EUR',
		'EUR 4.800',
		'€5',
		'$1,250.50',
		'1250.505 EUR',
		'15.5.2026',
		'K101',
		'INV-2024-118',
		`1${NBSP}000`,
		'Luka Zupan',
		'[PERSON_1]',
		'[PERSON_a7k2q]',
		'😀',
		'člen 5',
		'info@acme2.si',
		'Triglav, d.d.',
		'\n',
		'-5',
		'K.',
		"1'000",
		'a\u20101',
	];

	test('extraSpans: identical spans on generated texts', () => {
		const ext = loadExt(['lib/anonymizer.js', 'lib/id-model.js', 'lib/extra-detect.js']);
		const rnd = prng(4242);
		const own = (t) => t === '[PERSON_1]' || t === '[PERSON_a7k2q]';
		const texts = new Set();
		const separators = new Set();
		let twoOptions = 0;
		let withOwn = 0;
		for (let round = 0; round < 500; round++) {
			const parts = [];
			for (let i = 0; i < 1 + rnd(8); i++) parts.push(FRAGMENTS[rnd(FRAGMENTS.length)]);
			const sep = [' ', ', ', '', ' and '][rnd(4)];
			const text = parts.join(sep);
			const options = { NUMBER: !!rnd(2), AMOUNT: !!rnd(2), COMPANY: !!rnd(2) };
			const context = rnd(2) ? { isOwnPlaceholder: own } : {};
			texts.add(text);
			separators.add(sep);
			if (Object.values(options).filter(Boolean).length >= 2) twoOptions++;
			if (context.isOwnPlaceholder) withOwn++;
			assert.deepEqual(
				plain(X.extraSpans(text, options, context)),
				plain(ext.anonExtraDetect.spans(text, options, context)),
				JSON.stringify({ text, options }),
			);
		}
		// The corpus must actually vary (a degenerate PRNG once made it 5 distinct texts).
		assert.ok(texts.size > 400, `distinct texts ${texts.size}`);
		assert.equal(separators.size, 4);
		assert.ok(twoOptions > 150, `rounds with two or more options ${twoOptions}`);
		assert.ok(withOwn > 150, `rounds with isOwnPlaceholder ${withOwn}`);
	});

	test('mergeExtra: identical results on generated spans', () => {
		const ext = loadExt(['lib/anonymizer.js', 'lib/id-model.js', 'lib/extra-detect.js']);
		const rnd = prng(777);
		const types = ['PERSON', 'DATE', 'PHONE_NUMBER', 'LOCATION'];
		const texts = new Set();
		let withGateway = 0;
		let withTable = 0;
		for (let round = 0; round < 500; round++) {
			const parts = [];
			for (let i = 0; i < 1 + rnd(6); i++) parts.push(FRAGMENTS[rnd(FRAGMENTS.length)]);
			const text = parts.join(' ');
			const gateway = [];
			for (let i = 0; i < rnd(5); i++) {
				const start = rnd(text.length);
				gateway.push({
					entity_type: types[rnd(types.length)],
					start,
					end: start + 1 + rnd(12),
					score: 0.8,
				});
			}
			const table = [];
			for (let i = 0; i < rnd(3); i++) {
				const start = rnd(text.length);
				table.push({ entity_type: 'CUSTOM', start, end: start + 1 + rnd(6), score: 1 });
			}
			const extra = X.extraSpans(text, ALL);
			const mine = X.mergeExtra(text, gateway, table, extra);
			const theirs = ext.anonExtraDetect.mergeExtra(
				text,
				plain(gateway),
				plain(table),
				plain(extra),
			);
			assert.deepEqual(plain(mine), plain(theirs), JSON.stringify({ text, gateway, table }));
			texts.add(text);
			if (gateway.length > 0) withGateway++;
			if (table.length > 0) withTable++;
		}
		assert.ok(texts.size > 400, `distinct texts ${texts.size}`);
		assert.ok(withGateway > 300, `rounds with gateway spans ${withGateway}`);
		assert.ok(withTable > 250, `rounds with table spans ${withTable}`);
	});
});
