// Round trips of the maps Protect writes (placeholderMap, idFile, a whole output item) back into
// Existing Placeholder Map and Reveal, against dist/: the pipeline must never protect less after a
// round trip, and the node must read what it writes. Never shipped.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const P = require('../dist/nodes/Anonymizator/shared/protectPipeline.js');
const pm = require('../dist/nodes/Anonymizator/shared/placeholderMap.js');
const { revealText } = require('../dist/nodes/Anonymizator/shared/anonymizer.js');

/** The item state the Protect action builds from a parsed map (protect.ts itemState). */
function itemState(parsed, style) {
	if (!parsed.set) {
		return P.fromFlatMap({ table: parsed.table, used: parsed.used, mine: parsed.mine }, style);
	}
	const set = parsed.set;
	const masked = style === 'typed' || style === 'redacted';
	return {
		numbering: style,
		ids: set.ids.map((r) => ({ ...r })),
		subKeys: { ...set.subKeys },
		aliases: masked ? {} : { ...set.aliases },
		used: [...set.used],
	};
}

/** Protect's output placeholderMap (protect.ts outputMap): reveal table plus tombstones as ''. */
function outputMap(state) {
	const table = P.revealTable(state);
	if (state.numbering === 'typed' || state.numbering === 'redacted') return {};
	const map = { ...table };
	for (const key of state.used) if (!(key in map)) map[key] = '';
	return map;
}

const fromInput = (input, style) => itemState(pm.parsePlaceholderMap(input), style);

const STYLES = ['random', 'sequential', 'typed', 'redacted'];

/** A v2 extension ID file with one renamed PERSON row and its name parts. */
const CEO_FILE = {
	format: 'anonymizator-id-file',
	version: 2,
	name: 'ceo',
	numbering: 'random',
	ids: [{ value: 'Janez Novak', placeholder: '[PERSON_CEO]', type: 'PERSON', addedByYou: true }],
	nameParts: [
		{ placeholder: '[PERSON_CEO_NAME]', value: 'Janez', of: '[PERSON_CEO]', from: 'Janez Novak' },
		{
			placeholder: '[PERSON_CEO_SURNAME]',
			value: 'Novak',
			of: '[PERSON_CEO]',
			from: 'Janez Novak',
		},
	],
	revealOnly: [],
	usedPlaceholders: ['[PERSON_CEO]', '[PERSON_CEO_NAME]', '[PERSON_CEO_SURNAME]'],
};

describe('finding 2: name parts of a PERSON whose key has no minted suffix', () => {
	const text = 'Janez said Novak will call. Janez Novak.';

	test("the node's own placeholderMap fed back keeps the name parts protected", () => {
		const first = fromInput(CEO_FILE, 'random');
		const r1 = P.protect(first, text, []);
		assert.equal(r1.text, '[PERSON_CEO_NAME] said [PERSON_CEO_SURNAME] will call. [PERSON_CEO].');
		const second = fromInput(outputMap(first), 'random');
		const r2 = P.protect(second, text, []);
		assert.equal(r2.text, r1.text);
		assert.equal(second.ids.find((r) => r.key === 'PERSON_CEO').type, 'PERSON');
	});

	for (const style of STYLES) {
		test(`a hand-written map protects every value (${style})`, () => {
			const s = fromInput({ PERSON_CEO: 'Janez Novak', PERSON_CEO_SURNAME: 'Novak' }, style);
			const out = P.protect(s, text, []).text;
			assert.ok(!out.includes('Novak'), out);
		});

		test(`a merged map with one value under two keys protects the name parts (${style})`, () => {
			const s = fromInput(
				{
					CLIENT: 'Ana Novak',
					PERSON_1: 'Ana Novak',
					PERSON_1_NAME: 'Ana',
					PERSON_1_SURNAME: 'Novak',
				},
				style,
			);
			const out = P.protect(s, 'Ana Novak wrote. Ana and Novak.', []).text;
			assert.ok(!/Ana|Novak/.test(out), out);
		});
	}
});

describe('finding 14: name parts of a person whose full name sits under an earlier key', () => {
	for (const style of STYLES) {
		test(`every listed value is replaced (${style})`, () => {
			const s = fromInput(
				{
					PERSON_1: 'Janez Novak',
					PERSON_2: 'Janez Novak',
					PERSON_2_NAME: 'Janez',
					PERSON_2_SURNAME: 'Novak',
				},
				style,
			);
			const out = P.protect(s, 'Janez Novak; Novak; Janez', []).text;
			assert.ok(!/Janez|Novak/.test(out), out);
		});

		test(`a part of a non-PERSON duplicate is still replaced (${style})`, () => {
			const s = fromInput(
				{ PERSON_1: 'Acme', PERSON_aaaaa: 'Acme', PERSON_aaaaa_SURNAME: 'Novak' },
				style,
			);
			const out = P.protect(s, 'Acme; Novak', []).text;
			assert.ok(!/Acme|Novak/.test(out), out);
		});
	}

	test('unmasked: every key still reveals, and the set is a valid ID file', () => {
		const map = {
			PERSON_1: 'Janez Novak',
			PERSON_2: 'Janez Novak',
			PERSON_2_NAME: 'Janez',
			PERSON_2_SURNAME: 'Novak',
		};
		const s = fromInput(map, 'sequential');
		const out = P.protect(s, 'Janez Novak; Novak; Janez', []).text;
		assert.equal(out, '[PERSON_1]; [PERSON_2_SURNAME]; [PERSON_2_NAME]');
		assert.deepEqual(P.revealTable(s), map);
		assert.equal(revealText(out, P.revealTable(s)), 'Janez Novak; Novak; Janez');
		assert.doesNotThrow(() => pm.toIdFile(s));
	});
});

describe('finding 29: server-only types survive a flat-map round trip', () => {
	const text = 'CF RSSMRA85T10A562S, handle @janez_n';
	const map = { IT_FISCAL_CODE_0u1qg: 'RSSMRA85T10A562S', SOCIAL_HANDLE_o1b30: '@janez_n' };

	test('entityType is the key type, not CUSTOM', () => {
		const r = P.protect(fromInput(map, 'random'), text, []);
		assert.deepEqual(
			r.entities.map((e) => e.entity_type || e.entityType),
			['IT_FISCAL_CODE', 'SOCIAL_HANDLE'],
		);
	});

	test('Type Only prints the type, not [CUSTOM]', () => {
		const r = P.protect(fromInput(map, 'typed'), text, []);
		assert.equal(r.text, 'CF [IT_FISCAL_CODE], handle [SOCIAL_HANDLE]');
	});
});

describe('finding 31: Additionally Protect leaves foreign-minted placeholders of any type alone', () => {
	test('server-type counters and random suffixes stay whole; other numbers are protected', () => {
		const text =
			'Codice [IT_FISCAL_CODE_1], handle [SOCIAL_HANDLE_1], [SOCIAL_HANDLE_a1b2c], invoice 300 EUR';
		const s = P.emptyState('sequential');
		const r = P.protect(s, text, [], { extra: { NUMBER: true } });
		assert.equal(
			r.text,
			'Codice [IT_FISCAL_CODE_1], handle [SOCIAL_HANDLE_1], [SOCIAL_HANDLE_a1b2c], invoice [NUMBER_1] EUR',
		);
		assert.deepEqual(P.revealTable(s), { NUMBER_1: '300' });
	});

	test('a chained Protect with All Numbers keeps the first node reversible', () => {
		const a = P.emptyState('sequential');
		const source = 'Codice RSSMRA85T10A562S, handle @luka_z, invoice 300 EUR';
		const spans = [
			{ entity_type: 'IT_FISCAL_CODE', start: 7, end: 23, score: 0.9 },
			{ entity_type: 'SOCIAL_HANDLE', start: 32, end: 39, score: 0.9 },
		];
		const ra = P.protect(a, source, spans);
		assert.equal(ra.text, 'Codice [IT_FISCAL_CODE_1], handle [SOCIAL_HANDLE_1], invoice 300 EUR');
		const b = P.emptyState('sequential');
		const rb = P.protect(b, ra.text, [], { extra: { NUMBER: true } });
		const merged = { ...P.revealTable(a), ...P.revealTable(b) };
		assert.equal(revealText(rb.text, merged), source);
	});

	test('a word-like token of an unknown type is still not treated as minted by gateway spans', () => {
		// The gateway-span semantics stay the extension's: a server type is no evidence by shape.
		const own = P.ownPlaceholderTest(P.emptyState('random'));
		assert.equal(own('[SOCIAL_HANDLE_1]'), false);
		assert.equal(own('[PERSON_1]'), true);
	});
});

describe('finding 12: a value written in brackets', () => {
	test("Protect's own map with a bracketed value parses for Reveal and Existing Placeholder Map", () => {
		const file = {
			format: 'anonymizator-id-file',
			version: 2,
			name: 'acme',
			numbering: 'random',
			ids: [{ value: '[ACME]', placeholder: '[CUSTOM_ab12c]', type: 'CUSTOM', addedByYou: true }],
		};
		const s = fromInput(file, 'random');
		const r = P.protect(s, 'Project [ACME] for Janez Novak', [
			{ entity_type: 'PERSON', start: 19, end: 30, score: 0.9 },
		]);
		assert.ok(r.text.startsWith('Project [CUSTOM_ab12c] for [PERSON_'), r.text);
		const map = outputMap(s);
		const table = pm.normalizePlaceholderMap(map);
		assert.equal(revealText(r.text, table), 'Project [ACME] for Janez Novak');
		const again = P.protect(fromInput(map, 'random'), 'Project [ACME] for Janez Novak', []);
		assert.equal(again.text, r.text);
	});
});

describe('findings 6 and 16: a whole Protect output item', () => {
	const groupFile = {
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
	};

	test('finding 6: an item with placeholderMap and idFile uses the lossless idFile', () => {
		const first = fromInput(groupFile, 'random');
		const r1 = P.protect(first, 'Mail from J. Novak', []);
		assert.equal(r1.text, 'Mail from [PERSON_aaaaa]');
		const item = {
			protectedText: r1.text,
			placeholderMap: outputMap(first),
			idFile: pm.toIdFile(first),
		};
		const r2 = P.protect(fromInput(item, 'random'), 'Second mail from J. Novak', []);
		assert.equal(r2.text, 'Second mail from [PERSON_aaaaa]');
	});

	test('finding 6: a stale idFile (copied by Include Input Fields) loses to a newer placeholderMap', () => {
		const stale = pm.toIdFile(fromInput(groupFile, 'random'));
		const item = {
			placeholderMap: { PERSON_aaaaa: 'Janez Novak', PERSON_bbbbb: 'Ana Kos' },
			idFile: stale,
		};
		const parsed = pm.parsePlaceholderMap(item);
		assert.equal(parsed.table.PERSON_bbbbb, 'Ana Kos');
		assert.ok(parsed.used.includes('PERSON_bbbbb'));
	});

	test('finding 6: an invalid idFile falls back to the placeholderMap', () => {
		const item = {
			placeholderMap: { PERSON_1: 'Janez Novak' },
			idFile: { format: 'anonymizator-id-file', version: 9 },
		};
		assert.deepEqual({ ...pm.parsePlaceholderMap(item).table }, { PERSON_1: 'Janez Novak' });
	});

	test('finding 16: copied top-level ID file fields lose to the placeholderMap', () => {
		const file = {
			format: 'anonymizator-id-file',
			version: 2,
			name: 'one',
			numbering: 'sequential',
			ids: [{ value: 'Janez Novak', placeholder: '[PERSON_1]', type: 'PERSON', addedByYou: false }],
			usedPlaceholders: ['[PERSON_1]'],
		};
		const p1 = fromInput(file, 'sequential');
		const text1 = 'Janez Novak met Ana Kos';
		const r1 = P.protect(p1, text1, [{ entity_type: 'PERSON', start: 16, end: 23, score: 0.9 }]);
		assert.equal(r1.text, '[PERSON_1] met [PERSON_2]');
		const item = { ...file, protectedText: r1.text, placeholderMap: outputMap(p1) };
		const p2 = fromInput(item, 'sequential');
		const text2 = 'Marko Bele wrote';
		const r2 = P.protect(p2, text2, [{ entity_type: 'PERSON', start: 0, end: 10, score: 0.9 }]);
		assert.equal(r2.text, '[PERSON_3] wrote');
		const table = P.revealTable(p2);
		assert.equal(revealText(r1.text, table), text1);
		assert.equal(revealText(r2.text, table), text2);
	});
});
