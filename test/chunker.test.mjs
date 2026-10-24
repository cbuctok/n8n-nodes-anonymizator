// shared/chunker.ts: part packing, oversized blocks, cover, astral text, merging. Ported from the
// extension's tests/chunker.test.js (itself the web app's tests/js/engine/chunker.test.mjs): same
// cases, same expectations, node:test instead of vitest.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

const require = createRequire(import.meta.url);
const C = require('../dist/nodes/Anonymizator/shared/chunker.js');

const T = 8000;
const codePoints = (s) => [...s].length;

function coresJoined(text, parts) {
	return parts.map((p) => text.slice(p.coreStart16, p.coreEnd16)).join('');
}

function expectParts(text, parts, target = T) {
	assert.equal(coresJoined(text, parts), text); // the cores cover the text exactly
	for (const p of parts) {
		assert.equal(text.slice(p.start16, p.coreEnd16), p.text);
		assert.ok(codePoints(p.text) <= target);
	}
}

describe('chunker.split', () => {
	it('keeps the web app constants', () => {
		assert.deepEqual(
			{
				max: C.PART_TARGET_MAX,
				margin: C.PART_MARGIN,
				window: C.SENTENCE_WINDOW,
				overlap: C.OVERLAP,
			},
			{ max: 100000, margin: 2000, window: 2000, overlap: 256 },
		);
	});

	it('a short text is one part', () => {
		const parts = C.split('Pozdravljeni, Janez Novak.', T);
		assert.equal(parts.length, 1);
		assert.equal(parts[0].start16, 0);
		assert.equal(parts[0].text, 'Pozdravljeni, Janez Novak.');
	});

	it('an empty text is one empty part', () => {
		assert.deepEqual(
			C.split('', T).map((p) => p.text),
			[''],
		);
	});

	it('refuses a non-string text and a target too small for the overlap', () => {
		assert.throws(() => C.split(null, T), TypeError);
		assert.throws(() => C.split('abc', 512), RangeError);
		assert.throws(() => C.split('abc', 1.5e3 + 0.5), RangeError);
	});

	it('the part target follows the capabilities and is capped at 100 000', () => {
		assert.equal(C.partTarget(null), 8000); // bundled 10 000 - 2 000
		assert.equal(C.partTarget({ maxTextChars: 20000, maxBodyBytes: 1048576 }), 18000);
		assert.equal(C.partTarget({ maxTextChars: 900000, maxBodyBytes: 8 * 1048576 }), 100000);
		assert.equal(C.partTarget({ maxTextChars: 5000, maxBodyBytes: 1048576 }), 8000); // implausible: bundled
		assert.equal(C.partTarget({ maxTextChars: 14000, maxBodyBytes: 1048576 }), 12000); // the hosted cap
		assert.equal(C.partTargetFor(14000), 12000);
	});

	it('blocks are packed greedily and cut only after a newline, never at a tab', () => {
		const rows = [];
		for (let i = 0; i < 400; i++)
			rows.push(`Vrstica ${i}\tJanez Novak\tLjubljana\t${'x'.repeat(40)}`);
		const text = rows.join('\n');
		const parts = C.split(text, T);
		assert.ok(parts.length > 1);
		expectParts(text, parts);
		for (const p of parts.slice(0, -1)) {
			assert.equal(text[p.coreEnd16 - 1], '\n'); // every cut is right after a block separator
		}
		// Greedy: no part could have taken the next row as well.
		for (let i = 0; i < parts.length - 1; i++) {
			const nextRow = text.slice(parts[i].coreEnd16).split('\n')[0];
			assert.ok(codePoints(parts[i].text) + codePoints(nextRow) + 1 > T);
		}
	});

	it('a cut after an empty block is preferred within the last quarter', () => {
		const para = (n) =>
			Array.from({ length: n }, (_, i) => `Odstavek ${i} ${'b'.repeat(60)}`).join('\n');
		const text = `${para(90)}\n\n${para(90)}\n\n${para(90)}`;
		const parts = C.split(text, T);
		expectParts(text, parts);
		const firstCut = parts[0].coreEnd16;
		assert.equal(text.slice(firstCut - 2, firstCut), '\n\n'); // the first part ends after the empty block
	});

	it('a heading end listed by the caller is a preferred cut too', () => {
		const lines = Array.from({ length: 200 }, (_, i) => `Vrstica ${i} ${'c'.repeat(60)}`);
		const text = lines.join('\n');
		// The end of line 100 (inside the last quarter of the first part) is a "heading".
		const headingEnd = lines.slice(0, 101).join('\n').length + 1;
		const parts = C.split(text, T, { headingEnds: [headingEnd] });
		expectParts(text, parts);
		assert.equal(parts[0].coreEnd16, headingEnd);
	});

	it('one block longer than a part is cut at a sentence end, with a 256 code point overlap', () => {
		const text = 'Pogodba velja od podpisa dalje. '.repeat(1200).trim();
		const parts = C.split(text, T);
		assert.ok(parts.length >= 4);
		expectParts(text, parts);
		for (let i = 0; i < parts.length - 1; i++) {
			const cut = parts[i].coreEnd16;
			assert.equal(text[cut - 1], '.'); // cut right after the sentence end
			assert.equal(parts[i + 1].start16, cut - C.OVERLAP); // the next part starts 256 earlier
			assert.equal(parts[i + 1].coreStart16, cut);
		}
	});

	it('without a sentence end the cut is at the last space, never at a tab; else hard', () => {
		const words = 'beseda\tbeseda beseda\tbeseda '.repeat(800);
		const parts = C.split(words, T);
		expectParts(words, parts);
		for (const p of parts.slice(0, -1)) assert.equal(words[p.coreEnd16 - 1], ' ');

		const solid = 'a'.repeat(20000);
		const hard = C.split(solid, T);
		expectParts(solid, hard);
		assert.equal(hard[0].coreEnd16, T); // a hard cut at T
	});

	it('emoji and other astral characters around cuts: whole code points, cover intact', () => {
		const unit = '😀😀 Janez Novak 🎉 pozdrav 𝒜𝒷𝒸. ';
		const text = unit.repeat(900);
		const parts = C.split(text, T);
		assert.ok(parts.length > 1);
		expectParts(text, parts);
		const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
		for (const p of parts) assert.equal(lone.test(p.text), false); // no part splits a surrogate pair

		const solid = '😀'.repeat(9000); // 9 000 code points, 18 000 UTF-16 units, no space
		const hard = C.split(solid, T);
		expectParts(solid, hard);
		assert.equal(hard[0].coreEnd16, T * 2); // measured in code points
		assert.equal(hard[1].start16, (T - C.OVERLAP) * 2);
	});

	it('the cover assertion refuses parts that leave a gap', () => {
		const text = 'abc\ndef';
		assert.throws(() =>
			C.assertCover(text, [
				{ start16: 0, text: 'abc\n', coreStart16: 0, coreEnd16: 4 },
				{ start16: 5, text: 'ef', coreStart16: 5, coreEnd16: 7 },
			]),
		);
		assert.throws(() =>
			C.assertCover(text, [{ start16: 0, text: 'abc\nde', coreStart16: 0, coreEnd16: 6 }]),
		);
		assert.throws(() =>
			C.assertCover(text, [{ start16: 0, text: 'abc\ndeX', coreStart16: 0, coreEnd16: 7 }]),
		);
		assert.doesNotThrow(() =>
			C.assertCover(text, [{ start16: 0, text, coreStart16: 0, coreEnd16: 7 }]),
		);
	});
});

describe('chunker.merge', () => {
	it('shifts by part, sorts, drops exact duplicates and unites cut IDs', () => {
		const parts = [
			{ start16: 0, text: 'x'.repeat(100), coreStart16: 0, coreEnd16: 100 },
			{ start16: 90, text: 'y'.repeat(60), coreStart16: 100, coreEnd16: 150 },
		];
		const merged = C.merge(parts, [
			{
				entities: [
					{ start: 50, end: 55, entity_type: 'EMAIL_ADDRESS' },
					{ start: 95, end: 100, entity_type: 'PERSON' }, // truncated at the cut
					{ start: 10, end: 20, entity_type: 'PERSON' },
				],
				possible: [{ start: 30, end: 35, entity_type: 'ORGANIZATION' }],
			},
			{
				entities: [
					{ start: 5, end: 15, entity_type: 'PERSON' }, // the same ID, seen whole: 95..105
					{ start: 30, end: 34, entity_type: 'PHONE_NUMBER' },
					{ start: 30, end: 34, entity_type: 'PHONE_NUMBER' },
				],
				possible: [{ start: 13, end: 20, entity_type: 'ORGANIZATION' }], // 103..110 touches the ID
			},
		]);
		assert.deepEqual(
			merged.entities.map((e) => [e.start, e.end, e.entity_type]),
			[
				[10, 20, 'PERSON'],
				[50, 55, 'EMAIL_ADDRESS'],
				[95, 105, 'PERSON'],
				[120, 124, 'PHONE_NUMBER'],
			],
		);
		assert.deepEqual(
			merged.possible.map((p) => [p.start, p.end]),
			[[30, 35]],
		);
		assert.equal(
			merged.entities.every((e) => !('part' in e)),
			true,
		);
	});

	it('a partial overlap across a cut becomes the union (never protect less)', () => {
		const parts = [
			{ start16: 0, text: 'x'.repeat(100), coreStart16: 0, coreEnd16: 100 },
			{ start16: 90, text: 'y'.repeat(60), coreStart16: 100, coreEnd16: 150 },
		];
		const merged = C.merge(parts, [
			{ entities: [{ start: 92, end: 100, entity_type: 'PERSON', score: 0.6 }] }, // 92..100
			{ entities: [{ start: 5, end: 20, entity_type: 'LOCATION', score: 0.9 }] }, // 95..110, longer
		]);
		assert.deepEqual(merged.entities, [
			{ start: 92, end: 110, entity_type: 'LOCATION', score: 0.9 },
		]);
	});

	it('a single part is the analyze result sorted, duplicates dropped (no rebasing)', () => {
		const parts = C.split('Janez Novak, Janez Novak', T);
		const merged = C.merge(parts, [
			{
				entities: [
					{ start: 13, end: 24, entity_type: 'PERSON' },
					{ start: 0, end: 11, entity_type: 'PERSON' },
					{ start: 0, end: 11, entity_type: 'PERSON' },
					{ start: 0, end: 5, entity_type: 'PERSON' }, // inside, same part: kept for the anonymizer
				],
			},
		]);
		assert.deepEqual(
			merged.entities.map((e) => [e.start, e.end]),
			[
				[0, 11],
				[0, 5],
				[13, 24],
			],
		);
		assert.deepEqual(merged.possible, []);
	});

	it('rebases in UTF-16 units: spans after emoji in a later part land on the same characters', () => {
		const text = '😀'.repeat(9000) + 'Ana' + '😀'.repeat(100);
		const parts = C.split(text, T);
		// What gateway.ts analyzeSealed returns: UTF-16 offsets into each part's own text.
		const perPart = parts.map((p) => {
			const at = p.text.indexOf('Ana');
			return { entities: at === -1 ? [] : [{ start: at, end: at + 3, entity_type: 'PERSON' }] };
		});
		const merged = C.merge(parts, perPart);
		assert.equal(merged.entities.length, 1);
		assert.equal(text.slice(merged.entities[0].start, merged.entities[0].end), 'Ana');
	});
});
