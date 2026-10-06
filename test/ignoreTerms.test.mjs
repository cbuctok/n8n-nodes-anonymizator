// Ignore Terms helper (shared/ignoreTerms.ts), against the compiled module. Synthetic data only.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
	parseIgnoreTerms,
	filterIgnoredSpans,
} = require('../dist/nodes/Anonymizator/shared/ignoreTerms.js');

const span = (text, value, type = 'PERSON') => {
	const start = text.indexOf(value);
	assert.ok(start >= 0, value);
	return { entity_type: type, start, end: start + value.length, score: 0.85 };
};

describe('parseIgnoreTerms', () => {
	test('splits on commas and new lines, trims, drops blanks, folds case', () => {
		assert.deepEqual(
			[...parseIgnoreTerms(' Acme , Acme Cloud\n\nKOVAČ d.o.o.\r\n,')],
			['acme', 'acme cloud', 'kovač d.o.o.'],
		);
	});

	test('accepts an array from an expression, and nothing at all', () => {
		assert.deepEqual(
			[...parseIgnoreTerms(['Acme', 'Acme, Inc.', ' Beta ', 42, null])],
			['acme', 'acme, inc.', 'beta', '42'],
		);
		for (const empty of [undefined, null, '', '  ,\n', {}, []]) {
			assert.equal(parseIgnoreTerms(empty).size, 0);
		}
	});

	test('deduplicates terms that differ only in case', () => {
		assert.equal(parseIgnoreTerms('Acme, ACME, acme').size, 1);
	});
});

describe('filterIgnoredSpans', () => {
	const text = 'Janez Novak from ACME wrote to Ana Kovač about Acme Cloud.';

	test('drops a span whose whole text equals a term, case-insensitively', () => {
		const spans = [span(text, 'Janez Novak'), span(text, 'ACME', 'ORGANIZATION')];
		const kept = filterIgnoredSpans(text, spans, parseIgnoreTerms('acme'));
		assert.deepEqual(kept, [spans[0]]);
	});

	test('a span that only contains a term is kept', () => {
		const spans = [span(text, 'Acme Cloud', 'ORGANIZATION')];
		assert.deepEqual(filterIgnoredSpans(text, spans, parseIgnoreTerms('Acme')), spans);
	});

	test('surrounding whitespace in the span is ignored', () => {
		const start = text.indexOf(' ACME ');
		const spans = [{ entity_type: 'ORGANIZATION', start, end: start + 6 }];
		assert.deepEqual(filterIgnoredSpans(text, spans, parseIgnoreTerms('acme')), []);
	});

	test('Unicode case folding and normalisation', () => {
		const spans = [span(text, 'Ana Kovač')];
		assert.deepEqual(filterIgnoredSpans(text, spans, parseIgnoreTerms('ANA KOVAČ')), []);
		// The same name typed with a combining caron (NFD) still matches.
		assert.deepEqual(filterIgnoredSpans(text, spans, parseIgnoreTerms('ana kovač')), []);
	});

	test('no terms returns the spans unchanged; out-of-range spans are left alone', () => {
		const spans = [span(text, 'Janez Novak'), { entity_type: 'X', start: 5, end: 999 }];
		assert.equal(filterIgnoredSpans(text, spans, new Set()), spans);
		assert.deepEqual(filterIgnoredSpans(text, spans, parseIgnoreTerms('Janez Novak')), [spans[1]]);
	});
});
