/**
 * Ignore Terms: values the user never wants treated as personal data, such as a company or product
 * name. Shared by Protect and Detect.
 *
 * Filtering is local and happens after detection: the gateway still receives the whole text, and
 * the terms themselves never leave n8n. A detected span is dropped when its trimmed text equals a
 * term, compared case-insensitively after Unicode NFC normalisation. Only whole spans are compared;
 * a span that merely contains a term is kept.
 */
import type { Span } from './types';

/** Normal form used on both sides of the comparison. Locale-independent on purpose. */
function fold(value: string): string {
	return value.normalize('NFC').toLowerCase();
}

/**
 * Parses the Ignore Terms option: comma- or newline-separated text, or an array of strings when set
 * by expression. Array entries are taken whole, so a term such as "Acme, Inc." can be given that way.
 * Blank entries are dropped. Returns the folded terms, deduplicated.
 */
export function parseIgnoreTerms(input: unknown): Set<string> {
	const raw: string[] = [];
	if (typeof input === 'string') {
		raw.push(...input.split(/[,\r\n]+/));
	} else if (Array.isArray(input)) {
		for (const entry of input) {
			if (typeof entry === 'string') raw.push(entry);
			else if (typeof entry === 'number') raw.push(String(entry));
		}
	} else if (typeof input === 'number') {
		raw.push(String(input));
	}
	const terms = new Set<string>();
	for (const entry of raw) {
		const term = entry.trim();
		if (term !== '') terms.add(fold(term));
	}
	return terms;
}

/**
 * Drops every span whose trimmed text in `text` equals one of `terms` (as returned by
 * `parseIgnoreTerms`). Spans that do not index into `text` are kept unchanged; later stages skip
 * them anyway.
 */
export function filterIgnoredSpans(
	text: string,
	spans: Span[],
	terms: ReadonlySet<string>,
): Span[] {
	if (terms.size === 0) return spans;
	return spans.filter((span) => {
		if (span.start < 0 || span.end > text.length || span.end <= span.start) return true;
		const value = text.slice(span.start, span.end).trim();
		return !terms.has(fold(value));
	});
}
