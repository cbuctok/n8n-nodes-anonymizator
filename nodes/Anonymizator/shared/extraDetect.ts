/**
 * "Additionally protect": numbers, currency values and company names with a legal suffix, found by
 * rules over the text locally (never by the gateway). A port of the extension's
 * `lib/extra-detect.js`; pure, no n8n imports.
 *
 * `spans(text, options, { isOwnPlaceholder })` returns COMPANY, AMOUNT and NUMBER spans (UTF-16
 * offsets, sorted, non-overlapping). Every matcher is atomic: it finds the whole candidate run first
 * and accepts or rejects it as a unit, so no part of a run is ever taken ("1250.505 EUR" is no
 * amount, and never "250.50 EUR"). A candidate that intersects one of the set's own placeholders is
 * dropped whole. Order: COMPANY, then AMOUNT outside the companies, then NUMBER outside both.
 *
 *  - NUMBER: every token that holds a digit. A token is a maximal run of letters / digits, where
 *    single separators (. , ' : / - ‐ NBSP NNBSP) join two letters or digits.
 *  - AMOUNT: a whole numeric run that reads as an amount, with €, $, £, EUR, USD, CHF or GBP right
 *    before or after it (one space or NBSP between at most); neither end touches a letter or digit.
 *  - COMPANY: one to four name words before an optional comma and a whole legal form, on one line;
 *    leading stop words are trimmed.
 *
 * `mergeExtra(text, gateway, tableSpans, extra)` merges them with the gateway spans and the set's
 * table matches so that neither side protects less.
 */
import { legalFormAt } from './idModel';
import type { Span } from './types';

export type ExtraOption = 'NUMBER' | 'AMOUNT' | 'COMPANY';
export type ExtraOptions = { NUMBER: boolean; AMOUNT: boolean; COMPANY: boolean };

export const EXTRA_OPTIONS: readonly ExtraOption[] = ['NUMBER', 'AMOUNT', 'COMPANY'];

type Range = { start: number; end: number };

const LN_RE = new RegExp('^[\\p{L}\\p{N}]$', 'u');
const DIGIT_RE = /^[0-9]$/;
/** Separators that join two letters / digits inside a NUMBER token. */
const TOKEN_SEPS = new Set(['.', ',', "'", ':', '/', '-', '\u2010', '\u00A0', '\u202F']);
/** Separators that join two digits inside an AMOUNT's numeric run. */
const NUM_SEPS = new Set(['.', ',', "'", '\u00A0', '\u202F']);
const AMOUNT_NUM_RE =
	/^(?:\d{1,3}(?:[.,'\u00A0\u202F]\d{3})+(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?)$/;
const SYMBOLS = new Set(['€', '$', '£']);
const CODES = new Set(['EUR', 'USD', 'CHF', 'GBP']);
const GAP = new Set([' ', '\u00A0']);
const WORD_CHAR_RE = new RegExp("^[\\p{L}\\p{N}&'\u2019.-]$", 'u');
const WORD_START_RE = new RegExp('^[\\p{Lu}\\p{N}]', 'u');
const MAX_NAME_WORDS = 4;
const STOP_WORDS = new Set([
	// English
	'The',
	'A',
	'An',
	'And',
	'Or',
	'Of',
	'In',
	'At',
	'On',
	'For',
	'To',
	'With',
	'By',
	'From',
	'Company',
	// Slovene
	'Ali',
	'Za',
	'Pri',
	'Na',
	'V',
	'S',
	'Z',
	'Od',
	'Do',
	'Med',
	'Po',
	'K',
	'H',
	'Podjetje',
	'Družba',
	'Firma',
]);
const PLACEHOLDER_RE = /\[[^[\]\s]+\]/g;

/** The code point (1 or 2 UTF-16 units) at i, or ''. */
function cpAt(text: string, i: number): string {
	if (i < 0 || i >= text.length) return '';
	return String.fromCodePoint(text.codePointAt(i) as number);
}

/** The code point that ends at i, or ''. */
function cpBefore(text: string, i: number): string {
	if (i <= 0 || i > text.length) return '';
	const low = text.charCodeAt(i - 1);
	if (low >= 0xdc00 && low <= 0xdfff && i >= 2) {
		const high = text.charCodeAt(i - 2);
		if (high >= 0xd800 && high <= 0xdbff) return text.slice(i - 2, i);
	}
	return text[i - 1];
}

const isLN = (ch: string): boolean => ch !== '' && LN_RE.test(ch);
const isDigit = (ch: string | undefined): boolean =>
	ch !== undefined && ch !== '' && DIGIT_RE.test(ch);
const isSpaceOrTab = (ch: string | undefined): boolean => ch === ' ' || ch === '\t';

/** The options as three booleans (missing or non-boolean = false). */
export function normalizeExtraOptions(raw: unknown): ExtraOptions {
	const obj = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<
		string,
		unknown
	>;
	return {
		NUMBER: obj.NUMBER === true,
		AMOUNT: obj.AMOUNT === true,
		COMPANY: obj.COMPANY === true,
	};
}

type RangeSet = { list: Range[]; intersects(start: number, end: number): boolean };

/** Sorted, non-overlapping ranges with an O(log n) intersection test. */
function rangeSet(ranges: Range[]): RangeSet {
	const list = ranges.slice().sort((a, b) => a.start - b.start);
	return {
		list,
		intersects(start: number, end: number): boolean {
			let lo = 0;
			let hi = list.length - 1;
			while (lo <= hi) {
				const mid = (lo + hi) >> 1;
				if (list[mid].start < end) lo = mid + 1;
				else hi = mid - 1;
			}
			return hi >= 0 && list[hi].end > start;
		},
	};
}

/** The set's own placeholder tokens in `text`. */
function ownTokens(text: string, isOwn: ((token: string) => boolean) | undefined): Range[] {
	const out: Range[] = [];
	if (typeof isOwn !== 'function') return out;
	for (const m of text.matchAll(PLACEHOLDER_RE)) {
		const at = m.index ?? 0;
		if (isOwn(m[0])) out.push({ start: at, end: at + m[0].length });
	}
	return out;
}

// --- COMPANY ---------------------------------------------------------------

/**
 * Start of the company name that ends right before the legal form at `formPos` (spaces/tabs, an
 * optional comma), or -1 when no name word is left.
 */
function nameStart(text: string, formPos: number): number {
	let p = formPos;
	while (p > 0 && isSpaceOrTab(text[p - 1])) p--;
	if (p > 0 && text[p - 1] === ',') p--;
	const words: Array<{ start: number; word: string; amp: boolean }> = [];
	let named = 0;
	while (named < MAX_NAME_WORDS) {
		let q = p;
		for (let ch = cpBefore(text, q); ch !== '' && WORD_CHAR_RE.test(ch); ch = cpBefore(text, q)) {
			q -= ch.length;
		}
		if (q === p) break;
		const word = text.slice(q, p);
		const amp = word === '&';
		if (!amp && !WORD_START_RE.test(word)) break;
		if (!amp && named > 0 && word.endsWith('.')) break; // a sentence end, not part of the name
		words.unshift({ start: q, word, amp });
		if (!amp) named++;
		let r = q;
		while (r > 0 && isSpaceOrTab(text[r - 1])) r--;
		if (r === q) break; // a line break, punctuation or the start of the text
		p = r;
	}
	while (words.length > 0 && (words[0].amp || STOP_WORDS.has(words[0].word))) words.shift();
	return words.length > 0 ? words[0].start : -1;
}

function companyCandidates(text: string): Range[] {
	const out: Range[] = [];
	for (let i = 1; i < text.length; i++) {
		if (!isSpaceOrTab(text[i - 1])) continue;
		const formLen = legalFormAt(text, i);
		if (!formLen) continue;
		const start = nameStart(text, i);
		if (start >= 0) out.push({ start, end: i + formLen });
		i += formLen - 1;
	}
	return out;
}

// --- AMOUNT ----------------------------------------------------------------

/** End of a currency right after the number ending at `end`, else -1. */
function currencyAfter(text: string, end: number): number {
	const p = GAP.has(text[end]) ? end + 1 : end;
	if (SYMBOLS.has(text[p])) return p + 1;
	if (CODES.has(text.slice(p, p + 3))) return p + 3;
	return -1;
}

/** Start of a currency right before the number starting at `start`, else -1. */
function currencyBefore(text: string, start: number): number {
	const p = start > 0 && GAP.has(text[start - 1]) ? start - 1 : start;
	if (p > 0 && SYMBOLS.has(text[p - 1])) return p - 1;
	if (p >= 3 && CODES.has(text.slice(p - 3, p))) return p - 3;
	return -1;
}

function amountCandidates(text: string): Range[] {
	const out: Range[] = [];
	const n = text.length;
	let i = 0;
	while (i < n) {
		if (!isDigit(text[i])) {
			i++;
			continue;
		}
		let j = i + 1;
		for (;;) {
			if (j < n && isDigit(text[j])) j++;
			else if (j + 1 < n && NUM_SEPS.has(text[j]) && isDigit(text[j + 1])) j += 2;
			else break;
		}
		const start = i;
		const end = j;
		i = j;
		if (!AMOUNT_NUM_RE.test(text.slice(start, end))) continue; // the whole run, or nothing
		const after = currencyAfter(text, end);
		if (after > 0 && !isLN(cpAt(text, after)) && !isLN(cpBefore(text, start))) {
			out.push({ start, end: after });
			continue;
		}
		const before = currencyBefore(text, start);
		if (before >= 0 && !isLN(cpBefore(text, before)) && !isLN(cpAt(text, end))) {
			out.push({ start: before, end });
		}
	}
	return out;
}

// --- NUMBER ----------------------------------------------------------------

function numberCandidates(text: string): Range[] {
	const out: Range[] = [];
	const n = text.length;
	let i = 0;
	while (i < n) {
		const ch = cpAt(text, i);
		if (!isLN(ch)) {
			i += ch.length || 1;
			continue;
		}
		let j = i + ch.length;
		let digit = isDigit(ch);
		while (j < n) {
			const c = cpAt(text, j);
			if (isLN(c)) {
				digit = digit || isDigit(c);
				j += c.length;
			} else if (TOKEN_SEPS.has(c) && isLN(cpAt(text, j + 1))) {
				j += 1;
			} else {
				break;
			}
		}
		if (digit) out.push({ start: i, end: j });
		i = j;
	}
	return out;
}

/** The Additionally protect spans of `text` (score 1, sorted, non-overlapping). */
export function extraSpans(
	text: string,
	options: unknown,
	context: { isOwnPlaceholder?: (token: string) => boolean } = {},
): Span[] {
	const opts = normalizeExtraOptions(options);
	if (typeof text !== 'string' || !text || !EXTRA_OPTIONS.some((o) => opts[o])) return [];
	const blocked = rangeSet(ownTokens(text, context && context.isOwnPlaceholder));
	const taken: Span[] = [];
	const accept = (type: ExtraOption, candidates: Range[], others: RangeSet[]): RangeSet => {
		const kept: Range[] = [];
		for (const c of candidates) {
			if (
				blocked.intersects(c.start, c.end) ||
				others.some((set) => set.intersects(c.start, c.end))
			) {
				continue;
			}
			if (kept.length > 0 && kept[kept.length - 1].end > c.start) continue;
			kept.push(c);
		}
		for (const c of kept) taken.push({ entity_type: type, start: c.start, end: c.end, score: 1 });
		return rangeSet(kept);
	};
	const companies = opts.COMPANY ? accept('COMPANY', companyCandidates(text), []) : rangeSet([]);
	const amounts = opts.AMOUNT
		? accept('AMOUNT', amountCandidates(text), [companies])
		: rangeSet([]);
	if (opts.NUMBER) accept('NUMBER', numberCandidates(text), [companies, amounts]);
	return taken.sort((a, b) => a.start - b.start);
}

// --- Merge with the gateway spans and the set's table matches ------------------

/** Whitespace and the NUMBER token separators, trimmed off a split extra span. */
const PIECE_TRIM_RE = new RegExp("^[\\s.,':/\\-\\u2010\\u00A0\\u202F]$", 'u');
const HAS_LN_RE = new RegExp('[\\p{L}\\p{N}]', 'u');
const HAS_DIGIT_RE = /[0-9]/;

/** [start, end) without surrounding whitespace, as anonymizeFromSpans trims it. */
function trimmedRange(text: string, span: Range): Range {
	let { start, end } = span;
	while (start < end && /\s/.test(text[start])) start++;
	while (end > start && /\s/.test(text[end - 1])) end--;
	return { start, end };
}

const validSpan = (text: string, s: Span): boolean =>
	!!s &&
	Number.isInteger(s.start) &&
	Number.isInteger(s.end) &&
	s.start >= 0 &&
	s.start < s.end &&
	s.end <= text.length;

/** The pieces of extra span `e` outside the union of `over`, trimmed; kept while they hold a letter or digit. */
function extraPieces(text: string, e: Span, over: Range[]): Span[] {
	const union = over
		.map((o): [number, number] => [Math.max(o.start, e.start), Math.min(o.end, e.end)])
		.sort((a, b) => a[0] - b[0]);
	const gaps: Array<[number, number]> = [];
	let cursor = e.start;
	for (const [start, end] of union) {
		if (start > cursor) gaps.push([cursor, start]);
		cursor = Math.max(cursor, end);
	}
	if (cursor < e.end) gaps.push([cursor, e.end]);
	const keep = e.entity_type === 'COMPANY' ? HAS_LN_RE : HAS_DIGIT_RE;
	const out: Span[] = [];
	for (const gap of gaps) {
		let [start, end] = gap;
		while (start < end && PIECE_TRIM_RE.test(text[start])) start++;
		while (end > start && PIECE_TRIM_RE.test(text[end - 1])) end--;
		if (start < end && keep.test(text.slice(start, end))) out.push({ ...e, start, end });
	}
	return out;
}

/**
 * Merges the Additionally protect spans `extra` with the gateway spans and the table matches.
 * Neither side may protect less:
 *  - no overlap: the extra span is kept;
 *  - every overlapping span lies wholly inside it: the extra span is kept and those gateway spans
 *    dropped; table matches inside lose in anonymizeFromSpans (the earliest, longest span wins);
 *  - an overlapping span with exactly the same range wins over the extra span;
 *  - a span crosses an edge: the overlapping spans win and the pieces of the extra span outside
 *    them are kept, trimmed.
 */
export function mergeExtra(
	text: string,
	gateway: Span[],
	tableSpans: Span[],
	extra: Span[],
): { gateway: Span[]; extra: Span[] } {
	type Other = { span: Span; gateway: boolean; start: number; end: number };
	const others: Other[] = [
		...gateway
			.filter((s) => validSpan(text, s))
			.map((span) => ({ span, gateway: true, ...trimmedRange(text, span) })),
		...tableSpans.map((span) => ({ span, gateway: false, start: span.start, end: span.end })),
	]
		.filter((o) => o.start < o.end)
		.sort((a, b) => a.start - b.start);
	const maxLen = others.reduce((m, o) => Math.max(m, o.end - o.start), 0);
	const dropped = new Set<Span>();
	const kept: Span[] = [];
	for (const e of extra) {
		// Overlapping spans: start before e.end and end after e.start.
		let hi = others.length - 1;
		let lo = 0;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			if (others[mid].start < e.end) lo = mid + 1;
			else hi = mid - 1;
		}
		const over: Other[] = [];
		for (let i = hi; i >= 0 && others[i].start >= e.start - maxLen; i--) {
			if (others[i].end > e.start) over.push(others[i]);
		}
		if (over.length === 0) {
			kept.push(e);
		} else if (over.some((o) => o.start === e.start && o.end === e.end)) {
			continue;
		} else if (over.every((o) => o.start >= e.start && o.end <= e.end)) {
			kept.push(e);
			for (const o of over) if (o.gateway) dropped.add(o.span);
		} else {
			kept.push(...extraPieces(text, e, over));
		}
	}
	return { gateway: gateway.filter((s) => !dropped.has(s)), extra: kept };
}
