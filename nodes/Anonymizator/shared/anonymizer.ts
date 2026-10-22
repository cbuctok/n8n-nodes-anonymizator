/**
 * Local substitution engine: faithful TypeScript port of the extension's `lib/anonymizer.js`
 * (2026.10.19.1: type sanitising, integer offsets, `isOwnPlaceholder`), plus
 * the pure `mask`, `isValidKey` and anonymize-wrapper helpers from `lib/id-set.js`. No network, no
 * state.
 *
 * The gateway's `/v1/analyze` returns only entity spans over the original text. Everything else
 * happens here, locally: placeholder allocation, range to placeholder substitution, PERSON name
 * sub-placeholders, masking and reveal.
 *
 * Conventions (identical to the extension):
 * - The table is a flat `{ BARE_KEY: real }` object, e.g. `{ PERSON_a7k2q: 'Janez Novak' }`.
 * - Rendered text always carries the bracketed form `[PERSON_a7k2q]`.
 * - Keys are `TYPE_<suffix>`: a 5-character random lowercase a-z0-9 suffix by default, or a per-type
 *   counter (`TYPE_1`, `TYPE_2`, ...) continuing from the table in sequential mode. Lowercase is
 *   load-bearing: it keeps the suffix disjoint from the UPPERCASE type.
 * - PERSON entries also mint `KEY_NAME` (given name) and `KEY_SURNAME` (all remaining tokens).
 * - Offsets are UTF-16 code units (String#slice).
 * - An analyzer type that is not a plain UPPERCASE identifier becomes `PII` (the span is still
 *   protected, only its label is generic), and spans whose offsets are not integers are skipped.
 * - `isOwnPlaceholder` (optional) is asked about every bracketed, whitespace-free token; a span
 *   lying wholly inside a token it accepts is dropped, so re-protecting protected text never
 *   rewrites the caller's own placeholders.
 *
 * Deliberate differences from the extension, none of which change results for valid input:
 * - The random suffix uses `randomInt` from node:crypto (no modulo bias; same alphabet and length).
 * - The value-to-key reverse index is a Map, so text such as "constructor" never resolves to an
 *   Object.prototype member.
 * - Table lookups use own properties only.
 * - Sequential counters ignore keys whose numeric suffix is longer than MAX_SUFFIX_DIGITS (they
 *   would lose integer precision and make minting loop forever), and a sequential key that would
 *   pass MAX_SUFFIX_DIGITS falls back to a random suffix, as the extension's IdSet.nextKey does.
 * - revealText looks each word run up in the table instead of compiling every key into one regular
 *   expression, so a huge map cannot crash the process.
 * - pgwSpansFromTable skips an entry whose first letter/digit run is not a run of the text before
 *   compiling its regex (exact, see there), so a table of thousands of IDs costs per text.
 */
import { randomInt } from 'node:crypto';

import type {
	AnonymizeOptions,
	AnonymizeResult,
	LocalEntity,
	MaskMode,
	MaskResult,
	Numbering,
	PlaceholderTable,
	Span,
} from './types';

/** A bare placeholder key: capital first, then letters, digits and underscores. */
export const KEY_RE = /^[A-Z][A-Za-z0-9_]*$/;

/** Longest numeric suffix accepted on a key (guards the sequential counters against huge numbers). */
export const MAX_SUFFIX_DIGITS = 9;

/** Label every masked entity gets in `redacted` mode. */
export const REDACTED = '[REDACTED]';

/** Placeholder styles that keep nothing and cannot be revealed. */
export const MASKED_STYLES: readonly MaskMode[] = ['typed', 'redacted'];

/** Bracketed placeholder token as it appears in text (global, for scanning). */
export const PLACEHOLDER_TOKEN_RE = /\[[A-Z][A-Za-z0-9_]*\]/g;

/**
 * Leading title tokens stripped before splitting a PERSON span. Matched case-insensitively with any
 * trailing "." ignored. Scoped to the target markets (DACH, SI, HR, common English).
 */
const TITLE_TOKENS = new Set([
	// common English
	'mr',
	'mrs',
	'ms',
	'miss',
	'dr',
	'prof',
	// DE / AT
	'herr',
	'frau',
	'mag',
	'dipl',
	'ing',
	'di',
	'priv-doz',
	// SI
	'gospod',
	'gospa',
	'g',
	'ga',
	// HR
	'gospodin',
	'gospođa',
	'gđa',
	'gdin',
]);

/** One/two-letter abbreviations only count as titles when written with a dot. */
const TITLE_DOT_REQUIRED = new Set(['g', 'ga']);

/**
 * An analyzer entity type becomes part of a placeholder (`[TYPE_a7k2q]`), so it must be a plain
 * UPPERCASE identifier. Anything else (brackets, newlines, prompt text from a hostile or broken
 * server) is coerced to the fallback type.
 */
export const ENTITY_TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
export const FALLBACK_ENTITY_TYPE = 'PII';

/** The analyzer type as a placeholder type: itself when it is a plain identifier, else `PII`. */
export function pgwEntityType(type: unknown): string {
	return typeof type === 'string' && ENTITY_TYPE_RE.test(type) ? type : FALLBACK_ENTITY_TYPE;
}

/** `anonymizeFromSpans` options: the extension's `{sequential, isOwnPlaceholder}`. */
export type AnonymizeFromSpansOptions = AnonymizeOptions & {
	/** Asked about every bracketed, whitespace-free token; spans wholly inside an accepted one are dropped. */
	isOwnPlaceholder?: (token: string) => boolean;
};

const SUFFIX_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const SUFFIX_LENGTH = 5;

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g;

/** One run of Unicode letters and digits (the units the table matches are bounded by). */
const WORD_RUN_RE = new RegExp('[\\p{L}\\p{N}]+', 'gu');
const FIRST_RUN_RE = new RegExp('[\\p{L}\\p{N}]+', 'u');

function hasOwn(obj: object, key: string): boolean {
	return Object.prototype.hasOwnProperty.call(obj, key);
}

function escapeRegExp(value: string): string {
	return value.replace(REGEX_SPECIALS, '\\$&');
}

/** Whether `key` is a valid bare placeholder key (KEY_RE and at most 9 suffix digits). */
export function isValidKey(key: unknown): key is string {
	if (typeof key !== 'string' || !KEY_RE.test(key)) return false;
	const digits = /_(\d+)$/.exec(key);
	return !digits || digits[1].length <= MAX_SUFFIX_DIGITS;
}

function isTitle(token: string): boolean {
	const norm = token.toLowerCase().replace(/\.+$/, '');
	if (!TITLE_TOKENS.has(norm)) return false;
	if (TITLE_DOT_REQUIRED.has(norm) && !token.endsWith('.')) return false;
	return true;
}

/**
 * Splits a full person name into given name and surname after stripping leading titles while more
 * than one token remains. Null when fewer than two tokens are left. The surname is every remaining
 * token, so SI/HR double surnames and DE particles ("von Goethe") stay whole.
 */
export function splitPersonName(realFull: string): { given: string; surname: string } | null {
	let parts = String(realFull).split(/\s+/).filter(Boolean);
	while (parts.length > 1 && isTitle(parts[0])) parts = parts.slice(1);
	if (parts.length < 2) return null;
	return { given: parts[0], surname: parts.slice(1).join(' ') };
}

/** Random suffix of `length` characters from lowercase a-z0-9 (crypto RNG, unbiased). */
export function randomSuffix(length = SUFFIX_LENGTH): string {
	let out = '';
	for (let i = 0; i < length; i++) {
		out += SUFFIX_ALPHABET[randomInt(SUFFIX_ALPHABET.length)];
	}
	return out;
}

/**
 * Mints the next key for an entity type: a per-type counter in sequential mode, else a random
 * suffix. Never returns a key already present in `table` or `newEntries`.
 */
function mintKey(
	type: string,
	sequential: boolean,
	counters: Record<string, number>,
	table: PlaceholderTable,
	newEntries: PlaceholderTable,
): string {
	const taken = (key: string) => hasOwn(table, key) || hasOwn(newEntries, key);
	if (sequential) {
		let n = hasOwn(counters, type) ? counters[type] : 0;
		let key: string;
		do {
			n += 1;
			key = `${type}_${n}`;
		} while (taken(key));
		if (String(n).length <= MAX_SUFFIX_DIGITS) {
			counters[type] = n;
			return key;
		}
		// Past 9 digits the counter is spent; a random suffix is still a valid key.
	}
	let key: string;
	do {
		key = `${type}_${randomSuffix()}`;
	} while (taken(key));
	return key;
}

/**
 * Highest sequential number per type in `table` (`/^([A-Z][A-Z0-9_]*)_(\d+)$/`), so numbering continues
 * across runs. Sub-keys such as `PERSON_1_NAME` do not end in digits and are ignored, and so are
 * suffixes longer than MAX_SUFFIX_DIGITS.
 */
export function pgwCountersFromTable(table: PlaceholderTable): Record<string, number> {
	const counters: Record<string, number> = {};
	const re = /^([A-Z][A-Z0-9_]*)_(\d+)$/;
	for (const key of Object.keys(table)) {
		const m = re.exec(key);
		if (!m || m[2].length > MAX_SUFFIX_DIGITS) continue;
		const n = parseInt(m[2], 10);
		if ((hasOwn(counters, m[1]) ? counters[m[1]] : 0) < n) counters[m[1]] = n;
	}
	return counters;
}

/**
 * Spans for every non-blank table value found in `text`: exact, word-bounded on Unicode letters and
 * digits (`\b` would break on č/š/ž), so a mapped "Ana" never fires inside "Banana". The entity type
 * comes from the key (`PERSON_a7k2q_NAME` gives PERSON); other keys report as CUSTOM. Empty or
 * whitespace values (tombstones) are skipped. Score 1.
 */
export function pgwSpansFromTable(text: string, table: PlaceholderTable): Span[] {
	const spans: Span[] = [];
	let runs: Set<string> | null = null;
	for (const [key, real] of Object.entries(table || {})) {
		const value = String(real).trim();
		if (!value) continue;
		// A value can only match where its first letter/digit run is a whole run of the text (the
		// match is bounded by non-letters/digits at both ends), so most entries are ruled out by one
		// Set lookup instead of compiling and running a regex: the cost follows the text, not the
		// table. Values with no letter or digit are always scanned. Results and order are unchanged.
		const first = FIRST_RUN_RE.exec(value);
		if (first) {
			if (!runs) runs = new Set(text.match(WORD_RUN_RE) || []);
			if (!runs.has(first[0])) continue;
		}
		const typeMatch = /^([A-Z][A-Z0-9_]*?)_[a-z0-9]+(?:_[A-Z][A-Z0-9_]*)?$/.exec(key);
		const entityType = typeMatch ? typeMatch[1] : 'CUSTOM';
		const re = new RegExp(`(?<![\\p{L}\\p{N}])${escapeRegExp(value)}(?![\\p{L}\\p{N}])`, 'gu');
		for (const m of text.matchAll(re)) {
			const start = m.index ?? 0;
			spans.push({ entity_type: entityType, start, end: start + value.length, score: 1 });
		}
	}
	return spans;
}

/** Mints `KEY_NAME` / `KEY_SURNAME` for a PERSON entry; never overwrites an existing binding. */
function mintPersonSubKeys(
	key: string,
	real: string,
	table: PlaceholderTable,
	newEntries: PlaceholderTable,
	realToKey: Map<string, string>,
): void {
	const split = splitPersonName(real);
	if (!split) return;
	const subs: Array<[string, string]> = [
		[`${key}_NAME`, split.given],
		[`${key}_SURNAME`, split.surname],
	];
	for (const [subKey, subReal] of subs) {
		if (!hasOwn(table, subKey) && !hasOwn(newEntries, subKey)) {
			newEntries[subKey] = subReal;
			if (!realToKey.has(subReal)) realToKey.set(subReal, subKey);
		}
	}
}

/**
 * Substitutes `spans` (plus every table value found in the text) with bracketed placeholders, in
 * one pass. On overlap the earliest-starting, then longest, span wins; spans that overlap, are
 * empty or run past the text are skipped, and whitespace is trimmed out of each span.
 *
 * `table` is not mutated; `newEntries` holds only the keys minted here (incl. PERSON sub-keys).
 * Entity offsets index into the OUTPUT text.
 */
export function anonymizeFromSpans(
	text: string,
	spans: Span[],
	table: PlaceholderTable,
	options?: AnonymizeFromSpansOptions,
): AnonymizeResult {
	const source: PlaceholderTable = table || {};
	const sequential = !!(options && options.sequential);
	const counters = sequential ? pgwCountersFromTable(source) : {};
	// Reverse index over ALL entries (sub-keys included): a re-detected first name reuses
	// PERSON_n_NAME. Each value is indexed raw and trimmed (spans are trimmed before lookup).
	const realToKey = new Map<string, string>();
	for (const [key, real] of Object.entries(source)) {
		if (!realToKey.has(real)) realToKey.set(real, key);
		const trimmed = String(real).trim();
		if (!realToKey.has(trimmed)) realToKey.set(trimmed, key);
	}

	const isOwn =
		options && typeof options.isOwnPlaceholder === 'function' ? options.isOwnPlaceholder : null;
	const ownTokens: Array<[number, number]> = []; // [start, end) of own placeholders, ascending
	if (isOwn) {
		for (const m of text.matchAll(/\[[^[\]\s]+\]/g)) {
			const at = m.index ?? 0;
			if (isOwn(m[0])) ownTokens.push([at, at + m[0].length]);
		}
	}
	const insideOwnToken = (start: number, end: number): boolean => {
		let lo = 0;
		let hi = ownTokens.length - 1;
		while (lo <= hi) {
			// last token starting at or before `start`
			const mid = (lo + hi) >> 1;
			if (ownTokens[mid][0] <= start) lo = mid + 1;
			else hi = mid - 1;
		}
		return hi >= 0 && end <= ownTokens[hi][1];
	};

	const sorted = [...(spans || []), ...pgwSpansFromTable(text, source)].sort(
		(a, b) => a.start - b.start || b.end - a.end,
	);
	const newEntries: PlaceholderTable = {};
	const entities: LocalEntity[] = [];
	const parts: string[] = [];
	let cursor = 0; // position in the original text
	let outLen = 0; // length of the output built so far

	for (const span of sorted) {
		let start = span.start;
		let end = span.end;
		if (!Number.isInteger(start) || !Number.isInteger(end)) continue; // not offsets
		if (!(start >= cursor && end > start && end <= text.length)) continue;
		while (start < end && /\s/.test(text[start])) start++;
		while (end > start && /\s/.test(text[end - 1])) end--;
		if (start >= end) continue;
		if (ownTokens.length > 0 && insideOwnToken(start, end)) continue; // the caller's own placeholder
		const real = text.slice(start, end);
		const type = pgwEntityType(span.entity_type);

		let key = realToKey.get(real);
		if (!key) {
			key = mintKey(type, sequential, counters, source, newEntries);
			realToKey.set(real, key);
			newEntries[key] = real;
			if (type === 'PERSON') mintPersonSubKeys(key, real, source, newEntries, realToKey);
		}

		const replacement = `[${key}]`;
		const between = text.slice(cursor, start);
		parts.push(between, replacement);
		outLen += between.length;
		entities.push({
			entity_type: type,
			replacement,
			start: outLen,
			end: outLen + replacement.length,
			score: typeof span.score === 'number' ? Math.round(span.score * 100) / 100 : 0,
		});
		outLen += replacement.length;
		cursor = end;
	}
	parts.push(text.slice(cursor));

	return { text: parts.join(''), entities, newEntries };
}

/**
 * Rewrites an `anonymizeFromSpans` result so every entity becomes `[ENTITY_TYPE]` (typed) or
 * `[REDACTED]`, recomputing offsets. Nothing is revealable afterwards.
 */
export function mask(local: { text: string; entities: LocalEntity[] }, mode: MaskMode): MaskResult {
	const parts: string[] = [];
	const entities: LocalEntity[] = [];
	let cursor = 0;
	let outLen = 0;
	for (const entity of local.entities) {
		const label = mode === 'typed' ? `[${entity.entity_type}]` : REDACTED;
		const between = local.text.slice(cursor, entity.start);
		parts.push(between, label);
		outLen += between.length;
		entities.push({ ...entity, replacement: label, start: outLen, end: outLen + label.length });
		outLen += label.length;
		cursor = entity.end;
	}
	parts.push(local.text.slice(cursor));
	return { text: parts.join(''), entities };
}

/** Existing map state a protect run continues from. */
export type ProtectState = {
	/** Bare-key table, without tombstones. */
	table: PlaceholderTable;
	/** Every key ever used (tombstones included). Keys not in `table` are never re-minted. */
	used?: readonly string[];
};

/**
 * Pure equivalent of the extension's `IdSet.anonymize` (without the skipped list): tombstones
 * (`used` keys missing from the table) are passed in as empty entries so they are never re-minted
 * and still count for sequential numbering. Masked styles mint nothing and return no entries.
 * The returned `newEntries` never contain tombstones; merge them into the table to continue.
 */
export function protectText(
	text: string,
	spans: Span[],
	state: ProtectState,
	numbering: Numbering,
): AnonymizeResult {
	const tombstones: PlaceholderTable = {};
	for (const key of state.used ?? []) {
		if (!hasOwn(state.table, key)) tombstones[key] = '';
	}
	const local = anonymizeFromSpans(
		text,
		spans,
		{ ...state.table, ...tombstones },
		{ sequential: numbering === 'sequential' },
	);
	if (numbering === 'typed' || numbering === 'redacted') {
		return { ...mask(local, numbering), newEntries: {} };
	}
	return local;
}

/**
 * Replaces `[KEY]` and bare word-bounded `KEY` tokens with their table values. Unknown placeholders
 * are left alone; an empty table returns `text` unchanged. Replacement goes through a callback, so
 * `$&` in a value is never interpreted.
 *
 * The extension compiles every key into one alternation (longest first). Here each ASCII word run,
 * bracketed or bare, is looked up in the table instead. Every valid key (KEY_RE) is a single word
 * run, so `\bKEY\b` and `[KEY]` can only ever match a whole run and the results are identical, but
 * the cost is linear in the text whatever the map size: a pattern built from a few hundred thousand
 * keys makes V8 abort the whole process while compiling it.
 */
export function revealText(text: string, table: PlaceholderTable): string {
	// No emptiness check: Object.keys on a map of a few hundred thousand keys costs seconds, and an
	// empty table already leaves every run as it is.
	if (!table) return text;
	return text.replace(
		/\[([A-Za-z0-9_]+)\]|\b([A-Za-z0-9_]+)\b/g,
		(match: string, bracketed?: string, bare?: string) => {
			const key = bracketed ?? bare;
			return key !== undefined && hasOwn(table, key) ? table[key] : match;
		},
	);
}

/** Distinct bracketed placeholder tokens (`[TYPE_x]`) in `text`, in order of first appearance. */
export function listPlaceholders(text: string): string[] {
	return [...new Set(text.match(PLACEHOLDER_TOKEN_RE) ?? [])];
}
