/**
 * Possible IDs: text left in clear that is not certain enough to replace, listed for a person to
 * check. A port of the extension's `lib/id-possible.js` (`find`, `detectedValues`); pure, no n8n
 * imports. A possible is a prompt to look, never a score: there is no confidence field, and text
 * that is not listed can still hold personal data.
 *
 * Rules (conservative, case-sensitive, whole words only):
 *  1. company-name: the base name of a COMPANY ID ("Modra Vila" of "Modra Vila d.o.o.", at least 3
 *     characters) when no legal form follows it.
 *  2. surname / title-surname: the surname of a PERSON ID, with a title in front taken in
 *     ("Mr. Zupan", "g. Zupan"). Given names alone are never flagged by this rule.
 *  3. case-form: a Slovene case form of a PERSON token of at least 4 letters ("Luki", "Zupanu").
 *  4. Two possibles of the same ID separated by one space are one ("Markom Horvatom").
 *  5. extra spans (`extra`): kinds number / amount / company, `of: null`.
 *  5a. detected values (the gateway's `possible` spans): whole-word occurrences, kind `detected`,
 *     `of: null`, type mapped by DETECTED_TYPES (else null).
 *  6. Sorted by start (longer first), no overlaps, capped at MAX (`more`).
 * Never flagged: text inside an entity or inside any `[...]` token, and the values of records,
 * name parts and excluded (skipped / ignored) values.
 */
import { companyName, legalSuffixLength } from './idModel';
import type { IdSetContent } from './idModel';
import { splitPersonName } from './anonymizer';

export type PossibleKind =
	| 'company-name'
	| 'surname'
	| 'title-surname'
	| 'case-form'
	| 'number'
	| 'amount'
	| 'company'
	| 'detected';

/** One possible ID, in the text it was found in. */
export type PossibleId = {
	start: number;
	end: number;
	value: string;
	kind: PossibleKind;
	/** An ID type code (PERSON, COMPANY, NUMBER, ...), or null when unknown. */
	type: string | null;
	/** The live key the possible is a variant of, or null. */
	of: string | null;
};

/** A distinct value of the gateway's possible spans. */
export type DetectedValue = { value: string; type: string };

export const POSSIBLE_KINDS: readonly PossibleKind[] = [
	'company-name',
	'surname',
	'title-surname',
	'case-form',
	'number',
	'amount',
	'company',
	'detected',
];
export const ENDINGS: readonly string[] = ['a', 'e', 'i', 'o', 'u', 'om', 'em', 'ja', 'ju', 'jem'];
export const TITLE_RE = new RegExp(
	'(?:\\b(?:Mr|Mrs|Ms|Dr|Prof)\\.?|(?<![\\p{L}])(?:g|ga|gdč|dr|prof)\\.)[ \\u00A0]+$',
	'iu',
);
export const MAX_POSSIBLE = 50;
export const MAX_DETECTED = 200;
const MIN_TOKEN_LETTERS = 4;
const EXTRA_KINDS: Readonly<Record<string, PossibleKind>> = {
	NUMBER: 'number',
	AMOUNT: 'amount',
	COMPANY: 'company',
};
/** Gateway possible types → ID types. */
export const DETECTED_TYPES: Readonly<Record<string, string>> = {
	ORGANIZATION: 'COMPANY',
	PERSON: 'PERSON',
};
const PLACEHOLDER_RE = /\[[^[\]\s]+\]/g;
const WORD_RE_SOURCE = '(?<![\\p{L}\\p{N}])\\p{Lu}\\p{Ll}+(?![\\p{L}\\p{N}])';
const CASE_WORD_RE = new RegExp('^\\p{Lu}\\p{Ll}+$', 'u');
const LETTERS_RE = new RegExp('^\\p{L}+$', 'u');
const UPPER_FIRST_RE = new RegExp('^\\p{Lu}', 'u');
const WORD_RUN_RE = new RegExp('[\\p{L}\\p{N}]+', 'gu');
const FIRST_RUN_RE = new RegExp('[\\p{L}\\p{N}]+', 'u');

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const hasOwn = (obj: object, key: string): boolean =>
	Object.prototype.hasOwnProperty.call(obj, key);

type Candidate = {
	start: number;
	end: number;
	kind: PossibleKind;
	type: string | null;
	of: string | null;
};

/** The case stem of a name token: lower case, one final vowel dropped; '' under 3 letters. */
export function caseStem(token: unknown): string {
	if (typeof token !== 'string') return '';
	let stem = token.toLowerCase();
	if (/[aeiou]$/.test(stem)) stem = stem.slice(0, -1);
	return [...stem].length >= 3 ? stem : '';
}

/** True when `word` reads as a case form of the name token `token`. */
export function isCaseForm(word: unknown, token: unknown): boolean {
	if (typeof word !== 'string' || typeof token !== 'string') return false;
	if (!CASE_WORD_RE.test(word) || !UPPER_FIRST_RE.test(token)) return false;
	const stem = caseStem(token);
	if (!stem) return false;
	const w = word.toLowerCase();
	if (w === token.toLowerCase() || !w.startsWith(stem)) return false;
	if (word.length > token.length + 3) return false;
	return ENDINGS.includes(w.slice(stem.length));
}

/** The letter/digit runs of `text`, built once per findPossible call. */
type TextRuns = { set: Set<string> | null };

/**
 * Whole-word, case-sensitive occurrences of `value` in `text`. With `runs`, a value whose first
 * letter/digit run is not a whole run of the text is ruled out without compiling a regex (exact: a
 * match is bounded by non-letters/digits, so that run of the value is a run of the text too).
 */
function occurrences(
	text: string,
	value: string,
	runs?: TextRuns,
): Array<{ start: number; end: number }> {
	if (runs) {
		const first = FIRST_RUN_RE.exec(value);
		if (first) {
			if (!runs.set) runs.set = new Set(text.match(WORD_RUN_RE) || []);
			if (!runs.set.has(first[0])) return [];
		}
	}
	const re = new RegExp(`(?<![\\p{L}\\p{N}])${escapeRe(value)}(?![\\p{L}\\p{N}])`, 'gu');
	return [...text.matchAll(re)].map((m) => ({
		start: m.index ?? 0,
		end: (m.index ?? 0) + value.length,
	}));
}

/** The start of a title right before `start` ("Mr. ", "g. "), else `start`. */
function titleStart(text: string, start: number): number {
	const m = TITLE_RE.exec(text.slice(Math.max(0, start - 24), start));
	return m ? start - m[0].length : start;
}

/** The union of the entity ranges and every [...] token, sorted and disjoint. */
function blockedRanges(
	text: string,
	entities: ReadonlyArray<{ start: number; end: number }>,
): Array<[number, number]> {
	const list: Array<[number, number]> = [];
	for (const e of Array.isArray(entities) ? entities : []) {
		if (e && Number.isInteger(e.start) && Number.isInteger(e.end)) list.push([e.start, e.end]);
	}
	for (const m of text.matchAll(PLACEHOLDER_RE)) {
		const at = m.index ?? 0;
		list.push([at, at + m[0].length]);
	}
	list.sort((a, b) => a[0] - b[0]);
	const union: Array<[number, number]> = [];
	for (const [start, end] of list) {
		const last = union[union.length - 1];
		if (last && start <= last[1]) last[1] = Math.max(last[1], end);
		else union.push([start, end]);
	}
	return union;
}

/** True when [start, end) intersects a blocked range (binary search over the union). */
function isBlocked(blocked: Array<[number, number]>, start: number, end: number): boolean {
	let lo = 0;
	let hi = blocked.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		if (blocked[mid][0] < end) lo = mid + 1;
		else hi = mid - 1;
	}
	return hi >= 0 && blocked[hi][1] > start;
}

/** The PERSON name tokens to look for case forms of. */
function caseSources(state: IdSetContent): Array<{ token: string; of: string }> {
	const out: Array<{ token: string; of: string }> = [];
	const seen = new Set<string>();
	const push = (token: string, of: string): void => {
		if (
			!LETTERS_RE.test(token) ||
			!UPPER_FIRST_RE.test(token) ||
			[...token].length < MIN_TOKEN_LETTERS
		) {
			return;
		}
		const id = `${of}\u0000${token}`;
		if (seen.has(id)) return;
		seen.add(id);
		out.push({ token, of });
	};
	for (const r of state.ids) {
		if (r.type !== 'PERSON') continue;
		const split = splitPersonName(r.value);
		if (split) {
			push(split.given, r.key);
			for (const t of split.surname.split(/\s+/)) push(t, r.key);
		} else if (!/\s/.test(r.value.trim())) {
			push(r.value.trim(), r.key);
		}
	}
	for (const s of Object.values(state.subKeys || {})) {
		for (const t of String(s.value).split(/\s+/)) push(t, s.of);
	}
	return out;
}

/**
 * The case sources by case stem (lower case), each list in source order. A word can only be a case
 * form of a token whose stem is the word less one of the ENDINGS, so a word meets only those few
 * tokens instead of every token of the set.
 */
function caseIndex(sources: Array<{ token: string; of: string }>): Map<string, number[]> {
	const index = new Map<string, number[]>();
	sources.forEach((s, i) => {
		const stem = caseStem(s.token);
		if (!stem) return;
		const list = index.get(stem);
		if (list) list.push(i);
		else index.set(stem, [i]);
	});
	return index;
}

/** The first source (lowest index) `word` is a case form of, else null (as `sources.find`). */
function firstCaseSource(
	word: string,
	sources: Array<{ token: string; of: string }>,
	index: Map<string, number[]>,
): { token: string; of: string } | null {
	const w = word.toLowerCase();
	let best = -1;
	for (const ending of ENDINGS) {
		if (w.length <= ending.length || !w.endsWith(ending)) continue;
		const list = index.get(w.slice(0, w.length - ending.length));
		if (!list) continue;
		for (const i of list) {
			if (best !== -1 && i >= best) break;
			if (isCaseForm(word, sources[i].token)) {
				best = i;
				break;
			}
		}
	}
	return best === -1 ? null : sources[best];
}

/** Rules 1-3 over `text`. */
function variantCandidates(state: IdSetContent, text: string, runs: TextRuns): Candidate[] {
	const out: Candidate[] = [];
	for (const r of state.ids) {
		if (r.type === 'COMPANY') {
			const name = companyName(r.value);
			if (name.length < 3) continue;
			for (const o of occurrences(text, name, runs)) {
				if (legalSuffixLength(text, o.end) > 0) continue;
				out.push({ ...o, kind: 'company-name', type: 'COMPANY', of: r.key });
			}
		} else if (r.type === 'PERSON') {
			const split = splitPersonName(r.value);
			if (!split) continue;
			for (const o of occurrences(text, split.surname, runs)) {
				const start = titleStart(text, o.start);
				out.push({
					start,
					end: o.end,
					kind: start < o.start ? 'title-surname' : 'surname',
					type: 'PERSON',
					of: r.key,
				});
			}
		}
	}
	const sources = caseSources(state);
	if (sources.length > 0) {
		const index = caseIndex(sources);
		for (const m of text.matchAll(new RegExp(WORD_RE_SOURCE, 'gu'))) {
			const source = firstCaseSource(m[0], sources, index);
			if (!source) continue;
			const at = m.index ?? 0;
			out.push({
				start: titleStart(text, at),
				end: at + m[0].length,
				kind: 'case-form',
				type: 'PERSON',
				of: source.of,
			});
		}
	}
	return out;
}

/** Sorted by start, longer first; drops anything overlapping a kept one. */
function dropOverlaps(list: Candidate[]): Candidate[] {
	const sorted = list.slice().sort((a, b) => a.start - b.start || b.end - a.end);
	const kept: Candidate[] = [];
	let cursor = 0;
	for (const p of sorted) {
		if (p.start < cursor) continue;
		kept.push(p);
		cursor = p.end;
	}
	return kept;
}

/** Rule 4: possibles of the same ID one space apart become one. */
function mergeAdjacent(text: string, list: Candidate[]): Candidate[] {
	const out: Candidate[] = [];
	for (const p of list) {
		const prev = out[out.length - 1];
		const gap = prev ? text.slice(prev.end, p.start) : '';
		if (prev && prev.of !== null && prev.of === p.of && (gap === ' ' || gap === '\u00A0')) {
			prev.end = p.end;
			prev.kind = prev.kind === 'case-form' || p.kind === 'case-form' ? 'case-form' : 'surname';
			continue;
		}
		out.push({ ...p });
	}
	return out;
}

/** The values never flagged: record values and name parts (trimmed), plus `extra` values. */
export function exclusions(state: IdSetContent, extra: Iterable<string> = []): Set<string> {
	return new Set([
		...state.ids.map((r) => r.value.trim()),
		...Object.values(state.subKeys || {}).map((s) => String(s.value).trim()),
		...extra,
	]);
}

/** The ID type of a gateway possible type, else null. */
function detectedType(type: unknown): string | null {
	return typeof type === 'string' && hasOwn(DETECTED_TYPES, type) ? DETECTED_TYPES[type] : null;
}

/**
 * The possible IDs in `text` (the protected output). `entities` are the placeholders in `text`;
 * `extra` Additionally protect spans to list rather than protect; `detected` the gateway's
 * possible values (`detectedValues`); `isExcluded` a further test on the trimmed value (skipped
 * or ignored values).
 */
export function findPossible(
	state: IdSetContent | null,
	text: string,
	entities: ReadonlyArray<{ start: number; end: number }>,
	options: {
		extra?: ReadonlyArray<{ entity_type: string; start: number; end: number }>;
		detected?: ReadonlyArray<{ value: string; type: string }>;
		excluded?: Set<string>;
		isExcluded?: (value: string) => boolean;
	} = {},
): { possible: PossibleId[]; more: boolean } {
	if (typeof text !== 'string' || !text || !state) return { possible: [], more: false };
	const excluded = options.excluded instanceof Set ? options.excluded : exclusions(state);
	const isExcluded = typeof options.isExcluded === 'function' ? options.isExcluded : null;
	const blocked = blockedRanges(text, entities);
	const allowed = (p: Candidate): boolean => {
		if (!(p.start < p.end) || isBlocked(blocked, p.start, p.end)) return false;
		const value = text.slice(p.start, p.end).trim();
		return !excluded.has(value) && !(isExcluded && isExcluded(value));
	};
	const runs: TextRuns = { set: null };
	const variants = mergeAdjacent(
		text,
		dropOverlaps(variantCandidates(state, text, runs).filter(allowed)),
	).filter(allowed);
	const extra: Candidate[] = [];
	for (const s of Array.isArray(options.extra) ? options.extra : []) {
		if (!s || typeof s.entity_type !== 'string' || !hasOwn(EXTRA_KINDS, s.entity_type)) continue;
		if (!Number.isInteger(s.start) || !Number.isInteger(s.end) || s.end > text.length) continue;
		extra.push({
			start: s.start,
			end: s.end,
			kind: EXTRA_KINDS[s.entity_type],
			type: s.entity_type,
			of: null,
		});
	}
	const detected: Candidate[] = [];
	const detectedList = Array.isArray(options.detected)
		? options.detected.slice(0, MAX_DETECTED)
		: [];
	for (const d of detectedList) {
		if (!d || typeof d.value !== 'string' || !d.value.trim()) continue;
		for (const o of occurrences(text, d.value, runs)) {
			detected.push({ ...o, kind: 'detected', type: detectedType(d.type), of: null });
		}
	}
	const all = dropOverlaps([...variants, ...extra.filter(allowed), ...detected.filter(allowed)]);
	const possible = all.slice(0, MAX_POSSIBLE).map((p) => ({
		start: p.start,
		end: p.end,
		value: text.slice(p.start, p.end),
		kind: p.kind,
		type: p.type,
		of: p.of,
	}));
	return { possible, more: all.length > MAX_POSSIBLE };
}

/**
 * The distinct `{value, type}` of the gateway's possible spans over `text` (trimmed, non-empty,
 * first type wins), at most MAX_DETECTED.
 */
export function detectedValues(
	text: string,
	spans: ReadonlyArray<{ start: number; end: number; entity_type: string }> | null | undefined,
): DetectedValue[] {
	const out = new Map<string, DetectedValue>();
	if (typeof text !== 'string' || !Array.isArray(spans)) return [];
	for (const s of spans) {
		if (!s || !Number.isInteger(s.start) || !Number.isInteger(s.end)) continue;
		const value = text.slice(s.start, s.end).trim();
		if (value && !out.has(value)) out.set(value, { value, type: s.entity_type });
		if (out.size >= MAX_DETECTED) break;
	}
	return [...out.values()];
}
