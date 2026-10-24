/**
 * Cuts a long text into parts the gateway accepts, and merges the parts' spans back into offsets
 * over the whole text. Pure: no I/O, no state.
 *
 * Port of the extension's `lib/chunker.js` (`anonChunker`), itself a port of the web app's
 * `demo/js/engine/pgw-chunker.js` (gateway repository): same algorithm, same constants; only the
 * module wrapper, the types and the error texts differ.
 *
 * Parts (`split`):
 * - The part target T = min(effectiveMaxTextChars(caps) - 2000, 100 000), measured in code points
 *   (what the server counts).
 * - Blocks are the lines between '\n' separators; a '\t' (table cell) is never a cut point. Blocks
 *   are packed greedily. The cut goes after an empty block (or a heading, when the caller lists
 *   them) if one lies in the last quarter of the part, else after the last block that fits.
 * - A single block longer than the room left is cut at the last sentence end ([.!?] then
 *   whitespace) within the final 2 000 code points, else at the last whitespace, else hard at T;
 *   the next part then starts 256 code points earlier (overlap), so an ID cut in two is seen whole
 *   once.
 * - Every part is {start16, text, coreStart16, coreEnd16}: `text` is
 *   whole.slice(start16, coreEnd16); the cores [coreStart16, coreEnd16) are disjoint and cover the
 *   text exactly (asserted).
 *
 * Spans (`merge`): each part's spans, already UTF-16 offsets into the part's text (the gateway
 * answers in code points; `codePointSpansToUtf16` converts them against the exact part that was
 * sent), are shifted by start16 (UTF-16 too), sorted by start then longer first, and exact
 * (start, end, type) duplicates dropped, like a span inside a span of another part. Two spans of
 * DIFFERENT parts that overlap only partly (an ID truncated at a cut, seen whole in the overlap of
 * the next part) become their union, so a cut never leaves part of an ID in clear; the anonymizer's
 * overlap rule (earliest start, then longest) resolves the rest. Possible spans are merged the same
 * way and dropped where they touch an entity.
 */
import { effectiveMaxTextChars } from './limits';

export const PART_TARGET_MAX = 100000;
export const PART_MARGIN = 2000;
export const SENTENCE_WINDOW = 2000;
export const OVERLAP = 256;
const PREFERRED_FROM = 0.75; // a preferred cut must lie in the part's last quarter
const SENTENCE_END_RE = /[.!?]/;
const CUT_SPACE_RE = /[^\S\t]/; // whitespace, but never a table cell's tab

/** One part of a text: `text` is whole.slice(start16, coreEnd16); offsets are UTF-16 units. */
export type TextPart = { start16: number; text: string; coreStart16: number; coreEnd16: number };

/** Anything with a range and a type: a detected span or a review-only possible span. */
export type RangedSpan = { start: number; end: number; entity_type: string };

/** The part target in code points for a per-request cap (`effectiveMaxTextChars`). */
export function partTargetFor(maxTextChars: number): number {
	return Math.min(maxTextChars - PART_MARGIN, PART_TARGET_MAX);
}

/** The part target in code points for a verified capabilities document (or null). */
export function partTarget(
	caps: { maxTextChars?: number; maxBodyBytes?: number } | null | undefined,
): number {
	return partTargetFor(effectiveMaxTextChars(caps));
}

/** The code points of `text` and the UTF-16 offset of each (plus the end). */
function codePointIndex(text: string): { chars: string[]; at: number[] } {
	const chars: string[] = [];
	const at: number[] = [];
	let unit = 0;
	for (const ch of text) {
		chars.push(ch);
		at.push(unit);
		unit += ch.length;
	}
	at.push(unit);
	return { chars, at };
}

/** The last index in the ascending `list` with list[i] <= value, else -1. */
function lastAtMost(list: number[], value: number): number {
	let lo = 0;
	let hi = list.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		if (list[mid] <= value) lo = mid + 1;
		else hi = mid - 1;
	}
	return hi;
}

/**
 * Where to cut a block longer than the room left: after the last sentence end in the final
 * SENTENCE_WINDOW code points before `limit`, else after the last whitespace after `from`, else at
 * `limit`.
 */
function cutInsideBlock(chars: string[], from: number, limit: number): number {
	for (let i = limit - 1; i > Math.max(from, limit - SENTENCE_WINDOW); i--) {
		if (CUT_SPACE_RE.test(chars[i]) && SENTENCE_END_RE.test(chars[i - 1])) return i;
	}
	for (let i = limit - 1; i > from; i--) {
		if (CUT_SPACE_RE.test(chars[i])) return i + 1;
	}
	return limit;
}

/**
 * Cuts `text` into parts of at most `target` code points (overlap included).
 * `options.headingEnds`: UTF-16 offsets right after a heading block's '\n' (preferred cuts, like an
 * empty block). The node lists none: its input is plain text.
 */
export function split(
	text: string,
	target: number,
	options: { headingEnds?: number[] } = {},
): TextPart[] {
	if (typeof text !== 'string') throw new TypeError('chunker.split: text');
	if (!Number.isSafeInteger(target) || target <= OVERLAP * 2) {
		throw new RangeError('chunker.split: target');
	}
	const { chars, at } = codePointIndex(text);
	const n = chars.length;
	const headings = new Set(Array.isArray(options.headingEnds) ? options.headingEnds : []);

	// Block boundaries: the code point right after each '\n' (never after '\t').
	const boundaries: number[] = [];
	const preferred: number[] = [];
	for (let i = 0; i < n; i++) {
		if (chars[i] !== '\n') continue;
		boundaries.push(i + 1);
		const emptyBlock = i === 0 || chars[i - 1] === '\n';
		if (emptyBlock || headings.has(at[i + 1])) preferred.push(i + 1);
	}

	const parts: TextPart[] = [];
	let start = 0; // the part's first code point (overlap included)
	let coreStart = 0;
	while (parts.length === 0 || coreStart < n) {
		let cut: number;
		let next: number;
		if (n - start <= target) {
			cut = n;
			next = n;
		} else {
			const limit = start + target;
			const b = lastAtMost(boundaries, limit);
			if (b >= 0 && boundaries[b] > coreStart) {
				const p = lastAtMost(preferred, limit);
				const good =
					p >= 0 && preferred[p] > coreStart && preferred[p] >= start + target * PREFERRED_FROM;
				cut = good ? preferred[p] : boundaries[b];
				next = cut;
			} else {
				cut = cutInsideBlock(chars, coreStart, limit);
				next = Math.max(cut - OVERLAP, coreStart + 1);
			}
		}
		parts.push({
			start16: at[start],
			text: text.slice(at[start], at[cut]),
			coreStart16: at[coreStart],
			coreEnd16: at[cut],
		});
		coreStart = cut;
		start = next;
	}
	assertCover(text, parts);
	return parts;
}

/** Throws unless the parts' cores cover `text` exactly and each part is its slice. */
export function assertCover(text: string, parts: TextPart[]): void {
	let expect = 0;
	for (const part of parts) {
		if (
			part.coreStart16 !== expect ||
			part.start16 > part.coreStart16 ||
			part.coreEnd16 < part.coreStart16
		) {
			throw new Error('chunker: parts do not cover the text');
		}
		if (text.slice(part.start16, part.coreEnd16) !== part.text) {
			throw new Error('chunker: part text mismatch');
		}
		expect = part.coreEnd16;
	}
	if (expect !== text.length) throw new Error('chunker: parts do not cover the text');
}

type Tagged<S> = S & { part: number };

/** Shifted copies of every part's spans, tagged with the part index. */
function shifted<S extends RangedSpan>(
	parts: Array<{ start16: number }>,
	perPart: Array<S[] | undefined>,
): Array<Tagged<S>> {
	const out: Array<Tagged<S>> = [];
	parts.forEach((part, index) => {
		const spans = Array.isArray(perPart[index]) ? (perPart[index] as S[]) : [];
		for (const s of spans) {
			out.push({ ...s, start: s.start + part.start16, end: s.end + part.start16, part: index });
		}
	});
	out.sort((a, b) => a.start - b.start || b.end - a.end);
	return out;
}

/** Sorted, exact duplicates dropped, partial overlaps of different parts united. */
function mergeList<S extends RangedSpan>(list: Array<Tagged<S>>): S[] {
	const out: Array<Tagged<S>> = [];
	for (const s of list) {
		const prev = out[out.length - 1];
		if (
			prev &&
			prev.start === s.start &&
			prev.end === s.end &&
			prev.entity_type === s.entity_type
		) {
			continue;
		}
		if (prev && prev.part !== s.part && s.end <= prev.end) continue; // seen whole in another part
		if (prev && prev.part !== s.part && s.start < prev.end && s.end > prev.end) {
			// An ID truncated at a cut: protect the union (never less).
			const longer = s.end - s.start > prev.end - prev.start ? s : prev;
			out[out.length - 1] = { ...longer, start: prev.start, end: s.end, part: s.part };
			continue;
		}
		out.push(s);
	}
	return out.map((tagged) => {
		const span = { ...tagged } as Partial<Tagged<S>>;
		delete span.part;
		return span as unknown as S;
	});
}

/** True when [start, end) touches a range of the sorted, disjoint `ranges` (binary search). */
function touches(ranges: Array<[number, number]>, start: number, end: number): boolean {
	let lo = 0;
	let hi = ranges.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		if (ranges[mid][0] < end) lo = mid + 1;
		else hi = mid - 1;
	}
	return hi >= 0 && ranges[hi][1] > start;
}

/** The union of the (sorted) spans as disjoint [start, end) ranges. */
function unionRanges(spans: Array<{ start: number; end: number }>): Array<[number, number]> {
	const ranges: Array<[number, number]> = [];
	for (const s of spans) {
		const last = ranges[ranges.length - 1];
		if (last && s.start <= last[1]) last[1] = Math.max(last[1], s.end);
		else ranges.push([s.start, s.end]);
	}
	return ranges;
}

/**
 * The whole text's spans from every part's analyze result (UTF-16 offsets into each part's text).
 * Entities come back sorted by start, longer first.
 */
export function merge<E extends RangedSpan, P extends RangedSpan>(
	parts: Array<{ start16: number }>,
	perPart: Array<{ entities: E[]; possible?: P[] } | undefined>,
): { entities: E[]; possible: P[] } {
	const entities = mergeList(
		shifted(
			parts,
			perPart.map((r) => r?.entities),
		),
	);
	const covered = unionRanges(entities);
	const possible = mergeList(
		shifted(
			parts,
			perPart.map((r) => r?.possible),
		),
	).filter((p) => !touches(covered, p.start, p.end));
	return { entities, possible };
}
