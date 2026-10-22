/**
 * The Protect pipeline of the extension (`lib/id-edits.js` `anonIdEdits.anonymize`) as pure
 * functions over an ID set (state v2, `idModel.ts`). No n8n imports, no I/O.
 *
 * `anonymizer.ts` (the CDN-mirrored engine) knows none of the set's rules; `protect` applies them
 * around `anonymizeFromSpans`, in the extension's order:
 *  0. companies by legal form (`companySpans`), then skipped values dropped;
 *  0b. the Additionally protect spans (`extraSpans`, own placeholders blocked, skipped values
 *     dropped) merged with the gateway spans and the table matches (`mergeExtra`);
 *  1. the kept spans relabelled with their placeholder prefix (EMAIL_ADDRESS → EMAIL, PHONE_NUMBER
 *     → PHONE, IBAN_CODE → IBAN);
 *  2. the table: main records, other group members under synthetic keys `~i`, name parts, then
 *     every tombstone and alias as '' (never minted, never matched; sequential counters count them);
 *  3. `anonymizeFromSpans` with the own-placeholder test, never minting a key the text spells;
 *  4. every new entry stored as a record (`mine: false`) or a PERSON name part, in every numbering
 *     mode (masked sets mint random internal keys);
 *  5. one relabel / mask splice: `[~i]` → the group key; `typed` → `[PREFIX]`; `redacted` →
 *     `[REDACTED]`;
 *  6. the possible IDs left in the output (`findPossible`; skipped with `findPossible: false`).
 *
 * Not ported (no n8n equivalent): rev / dirty / epoch bookkeeping, locks, `ignored` (pass
 * `isSkipped` instead), the side panel.
 */
import { anonymizeFromSpans, MAX_SUFFIX_DIGITS, pgwSpansFromTable } from './anonymizer';
import type { AnonymizeFromSpansOptions } from './anonymizer';
import { extraSpans, mergeExtra } from './extraDetect';
import {
	addUsed,
	companySpans,
	emptyContent,
	extraBlockTest,
	fromV1,
	hasOwn,
	isMasked,
	liveKeys,
	namePart,
	ownPlaceholderTest,
	prefixFor,
	REDACTED_LABEL,
	revealTable as modelRevealTable,
	typeFromPrefix,
} from './idModel';
import type { FlatSet, IdRecord, IdSetContent } from './idModel';
import { detectedValues as possibleDetectedValues, findPossible } from './possible';
import type { DetectedValue, PossibleId } from './possible';
import type { AnonymizeResult, LocalEntity, Numbering, PlaceholderTable, Span } from './types';

/** The ID set the pipeline works on (extension state v2 content). Mutated in place by `protect`. */
export type PipelineState = IdSetContent;

/** Additionally protect options: protect every number / currency value / company with a legal form. */
export type ExtraProtect = { NUMBER?: boolean; AMOUNT?: boolean; COMPANY?: boolean };

export type ProtectOptions = {
	extra?: ExtraProtect;
	/** The gateway's possible values (`detectedValues`), listed as possible IDs. */
	detected?: ReadonlyArray<{ value: string; type: string }>;
	/**
	 * Values never protected (the extension's `skipped`), tested on the trimmed span text after
	 * companies are typed, so a skipped "Modra" never blocks "Modra Vila d.o.o.". Also never listed
	 * as possible IDs.
	 */
	isSkipped?: (value: string) => boolean;
	/**
	 * List the possible IDs left in clear (`findPossible`). Default true, as the extension. False
	 * skips the scan (its cost grows with the set's PERSON / COMPANY IDs times the text) and returns
	 * no possibles, for a caller that would discard them.
	 */
	findPossible?: boolean;
};

/** One replaced range in the protected text. */
export type ProtectEntity = {
	/** The record type code (EMAIL_ADDRESS, COMPANY, ...); PERSON for name parts. */
	entityType: string;
	/** What was written into the text: `[KEY]`, `[PREFIX]` (typed) or `[REDACTED]`. */
	placeholder: string;
	/** UTF-16 offsets into the protected text. */
	start: number;
	end: number;
	score: number;
	/** The live key the placeholder belongs to (the group key; a name part's person), or null. */
	key: string | null;
	/** The original text it replaced (trimmed). */
	value: string;
};

export type ProtectOutput = {
	text: string;
	entities: ProtectEntity[];
	possible: PossibleId[];
	possibleMore: boolean;
	/** Keys minted by this call (records and PERSON name parts). */
	minted: string[];
};

/** A fresh, empty set. */
export function emptyState(numbering: Numbering): PipelineState {
	return emptyContent(numbering);
}

/** A flat map (`{KEY: value}` table, used keys, hand-added keys) as a set (`anonIdModel.fromV1`). */
export function fromFlatMap(flat: FlatSet, numbering: Numbering): PipelineState {
	return fromV1(flat, numbering);
}

/** What Reveal uses: live keys, aliases and name parts; nothing for a masked set. */
export function revealTable(state: PipelineState): Record<string, string> {
	return modelRevealTable(state);
}

/** The distinct values of the gateway's possible spans over the ORIGINAL text. */
export function detectedValues(
	text: string,
	possibleSpans: ReadonlyArray<{ start: number; end: number; entity_type: string }>,
): DetectedValue[] {
	return possibleDetectedValues(text, possibleSpans);
}

/** The spans anonymizeFromSpans gets: the placeholder PREFIX as their type. */
export function withPrefixes(spans: Span[]): Span[] {
	return spans.map((s) => ({ ...s, entity_type: prefixFor(s.entity_type) }));
}

/**
 * The table handed to anonymizeFromSpans: main records (key → value), the other group members
 * under synthetic keys `~i` (i = index in ids), the name parts, then every tombstone and alias as
 * ''.
 */
export function protectTable(state: PipelineState): PlaceholderTable {
	const live = liveKeys(state);
	const table: PlaceholderTable = {};
	state.ids.forEach((r, i) => {
		table[r.main ? r.key : `~${i}`] = r.value;
	});
	for (const [key, s] of Object.entries(state.subKeys)) table[key] = s.value;
	for (const key of state.used) {
		if (!live.has(key) && !hasOwn(state.subKeys, key)) table[key] = '';
	}
	return table;
}

/** A key-shaped word (the extension's `\b...\b` pattern), tested on one whole ASCII word run. */
const KEY_WORD_RE = /^[A-Z][A-Z0-9_]*_[a-z0-9]+(?:_[A-Z][A-Z0-9_]*)?$/;
const ASCII_WORD_RUN_RE = /[A-Za-z0-9_]+/g;
/**
 * The longest key anonymizeFromSpans can mint: a 64-character type (ENTITY_TYPE_RE), '_', a
 * sequential suffix of MAX_SUFFIX_DIGITS digits and '_SURNAME'. A longer word can never clash with
 * a minted key, and its type part is too long to move a sequential counter.
 */
const MAX_MINTED_KEY_LENGTH = 64 + 1 + MAX_SUFFIX_DIGITS + '_SURNAME'.length;

/**
 * The minted keys that Reveal would also read OUTSIDE the placeholders of `local.text` (as `[KEY]`
 * or a bare word-bounded `KEY`). The splice can make a new word boundary: "PERSON_1Ana" with "Ana"
 * protected leaves a bare "PERSON_1" in front of the placeholder. Every key is one ASCII word run,
 * so each word run is looked up instead of compiling the keys into one pattern (as revealText).
 */
export function mintedInClear(local: AnonymizeResult): string[] {
	const minted = new Set(Object.keys(local.newEntries));
	if (minted.size === 0) return [];
	const placeholders = new Map(local.entities.map((e) => [e.start, e.end]));
	const clash = new Set<string>();
	for (const m of local.text.matchAll(/\[([A-Za-z0-9_]+)\]|\b([A-Za-z0-9_]+)\b/g)) {
		const key = m[1] !== undefined ? m[1] : m[2];
		if (!minted.has(key)) continue;
		const at = m.index ?? 0;
		if (placeholders.get(at) === at + m[0].length) continue;
		clash.add(key);
	}
	return [...clash];
}

/**
 * anonymizeFromSpans, never minting a key the protected text already spells: the key-shaped words
 * of the text join `table` as '' first, and a key that still lands in clear text through a new word
 * boundary is reserved the same way and the splice redone. `table` is changed in place.
 */
export function anonymizeReserved(
	text: string,
	spans: Span[],
	table: PlaceholderTable,
	options: AnonymizeFromSpansOptions,
): AnonymizeResult {
	// The extension runs its \b-bounded pattern over the whole text, which backtracks
	// quadratically inside one long word ("X_1_X_1_X..."). A match is always one whole ASCII word
	// run, so each run up to the longest mintable key is tested on its own: linear, same words.
	for (const m of text.matchAll(ASCII_WORD_RUN_RE)) {
		const word = m[0];
		if (word.length > MAX_MINTED_KEY_LENGTH || !KEY_WORD_RE.test(word)) continue;
		if (!hasOwn(table, word)) table[word] = '';
	}
	for (;;) {
		const local = anonymizeFromSpans(text, spans, table, options);
		const clash = mintedInClear(local);
		if (clash.length === 0) return local;
		for (const key of clash) table[key] = '';
	}
}

/** Stores what anonymizeFromSpans found for the first time; returns the minted keys. */
function storeFound(state: PipelineState, local: AnonymizeResult): string[] {
	const newEntries = local.newEntries;
	const minted = Object.keys(newEntries);
	if (minted.length === 0) return minted;
	const typeOf = new Map<string, string>();
	for (const entity of local.entities) {
		if (!typeOf.has(entity.replacement)) typeOf.set(entity.replacement, entity.entity_type);
	}
	const added: IdRecord[] = [];
	for (const key of minted) {
		const sub = /^(.+)_(?:NAME|SURNAME)$/.exec(key);
		if (sub && hasOwn(newEntries, sub[1])) {
			state.subKeys[key] = { of: sub[1], value: newEntries[key], rec: newEntries[sub[1]] };
			continue;
		}
		const found = typeOf.has(`[${key}]`) ? typeOf.get(`[${key}]`) : namePart(key);
		added.push({
			value: newEntries[key],
			key,
			type: typeFromPrefix(found),
			mine: false,
			main: true,
		});
	}
	state.ids = [...added, ...state.ids];
	addUsed(state, ...minted);
	return minted;
}

/** The visible placeholder of one output entity: the group key, or the mask label. */
function labelFor(
	state: PipelineState,
	entity: LocalEntity,
	owner: IdRecord | null,
	isSub: boolean,
): string {
	if (state.numbering === 'redacted') return REDACTED_LABEL;
	if (state.numbering === 'typed') {
		return `[${prefixFor(owner ? owner.type : entity.entity_type)}]`;
	}
	return owner && !isSub ? `[${owner.key}]` : entity.replacement;
}

/**
 * One splice over the output, by offset: `[~i]` → the group key; in a masked set every
 * placeholder → `[PREFIX]` / `[REDACTED]`. `records` is the ids array the table was built from.
 */
function relabel(
	state: PipelineState,
	records: IdRecord[],
	table: PlaceholderTable,
	local: AnonymizeResult,
): { text: string; entities: ProtectEntity[] } {
	const masked = isMasked(state);
	const newEntries = local.newEntries;
	const mains = new Map(state.ids.filter((r) => r.main).map((r) => [r.key, r]));
	const parts: string[] = [];
	const entities: ProtectEntity[] = [];
	let cursor = 0;
	let outLen = 0;
	for (const entity of local.entities) {
		const bare = entity.replacement.slice(1, -1);
		let owner: IdRecord | null = null;
		let isSub = false;
		if (bare.startsWith('~')) {
			owner = records[Number(bare.slice(1))] || null;
			if (!owner && !masked) {
				throw new Error(`Unmapped synthetic placeholder ${entity.replacement}`);
			}
		} else if (mains.has(bare)) {
			owner = mains.get(bare) || null;
		} else if (hasOwn(state.subKeys, bare)) {
			isSub = true;
			owner = mains.get(state.subKeys[bare].of) || null;
		}
		const label = labelFor(state, entity, owner, isSub);
		const between = local.text.slice(cursor, entity.start);
		parts.push(between, label);
		outLen += between.length;
		// The original the placeholder stands for.
		const original =
			hasOwn(table, bare) && table[bare]
				? table[bare]
				: hasOwn(newEntries, bare)
					? newEntries[bare]
					: '';
		entities.push({
			entityType: isSub ? 'PERSON' : owner ? owner.type : entity.entity_type,
			placeholder: label,
			start: outLen,
			end: outLen + label.length,
			score: entity.score,
			key: owner ? owner.key : isSub ? state.subKeys[bare].of : null,
			value: String(original).trim(),
		});
		outLen += label.length;
		cursor = entity.end;
	}
	parts.push(local.text.slice(cursor));
	return { text: parts.join(''), entities };
}

/**
 * Substitutes the gateway spans, the Additionally protect matches and every ID of the set in
 * `text`, stores the IDs found for the first time (in every numbering mode; `state` is mutated in
 * place: new records newest first, name parts, used keys) and lists the possible IDs left in
 * clear. `spans` index `text` in UTF-16 units.
 */
export function protect(
	state: PipelineState,
	text: string,
	spans: Span[],
	options: ProtectOptions = {},
): ProtectOutput {
	const records = state.ids;
	const isSkipped = options && typeof options.isSkipped === 'function' ? options.isSkipped : null;
	const notSkipped = (s: Span): boolean =>
		!isSkipped || !isSkipped(String(text.slice(s.start, s.end)).trim());
	// Skipped values go before the merge: a skipped "Modra" never blocks the COMPANY
	// "Modra Vila d.o.o." it lies in.
	const gateway = companySpans(state, text, spans).filter(notSkipped);
	const isOwnPlaceholder = ownPlaceholderTest(state);
	// Wider than isOwnPlaceholder: Additionally Protect never cuts into a minted placeholder.
	const extra = extraSpans(text, options && options.extra, {
		isOwnPlaceholder: extraBlockTest(state),
	}).filter(notSkipped);
	const table = protectTable(state);
	const merged =
		extra.length > 0
			? mergeExtra(text, gateway, pgwSpansFromTable(text, table), extra)
			: { gateway, extra };
	const local = anonymizeReserved(text, withPrefixes([...merged.gateway, ...merged.extra]), table, {
		sequential: state.numbering === 'sequential',
		isOwnPlaceholder,
	});
	const minted = storeFound(state, local);
	const out = relabel(state, records, table, local);
	const found =
		options && options.findPossible === false
			? { possible: [], more: false }
			: findPossible(state, out.text, out.entities, {
					detected: options && options.detected,
					isExcluded: isSkipped || undefined,
				});
	return {
		text: out.text,
		entities: out.entities,
		possible: found.possible,
		possibleMore: found.more,
		minted,
	};
}

export { companySpans, extraSpans, mergeExtra, findPossible, ownPlaceholderTest };
export type { DetectedValue, PossibleId };
