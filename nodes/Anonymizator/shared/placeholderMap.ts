/**
 * Placeholder map input normalisation and extension ID file (v1 and v2) parsing and writing.
 *
 * Accepted inputs (one normaliser shared by Reveal's map and Protect's existing map):
 * - a JSON string of any of the below;
 * - an extension ID file (`{ format: 'anonymizator-id-file', version: 1 | 2, ... }`), validated
 *   with the same rules, in the same order, as the extension's `sidepanel/sidepanel-idfile.js`
 *   parse(); the result also carries the extension's v2 ID set (`set`);
 * - an array of `{ placeholder, value }` (or `{ key, value }`);
 * - a plain object with bare (`PERSON_a7k2q`) or bracketed (`[PERSON_a7k2q]`) keys;
 * - a Protect output item (`{ placeholderMap: ..., idFile?: ... }`): its `idFile` when that is a
 *   valid ID file covering the `placeholderMap` (lossless: groups and types), else its
 *   `placeholderMap`, even when Include Input Fields copied an older ID file's top-level fields
 *   (`format`, `ids`, ...) into the item.
 * Every key must pass `isValidKey`. A bracketed value is a reversed entry only under a key that is
 * not a placeholder, or a minted-looking value under a key that is not minted-looking. Empty/whitespace values are tombstones: they go to `used`, never
 * to the table (a tombstone in a reveal table would erase text). Insertion order is preserved.
 *
 * `toIdFile(set, name?)` writes an ID file v2 exactly like the extension's anonSerializeIdFile and
 * refuses a set the extension would refuse (IdRules.validateSet, then its own v2 parser).
 *
 * Bad input throws PlaceholderMapError with a message fit to show the user as-is. Messages name
 * keys and positions but never echo values, which are the protected personal data.
 */
import { isValidKey, MAX_SUFFIX_DIGITS } from './anonymizer';
import { PlaceholderMapError } from './errors';
import type { Alias, IdRecord, SubKey } from './idModel';
import type { IdFileEntry, IdFileV1, Numbering, PlaceholderTable } from './types';

export { PlaceholderMapError };

export const ID_FILE_FORMAT = 'anonymizator-id-file';
/** The version `toIdFile` writes (the extension's ANON_ID_FILE_VERSION). */
export const ID_FILE_VERSION = 2;
/** The versions an input ID file may have (the extension's ANON_ID_FILE_VERSIONS). */
export const ID_FILE_VERSIONS: readonly number[] = [1, 2];
export const ID_FILE_SUFFIX = '-anonymizator-ids.json';

/** Placeholder styles an ID file may record (the extension's IdSet.NUMBERING). */
export const NUMBERINGS: readonly Numbering[] = ['random', 'sequential', 'typed', 'redacted'];

/** Numberings whose placeholders are labels: no groups and no reveal-only placeholders. */
const MASKED_NUMBERINGS: readonly Numbering[] = ['typed', 'redacted'];

/** The extension's own ID file error messages, used as the first sentence of ours. */
export const ID_FILE_ERRORS = {
	format: 'This file is not an ID file this version can open.',
	entries: 'This ID file has missing or invalid entries.',
	duplicates: 'This ID file has duplicate IDs or placeholders.',
} as const;

/** Bracketed placeholder as it appears in text and in the ID file. */
const BRACKETED_RE = /^\[[A-Z][A-Za-z0-9_]*\]$/;

/** A generated-looking key (`TYPE_suffix`, optional sub-key), used to spot a reversed map. */
const TYPED_KEY_RE = /^[A-Z][A-Z_]*_[a-z0-9]+(?:_[A-Z_]+)?$/;

/** An entity type code (the extension's IdRules.TYPE_RE). */
const TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

const ACCEPTED_FORMATS =
	'Use an object such as {"PERSON_a7k2q": "Janez Novak"} (keys with or without brackets), ' +
	'a list of {"placeholder": "[PERSON_a7k2q]", "value": "Janez Novak"}, ' +
	'the placeholderMap of a Protect result, or an ID file saved by the Anonymizator extension.';

/**
 * One ID of a v2 set (the extension's IdRecord; records sharing a key form a group), a PERSON name
 * part (`subKeys` entry: `of` is the owning key, `rec` the record value it came from) and a
 * reveal-only placeholder (`aliases` entry). One definition, in `idModel.ts`, shared with the
 * Protect pipeline.
 */
export type { IdRecord };
export type IdNamePart = SubKey;
export type IdRevealOnly = Alias;

/** The extension's v2 ID set as LOAD_ID_SET takes it (`anonParseIdFile(...).set`). */
export type IdSet = {
	/** Newest first. */
	ids: IdRecord[];
	subKeys: Record<string, IdNamePart>;
	aliases: Record<string, IdRevealOnly>;
	/** Every key ever used (live keys, name parts, aliases, tombstones), bare. */
	used: string[];
	numbering: Numbering;
};

/** What `toIdFile` takes: an IdSet or anything shaped like one (e.g. the Protect pipeline state). */
export type IdSetInput = {
	ids: readonly IdRecord[];
	subKeys?: Readonly<Record<string, IdNamePart>>;
	aliases?: Readonly<Record<string, IdRevealOnly>>;
	used: readonly string[];
	numbering: Numbering;
};

/** One `ids` entry of an ID file v2; `main` only for keys shared by several entries. */
export type IdFileV2Entry = {
	value: string;
	placeholder: string;
	type: string;
	addedByYou: boolean;
	main?: boolean;
};

/** Extension-compatible ID file, version 2 (`sidepanel/sidepanel-idfile.js`). */
export type IdFileV2 = {
	format: 'anonymizator-id-file';
	version: 2;
	name: string;
	numbering: Numbering;
	ids: IdFileV2Entry[];
	nameParts: Array<{ placeholder: string; value: string; of: string; from: string }>;
	revealOnly: Array<{ placeholder: string; value: string; of: string }>;
	usedPlaceholders: string[];
};

/** Full result of parsing a map input. */
export type ParsedPlaceholderMap = {
	/**
	 * Bare-key reveal table without tombstones, in input order. For an ID file: every main value,
	 * then (v2) every name part and reveal-only placeholder. Group members that are not the main
	 * value are only in `set`.
	 */
	table: PlaceholderTable;
	/** Every key ever used (tombstones + table keys), bare. Minting must avoid all of them. */
	used: string[];
	/** Keys the user added by hand (ID file `addedByYou: true`); empty for other inputs. */
	mine: string[];
	/** Numbering recorded in an ID file input, if any. */
	numbering?: Numbering;
	/** The extension's v2 ID set, for ID file inputs only (a v1 file converted by the fromV1 rules). */
	set?: IdSet;
};

/** Extra state carried into an ID file. */
export type IdFileExtras = {
	mine?: readonly string[];
	used?: readonly string[];
};

function hasOwn(obj: object, key: string): boolean {
	return Object.prototype.hasOwnProperty.call(obj, key);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Short, quoted rendering of a user-supplied key for an error message. */
function quote(raw: string): string {
	const shown = raw.length > 40 ? `${raw.slice(0, 40)}...` : raw;
	return JSON.stringify(shown);
}

function describeType(value: unknown): string {
	if (value === null) return 'null';
	if (Array.isArray(value)) return 'a list';
	return typeof value === 'object' ? 'an object' : `a ${typeof value}`;
}

/** Why `key` (already normalised) is not a valid placeholder, for an error message. */
function keyProblem(key: string): string {
	if (key === '') return 'it is empty';
	const digits = /_(\d+)$/.exec(key);
	if (digits && digits[1].length > MAX_SUFFIX_DIGITS) {
		return `its number has more than ${MAX_SUFFIX_DIGITS} digits`;
	}
	return 'a placeholder must start with a capital letter and contain only letters, digits and underscores (e.g. PERSON_a7k2q)';
}

function isNumbering(value: unknown): value is Numbering {
	return typeof value === 'string' && (NUMBERINGS as readonly string[]).includes(value);
}

/**
 * The parent of a PERSON name/surname sub-key, or null (the extension's `subKeyParent`): `K_NAME` /
 * `K_SURNAME` is a sub-key only when K starts with `PERSON_`, K is in `table` and K was not added by
 * the user. Only sub-keys may repeat a value.
 */
export function subKeyParent(
	key: string,
	table: PlaceholderTable,
	mine: readonly string[] | ReadonlySet<string>,
): string | null {
	const match = /^(PERSON_.+)_(?:NAME|SURNAME)$/.exec(key);
	if (!match) return null;
	const parent = match[1];
	const isMine = Array.isArray(mine)
		? (mine as readonly string[]).includes(parent)
		: (mine as ReadonlySet<string>).has(parent);
	return hasOwn(table, parent) && !isMine ? parent : null;
}

/** Keys whose value is shared with an earlier non-sub-key entry, as [first, second]. */
function findDuplicateValue(
	table: PlaceholderTable,
	mine: readonly string[] | ReadonlySet<string>,
): [string, string] | null {
	const seen = new Map<string, string>();
	for (const [key, value] of Object.entries(table)) {
		if (subKeyParent(key, table, mine)) continue;
		const first = seen.get(value.trim());
		if (first !== undefined) return [first, key];
		seen.set(value.trim(), key);
	}
	return null;
}

/**
 * Trims, strips one leading `[` and one trailing `]`, trims again and turns inner whitespace into
 * `_`. No case change. The result still has to pass `isValidKey`. Non-strings give `''`.
 */
export function normalizePlaceholder(raw: string): string {
	if (typeof raw !== 'string') return '';
	let key = raw.trim();
	if (key.startsWith('[')) key = key.slice(1);
	if (key.endsWith(']')) key = key.slice(0, -1);
	return key.trim().replace(/\s+/g, '_');
}

/** Accumulates entries in input order, with tombstones and duplicate-key detection. */
class MapBuilder {
	readonly table: PlaceholderTable = {};

	private readonly usedSet = new Set<string>();

	private readonly seen = new Map<string, string>();

	readonly mine: string[] = [];

	/** Adds one entry; `where` names it in error messages (e.g. `entry 3` or `key "X"`). */
	add(rawKey: unknown, value: unknown, where: string): void {
		if (typeof rawKey !== 'string') {
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: ${where} has no placeholder (expected text such as "[PERSON_a7k2q]", got ${describeType(rawKey)}).`,
			);
		}
		const key = normalizePlaceholder(rawKey);
		// A bracketed value is a reversed entry only when the key cannot be a placeholder, or the
		// value looks minted and the key does not: an ID value may itself be written in brackets
		// ("[ACME]" under CUSTOM_ab12c), and Protect writes such entries into its own map.
		const bracketed = typeof value === 'string' && BRACKETED_RE.test(value.trim());
		if (
			bracketed &&
			(!isValidKey(key) ||
				(TYPED_KEY_RE.test(normalizePlaceholder(value as string)) && !TYPED_KEY_RE.test(key)))
		) {
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: ${where} looks reversed (its value is a placeholder). Use the placeholder as the key and the original text as the value, e.g. {"PERSON_a7k2q": "Janez Novak"}.`,
			);
		}
		if (!isValidKey(key)) {
			if (typeof value === 'string' && TYPED_KEY_RE.test(normalizePlaceholder(value))) {
				throw new PlaceholderMapError(
					'entries',
					`Invalid placeholder map: ${where} looks reversed. Use the placeholder as the key and the original text as the value, e.g. {"PERSON_a7k2q": "Janez Novak"}.`,
				);
			}
			// Named by position only: an invalid key may be a real value (a reversed or mangled map).
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: ${where} has an invalid placeholder: ${keyProblem(key)}.`,
			);
		}
		if (typeof value !== 'string') {
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: the value of "${key}" must be text, got ${describeType(value)}.`,
			);
		}
		const previous = this.seen.get(key);
		if (previous !== undefined) {
			throw new PlaceholderMapError(
				'duplicates',
				`Invalid placeholder map: placeholder "${key}" appears more than once (as ${quote(previous)} and ${quote(rawKey)}).`,
			);
		}
		this.seen.set(key, rawKey);
		this.usedSet.add(key);
		if (value.trim() !== '') this.table[key] = value;
	}

	addUsed(key: string): void {
		this.usedSet.add(key);
	}

	result(numbering?: Numbering): ParsedPlaceholderMap {
		const mine = this.mine.filter((k) => hasOwn(this.table, k));
		const parsed: ParsedPlaceholderMap = { table: this.table, used: [...this.usedSet], mine };
		if (numbering) parsed.numbering = numbering;
		return parsed;
	}
}

function fromObject(obj: Record<string, unknown>): ParsedPlaceholderMap {
	const builder = new MapBuilder();
	Object.entries(obj).forEach(([rawKey, value], i) => {
		builder.add(rawKey, value, `entry ${i + 1}`);
	});
	return builder.result();
}

function fromList(list: unknown[]): ParsedPlaceholderMap {
	const builder = new MapBuilder();
	list.forEach((item, i) => {
		const where = `entry ${i + 1}`;
		if (!isPlainObject(item)) {
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: ${where} must be an object like {"placeholder": "[PERSON_a7k2q]", "value": "Janez Novak"}, got ${describeType(item)}.`,
			);
		}
		const rawKey = hasOwn(item, 'placeholder') ? item.placeholder : item.key;
		builder.add(rawKey, item.value, where);
		if (item.addedByYou === true && typeof rawKey === 'string') {
			builder.mine.push(normalizePlaceholder(rawKey));
		}
	});
	return builder.result();
}

function idFileError(code: keyof typeof ID_FILE_ERRORS, detail: string): PlaceholderMapError {
	return new PlaceholderMapError(code, `${ID_FILE_ERRORS[code]} ${detail}`);
}

function placeholderProblem(placeholder: unknown): string | null {
	if (typeof placeholder !== 'string') return `it must be text, got ${describeType(placeholder)}`;
	if (!BRACKETED_RE.test(placeholder)) {
		return 'it must be a bracketed placeholder such as "[PERSON_a7k2q]"';
	}
	return isValidKey(placeholder.slice(1, -1))
		? null
		: `its number has more than ${MAX_SUFFIX_DIGITS} digits`;
}

function isText(value: unknown): value is string {
	return typeof value === 'string' && value.trim() !== '';
}

function unbracket(placeholder: string): string {
	return placeholder.slice(1, -1);
}

// --- Types of keys (port of lib/id-model.js typeFromKey) ---

/** Type code → placeholder prefix (anonIdModel PREFIXES). */
const TYPE_PREFIXES: Readonly<Record<string, string>> = {
	PERSON: 'PERSON',
	COMPANY: 'COMPANY',
	EMAIL_ADDRESS: 'EMAIL',
	PHONE_NUMBER: 'PHONE',
	IBAN: 'IBAN',
	NUMBER: 'NUMBER',
	AMOUNT: 'AMOUNT',
	CUSTOM: 'CUSTOM',
	IBAN_CODE: 'IBAN',
};

/** Placeholder prefix → type code (anonIdModel FROM_PREFIX). */
const PREFIX_TYPES: Readonly<Record<string, string>> = {
	PERSON: 'PERSON',
	COMPANY: 'COMPANY',
	EMAIL: 'EMAIL_ADDRESS',
	PHONE: 'PHONE_NUMBER',
	IBAN: 'IBAN',
	NUMBER: 'NUMBER',
	AMOUNT: 'AMOUNT',
	CUSTOM: 'CUSTOM',
};

/** anonIdModel.KNOWN_TYPES: bundled types, fallbacks and placeholder prefixes. */
const KNOWN_TYPES: readonly string[] = [
	'PERSON',
	'EMAIL_ADDRESS',
	'PHONE_NUMBER',
	'CREDIT_CARD',
	'IBAN',
	'IBAN_CODE',
	'US_SSN',
	'API_KEY',
	'URL',
	'EMSO',
	'SI_TAX_ID',
	'OIB',
	'AT_SVN',
	'ZZZS',
	'BIRTH_DATE',
	'LOCATION',
	'IP_ADDRESS',
	'PII',
	'CUSTOM',
	'COMPANY',
	'NUMBER',
	'AMOUNT',
	'EMAIL',
	'PHONE',
];

/** TYPE_suffix with a lowercase/digit suffix; the lazy TYPE keeps underscored types whole. */
const KEY_PARTS_RE = /^([A-Z][A-Z0-9_]*?)_[a-z0-9]+$/;

/** The type a key stands for when a file does not say: a known prefix or type, else CUSTOM. */
function typeFromKey(key: string): string {
	const match = KEY_PARTS_RE.exec(key);
	if (!match) return 'CUSTOM';
	const prefix = match[1];
	if (
		!hasOwn(TYPE_PREFIXES, prefix) &&
		!hasOwn(PREFIX_TYPES, prefix) &&
		!KNOWN_TYPES.includes(prefix)
	) {
		return 'CUSTOM';
	}
	// IBAN_CODE_1 → IBAN, like a found IBAN now.
	const mapped = hasOwn(TYPE_PREFIXES, prefix) ? TYPE_PREFIXES[prefix] : prefix;
	if (hasOwn(PREFIX_TYPES, mapped)) return PREFIX_TYPES[mapped];
	return TYPE_RE.test(mapped) ? mapped : 'CUSTOM';
}

/**
 * A flat v1 table as a v2 ID set (the extension's anonIdModel.fromV1): PERSON name/surname sub-keys
 * of found parents become name parts, every other entry a single-member ID typed from its key,
 * newest first (the table is oldest first). Values are taken as they are; the ID file parser trims
 * them first.
 */
export function idSetFromTable(
	table: PlaceholderTable,
	numbering: Numbering,
	extras?: IdFileExtras,
): IdSet {
	const mine = new Set((extras?.mine ?? []).filter((k) => typeof k === 'string'));
	const ids: IdRecord[] = [];
	const subKeys: Record<string, IdNamePart> = {};
	for (const [key, value] of Object.entries(table)) {
		if (typeof value !== 'string') continue;
		const parent = subKeyParent(key, table, mine);
		if (parent) {
			subKeys[key] = { of: parent, value, rec: String(table[parent]) };
		} else {
			ids.unshift({ value, key, type: typeFromKey(key), mine: mine.has(key), main: true });
		}
	}
	const used = [
		...new Set([
			...(extras?.used ?? []).filter((k) => typeof k === 'string'),
			...Object.keys(table),
		]),
	];
	return {
		ids,
		subKeys,
		aliases: {},
		used,
		numbering: isNumbering(numbering) ? numbering : 'random',
	};
}

/**
 * Bare-key reveal table of a set, in file order: every main value, then every name part, then every
 * reveal-only placeholder (so a main value comes before an alias holding the same value). Unlike the
 * extension's revealTable, a masked set keeps its table: the node's Placeholder Style decides.
 */
function tableOfSet(set: IdSet, fileOrderIds: readonly IdRecord[]): PlaceholderTable {
	const table: PlaceholderTable = {};
	for (const record of fileOrderIds) if (record.main) table[record.key] = record.value;
	for (const [key, part] of Object.entries(set.subKeys)) table[key] = part.value;
	for (const [key, alias] of Object.entries(set.aliases)) table[key] = alias.value;
	return table;
}

/** Keys whose main record was added by the user, in file order. */
function mineOfSet(fileOrderIds: readonly IdRecord[]): string[] {
	return fileOrderIds.filter((r) => r.main && r.mine).map((r) => r.key);
}

/** The extension's v1 parse rules with specific messages, then the fromV1 conversion. */
function fromIdFileV1(data: Record<string, unknown>, numbering: Numbering): ParsedPlaceholderMap {
	const list = data.ids as unknown[];
	if (list.length === 0) throw idFileError('entries', 'Its "ids" list is empty.');

	list.forEach((entry: unknown, i) => {
		const where = `Entry ${i + 1}`;
		if (!isPlainObject(entry)) throw idFileError('entries', `${where} is not an object.`);
		if (!isText(entry.value)) {
			throw idFileError('entries', `${where} has a missing or blank value.`);
		}
		const problem = placeholderProblem(entry.placeholder);
		if (problem) throw idFileError('entries', `${where} has an invalid placeholder: ${problem}.`);
	});

	const usedRaw = data.usedPlaceholders;
	if (usedRaw !== undefined) {
		if (!Array.isArray(usedRaw)) {
			throw idFileError('entries', 'Its "usedPlaceholders" must be a list.');
		}
		usedRaw.forEach((p: unknown, i) => {
			const problem = placeholderProblem(p);
			if (problem) {
				throw idFileError('entries', `usedPlaceholders item ${i + 1} is invalid: ${problem}.`);
			}
		});
	}

	const entries = list as Array<{ value: string; placeholder: string; addedByYou?: unknown }>;
	const keys = entries.map((entry) => unbracket(entry.placeholder));
	const table: PlaceholderTable = {};
	const mine: string[] = [];
	// Values are compared and stored trimmed, as the extension keeps them.
	entries.forEach((entry, i) => {
		if (hasOwn(table, keys[i])) {
			throw idFileError('duplicates', `Placeholder "[${keys[i]}]" appears more than once.`);
		}
		table[keys[i]] = entry.value.trim();
		if (entry.addedByYou === true) mine.push(keys[i]);
	});

	const duplicate = findDuplicateValue(table, mine);
	if (duplicate) {
		throw idFileError(
			'duplicates',
			`Placeholders "[${duplicate[0]}]" and "[${duplicate[1]}]" have the same value.`,
		);
	}

	const used = [...new Set([...((usedRaw as string[] | undefined) ?? []).map(unbracket), ...keys])];
	const set = idSetFromTable(table, numbering, { mine, used });
	return { table, used: set.used, mine, numbering, set };
}

/** v2 `ids` entries: text value, valid placeholder, optional type code, optional boolean main. */
function checkV2Entries(list: unknown[]): void {
	if (list.length === 0) throw idFileError('entries', 'Its "ids" list is empty.');
	list.forEach((entry: unknown, i) => {
		const where = `Entry ${i + 1}`;
		if (!isPlainObject(entry)) throw idFileError('entries', `${where} is not an object.`);
		if (!isText(entry.value)) {
			throw idFileError('entries', `${where} has a missing or blank value.`);
		}
		const problem = placeholderProblem(entry.placeholder);
		if (problem) throw idFileError('entries', `${where} has an invalid placeholder: ${problem}.`);
		if (entry.type !== undefined && (typeof entry.type !== 'string' || !TYPE_RE.test(entry.type))) {
			throw idFileError(
				'entries',
				`${where} has an invalid "type": it must be an entity type code such as "PERSON" (capital letters, digits and underscores, at most 64 characters).`,
			);
		}
		if (entry.main !== undefined && typeof entry.main !== 'boolean') {
			throw idFileError('entries', `${where} has an invalid "main": it must be true or false.`);
		}
	});
}

/** An optional top-level list: absent is empty, anything but a list is refused. */
function optionalV2List(data: Record<string, unknown>, field: string): unknown[] {
	const value = data[field];
	if (value === undefined) return [];
	if (!Array.isArray(value)) throw idFileError('entries', `Its "${field}" must be a list.`);
	return value;
}

type V2Part = { placeholder: string; value: string; of: string; from?: string };

/** nameParts / revealOnly entries and usedPlaceholders; no reveal-only entries in a masked file. */
function checkV2Parts(
	nameParts: unknown[],
	revealOnly: unknown[],
	usedPlaceholders: unknown[],
	numbering: Numbering,
): void {
	const labelled: Array<[unknown, string]> = [
		...nameParts.map((part, i): [unknown, string] => [part, `nameParts item ${i + 1}`]),
		...revealOnly.map((part, i): [unknown, string] => [part, `revealOnly item ${i + 1}`]),
	];
	for (const [part, where] of labelled) {
		if (!isPlainObject(part)) throw idFileError('entries', `${where} is not an object.`);
		if (!isText(part.value)) {
			throw idFileError('entries', `${where} has a missing or blank value.`);
		}
		const problem = placeholderProblem(part.placeholder);
		if (problem) throw idFileError('entries', `${where} has an invalid placeholder: ${problem}.`);
		const ofProblem = placeholderProblem(part.of);
		if (ofProblem) {
			throw idFileError(
				'entries',
				`${where} has an invalid "of" (the placeholder it belongs to): ${ofProblem}.`,
			);
		}
	}
	nameParts.forEach((part, i) => {
		const from = (part as Record<string, unknown>).from;
		if (from !== undefined && typeof from !== 'string') {
			throw idFileError(
				'entries',
				`nameParts item ${i + 1} has an invalid "from": it must be text.`,
			);
		}
	});
	usedPlaceholders.forEach((p, i) => {
		const problem = placeholderProblem(p);
		if (problem) {
			throw idFileError('entries', `usedPlaceholders item ${i + 1} is invalid: ${problem}.`);
		}
	});
	if (MASKED_NUMBERINGS.includes(numbering) && revealOnly.length > 0) {
		throw idFileError(
			'entries',
			`A file with "${numbering}" numbering cannot have "revealOnly" entries.`,
		);
	}
}

/** The first placeholder that repeats in `keys`, or null. */
function firstRepeat(keys: readonly string[]): string | null {
	const seen = new Set<string>();
	for (const key of keys) {
		if (seen.has(key)) return key;
		seen.add(key);
	}
	return null;
}

/**
 * Duplicates: values among ids (trimmed); a placeholder twice within nameParts or revealOnly, or
 * in two of ids / nameParts / revealOnly. Returns the set of ID keys.
 */
function checkV2Duplicates(
	list: ReadonlyArray<{ value: string; placeholder: string }>,
	nameParts: readonly V2Part[],
	revealOnly: readonly V2Part[],
): Set<string> {
	const firstByValue = new Map<string, number>();
	list.forEach((entry, i) => {
		const value = entry.value.trim();
		const first = firstByValue.get(value);
		if (first !== undefined) {
			throw idFileError('duplicates', `Entries ${first + 1} and ${i + 1} have the same value.`);
		}
		firstByValue.set(value, i);
	});
	const idKeys = new Set(list.map((entry) => unbracket(entry.placeholder)));
	const partKeys = nameParts.map((part) => unbracket(part.placeholder));
	const aliasKeys = revealOnly.map((part) => unbracket(part.placeholder));
	const partRepeat = firstRepeat(partKeys);
	if (partRepeat !== null) {
		throw idFileError(
			'duplicates',
			`Placeholder "[${partRepeat}]" appears more than once in "nameParts".`,
		);
	}
	const aliasRepeat = firstRepeat(aliasKeys);
	if (aliasRepeat !== null) {
		throw idFileError(
			'duplicates',
			`Placeholder "[${aliasRepeat}]" appears more than once in "revealOnly".`,
		);
	}
	const partId = partKeys.find((key) => idKeys.has(key));
	if (partId !== undefined) {
		throw idFileError('duplicates', `Placeholder "[${partId}]" is both an ID and a name part.`);
	}
	const aliasId = aliasKeys.find((key) => idKeys.has(key));
	if (aliasId !== undefined) {
		throw idFileError(
			'duplicates',
			`Placeholder "[${aliasId}]" is both an ID and a reveal-only placeholder.`,
		);
	}
	const both = partKeys.find((key) => aliasKeys.includes(key));
	if (both !== undefined) {
		throw idFileError(
			'duplicates',
			`Placeholder "[${both}]" is both a name part and a reveal-only placeholder.`,
		);
	}
	return idKeys;
}

type V2Entry = {
	value: string;
	placeholder: string;
	type?: string;
	addedByYou?: unknown;
	main?: boolean;
};

/** Groups: exactly one main, one type, none in a masked file. Entries per key and main values. */
function groupV2Entries(
	list: readonly V2Entry[],
	numbering: Numbering,
): { groups: Map<string, V2Entry[]>; mainValue: Map<string, string> } {
	const groups = new Map<string, V2Entry[]>();
	for (const entry of list) {
		const key = unbracket(entry.placeholder);
		const members = groups.get(key);
		if (members) members.push(entry);
		else groups.set(key, [entry]);
	}
	const mainValue = new Map<string, string>();
	for (const [key, entries] of groups) {
		const typeOf = (entry: V2Entry) => (entry.type !== undefined ? entry.type : typeFromKey(key));
		if (entries.length > 1) {
			if (MASKED_NUMBERINGS.includes(numbering)) {
				throw idFileError(
					'entries',
					`Placeholder "[${key}]" is shared by several IDs, which a file with "${numbering}" numbering cannot have.`,
				);
			}
			if (entries.filter((entry) => entry.main === true).length !== 1) {
				throw idFileError(
					'entries',
					`Placeholder "[${key}]" is shared by several IDs, and exactly one of them must have "main": true.`,
				);
			}
			if (entries.some((entry) => typeOf(entry) !== typeOf(entries[0]))) {
				throw idFileError('entries', `Placeholder "[${key}]" is shared by IDs of different types.`);
			}
		}
		const main = entries.length > 1 ? entries.find((entry) => entry.main === true) : entries[0];
		mainValue.set(key, (main as V2Entry).value.trim());
	}
	return { groups, mainValue };
}

/** The extension's v2 parse rules with specific messages. */
function fromIdFileV2(data: Record<string, unknown>, numbering: Numbering): ParsedPlaceholderMap {
	const rawList = data.ids as unknown[];
	checkV2Entries(rawList);
	const rawNameParts = optionalV2List(data, 'nameParts');
	const rawRevealOnly = optionalV2List(data, 'revealOnly');
	const rawUsed = optionalV2List(data, 'usedPlaceholders');
	checkV2Parts(rawNameParts, rawRevealOnly, rawUsed, numbering);
	const list = rawList as V2Entry[];
	const nameParts = rawNameParts as V2Part[];
	const revealOnly = rawRevealOnly as V2Part[];
	const idKeys = checkV2Duplicates(list, nameParts, revealOnly);
	const { groups, mainValue } = groupV2Entries(list, numbering);

	// One record per entry, in file order; a single-member key is its own main.
	const ids: IdRecord[] = list.map((entry) => {
		const key = unbracket(entry.placeholder);
		const single = (groups.get(key) as V2Entry[]).length === 1;
		return {
			value: entry.value.trim(),
			key,
			type: entry.type !== undefined ? entry.type : typeFromKey(key),
			mine: entry.addedByYou === true,
			main: single ? true : entry.main === true,
		};
	});

	// Name parts belong to a PERSON ID and, with `from`, to one of its values.
	const subKeys: Record<string, IdNamePart> = {};
	for (const part of nameParts) {
		const key = unbracket(part.placeholder);
		const of = unbracket(part.of);
		const members = groups.get(of);
		if (!members) {
			throw idFileError(
				'entries',
				`Name part "[${key}]" belongs to "[${of}]", which is not an ID in this file.`,
			);
		}
		const owner = members[0];
		if ((owner.type !== undefined ? owner.type : typeFromKey(of)) !== 'PERSON') {
			throw idFileError(
				'entries',
				`Name part "[${key}]" belongs to "[${of}]", which is not a PERSON ID (only names have name parts).`,
			);
		}
		const from = part.from;
		if (from !== undefined && !members.some((entry) => entry.value.trim() === from.trim())) {
			throw idFileError(
				'entries',
				`Name part "[${key}]" has a "from" that is not one of the values of "[${of}]".`,
			);
		}
		subKeys[key] = {
			of,
			value: part.value,
			rec: from !== undefined ? from.trim() : (mainValue.get(of) as string),
		};
	}

	// Reveal-only placeholders belong to an ID.
	const aliases: Record<string, IdRevealOnly> = {};
	for (const part of revealOnly) {
		const key = unbracket(part.placeholder);
		const owner = unbracket(part.of);
		if (!groups.has(owner)) {
			throw idFileError(
				'entries',
				`Reveal-only placeholder "[${key}]" belongs to "[${owner}]", which is not an ID in this file.`,
			);
		}
		aliases[key] = { value: part.value, owner };
	}

	const used = [
		...new Set([
			...(rawUsed as string[]).map(unbracket),
			...idKeys,
			...Object.keys(subKeys),
			...Object.keys(aliases),
		]),
	];
	const set: IdSet = { ids, subKeys, aliases, used, numbering };
	return { table: tableOfSet(set, ids), used, mine: mineOfSet(ids), numbering, set };
}

/** The extension's ID file parse() (versions 1 and 2) with specific messages. */
function fromIdFile(data: Record<string, unknown>): ParsedPlaceholderMap {
	if (data.format !== ID_FILE_FORMAT) {
		throw idFileError('format', `Its "format" must be "${ID_FILE_FORMAT}".`);
	}
	if (typeof data.version !== 'number' || !ID_FILE_VERSIONS.includes(data.version)) {
		throw idFileError('format', `Only versions ${ID_FILE_VERSIONS.join(' and ')} are supported.`);
	}
	const numbering = data.numbering;
	if (!isNumbering(numbering)) {
		throw idFileError('format', `Its "numbering" must be one of: ${NUMBERINGS.join(', ')}.`);
	}
	if (!Array.isArray(data.ids)) throw idFileError('format', 'Its "ids" must be a list.');
	return data.version === 1 ? fromIdFileV1(data, numbering) : fromIdFileV2(data, numbering);
}

/**
 * Where a JSON.parse failure happened, for an error message: only the line/column or position V8
 * reports. The engine's own message is never copied, because for an unexpected token it quotes a
 * slice of the input, which here is a map of real values.
 */
function jsonErrorPosition(engineMessage: string): string {
	const lineColumn = /\(line (\d+) column (\d+)\)/.exec(engineMessage);
	if (lineColumn) return ` (line ${lineColumn[1]}, column ${lineColumn[2]})`;
	const position = /position (\d+)/.exec(engineMessage);
	return position ? ` (near character ${Number(position[1]) + 1})` : '';
}

function parseValue(input: unknown, depth: number): ParsedPlaceholderMap {
	if (input === undefined || input === null) return { table: {}, used: [], mine: [] };
	if (typeof input === 'string') {
		if (input.trim() === '') return { table: {}, used: [], mine: [] };
		if (depth >= 2) {
			throw new PlaceholderMapError(
				'format',
				`The placeholder map is not valid. ${ACCEPTED_FORMATS}`,
			);
		}
		let parsed: unknown;
		let failed = false;
		let parseError = '';
		try {
			parsed = JSON.parse(input);
		} catch (error) {
			failed = true;
			parseError = error instanceof Error ? error.message : String(error);
		}
		if (failed) {
			throw new PlaceholderMapError(
				'format',
				`The placeholder map is not valid JSON${jsonErrorPosition(parseError)}. Check that every placeholder and value is in double quotes and that entries are separated by commas. ${ACCEPTED_FORMATS}`,
			);
		}
		return parseValue(parsed, depth + 1);
	}
	if (Array.isArray(input)) return fromList(input);
	if (!isPlainObject(input)) {
		throw new PlaceholderMapError(
			'format',
			`The placeholder map must be an object, a list or JSON text, got ${describeType(input)}. ${ACCEPTED_FORMATS}`,
		);
	}
	// A whole Protect output item: its `idFile` when that is a valid ID file holding at least what
	// its `placeholderMap` holds (lossless: groups, types), else its `placeholderMap`. Only then the
	// top-level ID file fields, which Include Input Fields may have copied from an older input file.
	if (depth < 2 && (hasOwn(input, 'placeholderMap') || isIdFileObject(input.idFile))) {
		const flat = hasOwn(input, 'placeholderMap')
			? parseValue(input.placeholderMap, depth + 1)
			: null;
		const file = isIdFileObject(input.idFile) ? tryIdFile(input.idFile) : null;
		if (file && !(file instanceof PlaceholderMapError) && (!flat || covers(file, flat))) {
			return file;
		}
		if (flat) return flat;
		if (file instanceof PlaceholderMapError) throw file;
	}
	if (hasOwn(input, 'format')) return fromIdFile(input);
	return fromObject(input);
}

function isIdFileObject(value: unknown): value is Record<string, unknown> {
	return isPlainObject(value) && value.format === ID_FILE_FORMAT;
}

/** The parsed ID file, or the PlaceholderMapError it was refused with. */
function tryIdFile(data: Record<string, unknown>): ParsedPlaceholderMap | PlaceholderMapError {
	let result: ParsedPlaceholderMap | PlaceholderMapError;
	try {
		result = fromIdFile(data);
	} catch (error) {
		result =
			error instanceof PlaceholderMapError
				? error
				: new PlaceholderMapError('entries', ID_FILE_ERRORS.entries);
	}
	return result;
}

/**
 * Whether the ID file reveals every entry of the flat map the same way and knows every key it
 * used, so it is the same set or a newer, lossless copy of it (never a stale copied file).
 */
function covers(file: ParsedPlaceholderMap, flat: ParsedPlaceholderMap): boolean {
	const used = new Set(file.used);
	if (!flat.used.every((key) => used.has(key))) return false;
	return Object.keys(flat.table).every(
		(key) => hasOwn(file.table, key) && file.table[key] === flat.table[key],
	);
}

/** Parses any accepted map input. `undefined`, `null` and `''` give an empty map. */
export function parsePlaceholderMap(input: unknown): ParsedPlaceholderMap {
	return parseValue(input, 0);
}

/** Bare-key table for reveal (no tombstones): `parsePlaceholderMap(input).table`. */
export function normalizePlaceholderMap(input: unknown): Record<string, string> {
	return parsePlaceholderMap(input).table;
}

/** Local-time `YYYYMMDDTHHMMSS-anonymizator-ids.json`. */
export function defaultIdFileName(date: Date): string {
	const pad = (n: number) => String(n).padStart(2, '0');
	const stamp =
		String(date.getFullYear()) +
		pad(date.getMonth() + 1) +
		pad(date.getDate()) +
		'T' +
		pad(date.getHours()) +
		pad(date.getMinutes()) +
		pad(date.getSeconds());
	return stamp + ID_FILE_SUFFIX;
}

/**
 * Builds an ID file **v1** (the format of extension 0.15.0; current extensions still load it).
 * Minted keys and PERSON sub-keys get `addedByYou: false` unless listed in `extras.mine`. `name`
 * defaults to the default file name; a trailing `.json` is dropped. `usedPlaceholders` lists
 * `extras.used` plus every table key.
 *
 * Throws PlaceholderMapError('entries') for an empty table (the extension rejects it) or an invalid
 * key/value, and PlaceholderMapError('duplicates') when two non-sub-key entries share a value.
 *
 * @deprecated Write v2 with `toIdFile(set, name)` (`idSetFromTable` converts a flat table).
 */
export function toIdFileV1(
	table: PlaceholderTable,
	numbering: Numbering,
	name?: string,
	extras?: IdFileExtras,
): IdFileV1 {
	const keys = Object.keys(table);
	if (keys.length === 0) {
		throw new PlaceholderMapError(
			'entries',
			'There are no placeholders to save: the Anonymizator extension cannot load an empty ID file.',
		);
	}
	for (const key of keys) {
		if (!isValidKey(key)) {
			throw new PlaceholderMapError(
				'entries',
				`Cannot build an ID file: ${quote(key)} is not a valid placeholder: ${keyProblem(key)}.`,
			);
		}
		const value = table[key];
		if (typeof value !== 'string' || value.trim() === '') {
			throw new PlaceholderMapError(
				'entries',
				`Cannot build an ID file: the value of "${key}" is missing or blank.`,
			);
		}
	}
	const mine = new Set((extras?.mine ?? []).filter((k) => hasOwn(table, k)));
	const duplicate = findDuplicateValue(table, mine);
	if (duplicate) {
		throw new PlaceholderMapError(
			'duplicates',
			`Cannot build an ID file: placeholders "${duplicate[0]}" and "${duplicate[1]}" have the same value, and the Anonymizator extension requires unique values (only PERSON _NAME/_SURNAME placeholders may repeat one).`,
		);
	}
	const used = [...new Set([...(extras?.used ?? []), ...keys])];
	const badUsed = used.find((k) => !isValidKey(k));
	if (badUsed !== undefined) {
		throw new PlaceholderMapError(
			'entries',
			`Cannot build an ID file: used placeholder ${quote(badUsed)} is not valid: ${keyProblem(badUsed)}.`,
		);
	}
	const ids: IdFileEntry[] = keys.map((key) => ({
		value: table[key],
		placeholder: `[${key}]`,
		addedByYou: mine.has(key),
	}));
	return {
		format: ID_FILE_FORMAT,
		version: 1,
		name: String(name || defaultIdFileName(new Date())).replace(/\.json$/i, ''),
		numbering: isNumbering(numbering) ? numbering : 'random',
		ids,
		usedPlaceholders: used.map((k) => `[${k}]`),
	};
}

type SetProblem = { code: 'entries' | 'duplicates'; detail: string };

/**
 * Why the extension's IdRules.validateSet would refuse `set`, or null. Same checks in the same
 * order; the detail names placeholders and positions, never values.
 */
export function idSetProblem(set: unknown): SetProblem | null {
	const entries = (detail: string): SetProblem => ({ code: 'entries', detail });
	if (!isPlainObject(set) || !Array.isArray(set.ids)) return entries('the ID set is malformed');
	if (set.ids.length === 0) {
		return entries(
			'there are no IDs to save: the Anonymizator extension cannot load an empty ID file',
		);
	}
	if (!isNumbering(set.numbering)) {
		return entries(`its numbering must be one of: ${NUMBERINGS.join(', ')}`);
	}
	if (!Array.isArray(set.used)) return entries('its list of used placeholders is missing');
	const badUsed = set.used.findIndex((k: unknown) => !isValidKey(k));
	if (badUsed !== -1) {
		const key = set.used[badUsed];
		return entries(
			`used placeholder ${badUsed + 1} is not valid: ${typeof key === 'string' ? keyProblem(key) : 'it is not text'}`,
		);
	}
	const subKeys = set.subKeys === undefined ? {} : set.subKeys;
	const aliases = set.aliases === undefined ? {} : set.aliases;
	if (!isPlainObject(subKeys)) return entries('its name parts are malformed');
	if (!isPlainObject(aliases)) return entries('its reveal-only placeholders are malformed');
	const masked = MASKED_NUMBERINGS.includes(set.numbering);
	const values = new Map<string, string>();
	const rows = new Map<string, IdRecord[]>();
	for (let i = 0; i < set.ids.length; i++) {
		const r: unknown = set.ids[i];
		const where = `ID ${i + 1}`;
		if (!isPlainObject(r) || !isText(r.value))
			return entries(`${where} has a missing or blank value`);
		if (r.value !== r.value.trim()) {
			return entries(`the value of ${where} has leading or trailing spaces`);
		}
		if (!isValidKey(r.key)) {
			return entries(
				`${where} has an invalid placeholder: ${typeof r.key === 'string' ? keyProblem(r.key) : 'it is not text'}`,
			);
		}
		const key = r.key;
		if (typeof r.type !== 'string' || !TYPE_RE.test(r.type)) {
			return entries(
				`ID "${key}" has an invalid type: it must be an entity type code such as PERSON`,
			);
		}
		if (typeof r.mine !== 'boolean' || typeof r.main !== 'boolean') {
			return entries(
				`ID "${key}" must say whether it was added by you and whether it is the main value`,
			);
		}
		const first = values.get(r.value);
		if (first !== undefined) {
			return {
				code: 'duplicates',
				detail: `"${first}" and "${key}" have the same value, and the Anonymizator extension requires unique values`,
			};
		}
		values.set(r.value, key);
		const record = r as IdRecord;
		const members = rows.get(key);
		if (members) members.push(record);
		else rows.set(key, [record]);
	}
	for (const [key, records] of rows) {
		if (records.filter((r) => r.main).length !== 1) {
			return entries(`placeholder "${key}" must have exactly one main value`);
		}
		if (records.some((r) => r.type !== records[0].type)) {
			return entries(`the values of placeholder "${key}" have different types`);
		}
		if (masked && records.length > 1) {
			return entries(
				`placeholder "${key}" has several values, which a set with "${set.numbering}" numbering cannot have`,
			);
		}
	}
	let n = 0;
	for (const [key, s] of Object.entries(subKeys)) {
		n += 1;
		if (!isValidKey(key))
			return entries(`name part ${n} has an invalid placeholder: ${keyProblem(key)}`);
		if (rows.has(key)) return entries(`placeholder "${key}" is both an ID and a name part`);
		if (!isPlainObject(s) || typeof s.of !== 'string' || !rows.has(s.of)) {
			return entries(`name part "${key}" does not belong to an ID of the set`);
		}
		if (!isText(s.value) || !isText(s.rec)) {
			return entries(`name part "${key}" has a missing or blank value`);
		}
		if ((rows.get(s.of) as IdRecord[])[0].type !== 'PERSON') {
			return entries(
				`name part "${key}" belongs to "${s.of}", which is not a PERSON ID (only names have name parts)`,
			);
		}
	}
	if (masked && Object.keys(aliases).length > 0) {
		return entries(`a set with "${set.numbering}" numbering cannot have reveal-only placeholders`);
	}
	n = 0;
	for (const [key, a] of Object.entries(aliases)) {
		n += 1;
		if (!isValidKey(key)) {
			return entries(`reveal-only placeholder ${n} is invalid: ${keyProblem(key)}`);
		}
		if (rows.has(key) || hasOwn(subKeys, key)) {
			return entries(`reveal-only placeholder "${key}" is also an ID or a name part`);
		}
		if (!isPlainObject(a) || typeof a.owner !== 'string' || !rows.has(a.owner)) {
			return entries(`reveal-only placeholder "${key}" does not belong to an ID of the set`);
		}
		if (!isText(a.value))
			return entries(`reveal-only placeholder "${key}" has a missing or blank value`);
	}
	return null;
}

/** The extension's anonSerializeIdFile: same fields, same order. */
function serializeIdSet(set: IdSetInput, fileName: string): IdFileV2 {
	const subKeys = set.subKeys ?? {};
	const aliases = set.aliases ?? {};
	const counts = new Map<string, number>();
	for (const r of set.ids) counts.set(r.key, (counts.get(r.key) ?? 0) + 1);
	const used = [
		...new Set([
			...set.used,
			...set.ids.map((r) => r.key),
			...Object.keys(subKeys),
			...Object.keys(aliases),
		]),
	];
	return {
		format: ID_FILE_FORMAT,
		version: 2,
		name: fileName.replace(/\.json$/i, ''),
		numbering: isNumbering(set.numbering) ? set.numbering : 'random',
		ids: set.ids.map((r) => {
			const entry: IdFileV2Entry = {
				value: r.value,
				placeholder: `[${r.key}]`,
				type: r.type,
				addedByYou: r.mine === true,
			};
			if ((counts.get(r.key) ?? 0) > 1) entry.main = r.main === true;
			return entry;
		}),
		nameParts: Object.entries(subKeys).map(([key, s]) => ({
			placeholder: `[${key}]`,
			value: s.value,
			of: `[${s.of}]`,
			from: s.rec,
		})),
		revealOnly: Object.entries(aliases).map(([key, a]) => ({
			placeholder: `[${key}]`,
			value: a.value,
			of: `[${a.owner}]`,
		})),
		usedPlaceholders: used.map((k) => `[${k}]`),
	};
}

function writeIdFileV2(set: IdSetInput, name?: string): IdFileV2 {
	const problem = idSetProblem(set);
	if (problem) {
		throw new PlaceholderMapError(problem.code, `Cannot build an ID file: ${problem.detail}.`);
	}
	const file = serializeIdSet(set, String(name || defaultIdFileName(new Date())));
	// What the extension's Load IDs does with the saved text: parse the JSON with its v2 rules.
	let refusal: PlaceholderMapError | null = null;
	try {
		fromIdFile(JSON.parse(JSON.stringify(file)) as Record<string, unknown>);
	} catch (error) {
		refusal = error instanceof PlaceholderMapError ? error : null;
		if (!refusal) refusal = new PlaceholderMapError('entries', String(error));
	}
	if (refusal) {
		throw new PlaceholderMapError(
			refusal.code,
			`Cannot build an ID file the Anonymizator extension would load: ${refusal.message}`,
		);
	}
	return file;
}

/**
 * Builds an ID file **v2**, exactly as the extension's anonSerializeIdFile writes it, from a v2 ID
 * set (`ids` newest first, `subKeys`, `aliases`, `used`, `numbering`; the Protect pipeline state has
 * this shape). `name` defaults to the default file name of the current local time; a trailing
 * `.json` is dropped. Locks, skipped and ignored values are never written.
 *
 * Throws PlaceholderMapError when the extension would refuse the set (IdRules.validateSet) or the
 * written file (its v2 parser), with a message that never contains a value.
 *
 * The legacy form `toIdFile(table, numbering, name?, extras?)` still writes v1 (see `toIdFileV1`).
 */
export function toIdFile(set: IdSetInput, name?: string): IdFileV2;
/** @deprecated Use `toIdFile(idSetFromTable(table, numbering, extras), name)` for a v2 file. */
export function toIdFile(
	table: PlaceholderTable,
	numbering: Numbering,
	name?: string,
	extras?: IdFileExtras,
): IdFileV1;
export function toIdFile(
	first: IdSetInput | PlaceholderTable,
	second?: string,
	name?: string,
	extras?: IdFileExtras,
): IdFileV2 | IdFileV1 {
	if (isPlainObject(first) && hasOwn(first, 'ids')) {
		return writeIdFileV2(first as IdSetInput, second);
	}
	return toIdFileV1(first as PlaceholderTable, second as Numbering, name, extras);
}
