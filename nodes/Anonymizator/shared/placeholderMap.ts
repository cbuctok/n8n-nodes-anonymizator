/**
 * Placeholder map input normalisation and extension ID file v1 output.
 *
 * Accepted inputs (one normaliser shared by Reveal's map and Protect's existing map):
 * - a JSON string of any of the below;
 * - an extension ID file v1 (`{ format: 'anonymizator-id-file', version: 1, ... }`), validated with
 *   the same rules as the extension's `sidepanel/sidepanel-idfile.js` parse();
 * - an array of `{ placeholder, value }` (or `{ key, value }`);
 * - a plain object with bare (`PERSON_a7k2q`) or bracketed (`[PERSON_a7k2q]`) keys;
 * - a Protect output item (`{ placeholderMap: ... }`), which is unwrapped.
 * Every key must pass `isValidKey`. Empty/whitespace values are tombstones: they go to `used`, never
 * to the table (a tombstone in a reveal table would erase text). Insertion order is preserved.
 *
 * Bad input throws PlaceholderMapError with a message fit to show the user as-is. Messages name
 * keys and positions but never echo values, which are the protected personal data.
 */
import { isValidKey, MAX_SUFFIX_DIGITS } from './anonymizer';
import { PlaceholderMapError } from './errors';
import type { IdFileEntry, IdFileV1, Numbering, PlaceholderTable } from './types';

export { PlaceholderMapError };

export const ID_FILE_FORMAT = 'anonymizator-id-file';
export const ID_FILE_VERSION = 1;
export const ID_FILE_SUFFIX = '-anonymizator-ids.json';

/** Placeholder styles an ID file may record (the extension's IdSet.NUMBERING). */
export const NUMBERINGS: readonly Numbering[] = ['random', 'sequential', 'typed', 'redacted'];

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

const ACCEPTED_FORMATS =
	'Use an object such as {"PERSON_a7k2q": "Janez Novak"} (keys with or without brackets), ' +
	'a list of {"placeholder": "[PERSON_a7k2q]", "value": "Janez Novak"}, ' +
	'the placeholderMap of a Protect result, or an ID file saved by the Anonymizator extension.';

/** Full result of parsing a map input. */
export type ParsedPlaceholderMap = {
	/** Bare-key table without tombstones, in input order. */
	table: PlaceholderTable;
	/** Every key ever used (tombstones + table keys), bare. Minting must avoid all of them. */
	used: string[];
	/** Keys the user added by hand (ID file `addedByYou: true`); empty for other inputs. */
	mine: string[];
	/** Numbering recorded in an ID file input, if any. */
	numbering?: Numbering;
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
		const first = seen.get(value);
		if (first !== undefined) return [first, key];
		seen.set(value, key);
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
		if (typeof value === 'string' && BRACKETED_RE.test(value.trim())) {
			throw new PlaceholderMapError(
				'entries',
				`Invalid placeholder map: ${where} looks reversed (its value is a placeholder). Use the placeholder as the key and the original text as the value, e.g. {"PERSON_a7k2q": "Janez Novak"}.`,
			);
		}
		const key = normalizePlaceholder(rawKey);
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

/** The extension's ID file parse() with specific messages. */
function fromIdFile(data: Record<string, unknown>): ParsedPlaceholderMap {
	if (data.format !== ID_FILE_FORMAT) {
		throw idFileError('format', `Its "format" must be "${ID_FILE_FORMAT}".`);
	}
	if (data.version !== ID_FILE_VERSION) {
		throw idFileError('format', `Only version ${ID_FILE_VERSION} is supported.`);
	}
	if (!isNumbering(data.numbering)) {
		throw idFileError('format', `Its "numbering" must be one of: ${NUMBERINGS.join(', ')}.`);
	}
	const list = data.ids;
	if (!Array.isArray(list)) throw idFileError('format', 'Its "ids" must be a list.');
	if (list.length === 0) throw idFileError('entries', 'Its "ids" list is empty.');

	list.forEach((entry: unknown, i) => {
		const where = `Entry ${i + 1}`;
		if (!isPlainObject(entry)) throw idFileError('entries', `${where} is not an object.`);
		if (typeof entry.value !== 'string' || entry.value.trim() === '') {
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
	const keys = entries.map((entry) => entry.placeholder.slice(1, -1));
	const table: PlaceholderTable = {};
	const mine: string[] = [];
	entries.forEach((entry, i) => {
		if (hasOwn(table, keys[i])) {
			throw idFileError('duplicates', `Placeholder "[${keys[i]}]" appears more than once.`);
		}
		table[keys[i]] = entry.value;
		if (entry.addedByYou === true) mine.push(keys[i]);
	});

	const duplicate = findDuplicateValue(table, mine);
	if (duplicate) {
		throw idFileError(
			'duplicates',
			`Placeholders "[${duplicate[0]}]" and "[${duplicate[1]}]" have the same value.`,
		);
	}

	const used = [
		...new Set([...((usedRaw as string[] | undefined) ?? []).map((p) => p.slice(1, -1)), ...keys]),
	];
	return { table, used, mine, numbering: data.numbering };
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
	// A whole Protect output item can carry an unrelated `format` field copied from its input
	// (Include Input Fields), so `format` means an ID file only when it says so or nothing else fits.
	if (
		hasOwn(input, 'format') &&
		(input.format === ID_FILE_FORMAT || !hasOwn(input, 'placeholderMap'))
	) {
		return fromIdFile(input);
	}
	if (hasOwn(input, 'placeholderMap') && depth < 2)
		return parseValue(input.placeholderMap, depth + 1);
	return fromObject(input);
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
 * Builds an ID file v1 the extension's Load IDs accepts (its parse() and IdSet.load() rules).
 * Minted keys and PERSON sub-keys get `addedByYou: false` unless listed in `extras.mine`. `name`
 * defaults to the default file name; a trailing `.json` is dropped. `usedPlaceholders` lists
 * `extras.used` plus every table key.
 *
 * Throws PlaceholderMapError('entries') for an empty table (the extension rejects it) or an invalid
 * key/value, and PlaceholderMapError('duplicates') when two non-sub-key entries share a value.
 */
export function toIdFile(
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
		version: ID_FILE_VERSION,
		name: String(name || defaultIdFileName(new Date())).replace(/\.json$/i, ''),
		numbering: isNumbering(numbering) ? numbering : 'random',
		ids,
		usedPlaceholders: used.map((k) => `[${k}]`),
	};
}
