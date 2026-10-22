/**
 * The ID-set model (state v2) of the extension, as pure functions: a port of `lib/id-model.js`
 * (types, prefixes, legal forms, `fromV1`, `revealTable`), the own-placeholder test of
 * `lib/id-rules.js` (`ownPlaceholderTest`, `FOREIGN_MINTED_RE`; `extraBlockTest`) and `companySpans` of
 * `lib/id-names.js`. No n8n imports, no I/O.
 *
 * A set holds records `{ value, key, type, mine, main }` (newest first), PERSON name parts
 * (`subKeys`), reveal-only `aliases` and every key ever used (`used`). Two or more records sharing a
 * key are a group; exactly one is `main` (what Reveal brings back). Tombstones are the `used` keys
 * that are neither live, a name part nor an alias.
 *
 * Deliberate differences from the extension (n8n feeds Protect's flat placeholderMap back in and
 * chains Protect nodes, which the extension never does):
 * - `fromV1` turns a value that appears under several keys into one record (the first key in table
 *   order) plus reveal-only aliases for the other keys, so every key of a flat map keeps revealing.
 *   A name part never loses protection: when its person is not a live PERSON record it joins the
 *   PERSON record holding that person's value, else it becomes a PERSON record of its own; only a
 *   part whose value a record already holds becomes an alias. A key with name parts is a PERSON
 *   (`PERSON_CEO`), and a `TYPE_suffix` key keeps any entity type code as its type
 *   (`flatTypeFromKey`: `SOCIAL_HANDLE_o1b30` is SOCIAL_HANDLE, `CASE_1` is CASE), so server-only
 *   types survive the round trip. The extension never meets such tables (its ID file parser refuses
 *   them, its v2 files carry types); its `normalize` would drop the extra keys and parts and type
 *   unknown prefixes CUSTOM.
 * - `extraBlockTest` (Additionally Protect only) also blocks a placeholder minted for ANY entity
 *   type code with a digit-bearing suffix (`[SOCIAL_HANDLE_1]`), where the extension's NUMBER rule
 *   would cut it into `[SOCIAL_HANDLE_[NUMBER_1]]`. `ownPlaceholderTest`, used for gateway spans and
 *   minting, keeps the extension's semantics.
 * - Own-property lookups everywhere (`Object.hasOwn` is not available on the es2019 target).
 */
import { isValidKey, splitPersonName } from './anonymizer';
import type { Numbering, PlaceholderTable, Span } from './types';

/** One ID of a set. */
export type IdRecord = {
	value: string;
	key: string;
	type: string;
	mine: boolean;
	main: boolean;
};

/** A PERSON name part: `SUBKEY` → its value, the live key it belongs to and that record's value. */
export type SubKey = { of: string; value: string; rec: string };

/** A reveal-only key: the value it still reveals and the live key that owns it. */
export type Alias = { value: string; owner: string };

/** The content of an ID set, the shape the Protect pipeline works on (extension state v2). */
export type IdSetContent = {
	numbering: Numbering;
	/** Records, newest first. */
	ids: IdRecord[];
	subKeys: Record<string, SubKey>;
	aliases: Record<string, Alias>;
	/** Every key ever used: live keys, name parts, aliases and tombstones. */
	used: string[];
};

export const NUMBERING: readonly Numbering[] = ['random', 'sequential', 'typed', 'redacted'];
export const MASKED: readonly Numbering[] = ['typed', 'redacted'];
/** What every ID becomes in a `redacted` set. */
export const REDACTED_LABEL = '[REDACTED]';
/** An entity type code (`lib/anonymizer.js` PGW_ENTITY_TYPE_RE). */
export const TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

/** The extension editor's type list, in display order: type code, label, placeholder prefix. */
export const TYPES: ReadonlyArray<Readonly<{ code: string; label: string; prefix: string }>> = [
	{ code: 'PERSON', label: 'Name', prefix: 'PERSON' },
	{ code: 'COMPANY', label: 'Company', prefix: 'COMPANY' },
	{ code: 'EMAIL_ADDRESS', label: 'Email address', prefix: 'EMAIL' },
	{ code: 'PHONE_NUMBER', label: 'Phone number', prefix: 'PHONE' },
	{ code: 'IBAN', label: 'Bank account (IBAN)', prefix: 'IBAN' },
	{ code: 'NUMBER', label: 'Number', prefix: 'NUMBER' },
	{ code: 'AMOUNT', label: 'Amount', prefix: 'AMOUNT' },
	{ code: 'CUSTOM', label: 'Other', prefix: 'CUSTOM' },
];

/** Type code → placeholder prefix; the server's IBAN_CODE mints IBAN_… like an IBAN. */
export const PREFIXES: Readonly<Record<string, string>> = {
	...fromPairs(TYPES.map((t) => [t.code, t.prefix])),
	IBAN_CODE: 'IBAN',
};
const FROM_PREFIX: Readonly<Record<string, string>> = fromPairs(
	TYPES.map((t) => [t.prefix, t.code]),
);

/**
 * The bundled entity types plus the fallbacks and the placeholder prefixes (the extension's
 * `anonIdModel.KNOWN_TYPES` / `IdRules.PLACEHOLDER_TYPES`). Never extended with server types.
 */
export const KNOWN_TYPES: readonly string[] = [
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

/**
 * Legal forms that make a name a company. In text, the lowercase Slovene / Polish forms match in
 * any case (d.o.o., D.O.O.), the others exactly as written; the dots are part of the form.
 */
const LEGAL_ANY_CASE = ['d.o.o.', 'd.d.', 's.p.', 'k.d.', 'd.n.o.', 'z.o.o.'];
const LEGAL_EXACT = [
	'GmbH',
	'AG',
	'KG',
	'OG',
	'Ltd.',
	'Ltd',
	'Inc.',
	'Inc',
	'LLC',
	'Corp.',
	'Corporation',
	'S.p.A.',
	'S.r.l.',
];
export const LEGAL_FORMS: readonly string[] = [...LEGAL_ANY_CASE, ...LEGAL_EXACT];

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const byLength = (forms: readonly string[]): string[] =>
	forms.slice().sort((a, b) => b.length - a.length); // "Ltd." before "Ltd"
const anyCase = (f: string): string =>
	escapeRe(f).replace(/[a-z]/g, (c) => `[${c}${c.toUpperCase()}]`);
const LEGAL_ALT = byLength(LEGAL_FORMS)
	.map((f) => (LEGAL_ANY_CASE.includes(f) ? anyCase(f) : escapeRe(f)))
	.join('|');
/** An optional comma, spaces or tabs (never a line break), then a whole legal form. */
const LEGAL_AFTER_RE = new RegExp(`^,?[ \\t]+(?:${LEGAL_ALT})(?![\\p{L}\\p{N}])`, 'u');
/** A whole legal form starting exactly at lastIndex (sticky). */
const LEGAL_AT_RE = new RegExp(`(?:${LEGAL_ALT})(?![\\p{L}\\p{N}])`, 'uy');
const COMPANY_NAME_RE = new RegExp(`^(.*?\\S),?[ \\t]+(?:${LEGAL_ALT})$`, 'u');
/** A value the user types: any case, except the two-letter forms ("Hans Ag" stays a name). */
const LEGAL_TYPED_RE = new RegExp(
	`\\S,?\\s+(?:${byLength(LEGAL_FORMS)
		.filter((f) => !/^[A-Z]{2}$/.test(f))
		.map(escapeRe)
		.join('|')})$`,
	'iu',
);
/** Dates are not phone numbers: 2024-10-09, 09/10/2024, 9-10-24. */
const DATE_RE = /^(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})$/;
const CUR = '€|EUR|USD|GBP|CHF|\\$|£';
const NUM = "\\d(?:[\\d.,' ]*\\d)?";
const AMOUNT_RE = new RegExp(`^(?:(?:${CUR})\\s?${NUM}|${NUM}\\s?(?:${CUR}))$`, 'i');
const NUMBER_RE = new RegExp(`^${NUM}$`);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IBAN_RE = /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/i;
const PHONE_RE = /^(?:\+|00)?[\d\s()/-]+$/;
/** TYPE_suffix with a lowercase/digit suffix; the lazy TYPE keeps underscored types whole. */
const KEY_PARTS_RE = /^([A-Z][A-Z0-9_]*?)_[a-z0-9]+$/;
const SUB_KEY_RE = /^(PERSON_.+)_(?:NAME|SURNAME)$/;

/**
 * `TYPE_suffix[_NAME|_SURNAME]` as the anonymizer mints it: a 5-character a-z0-9 random suffix or
 * a counter of 1-9 digits. The lazy TYPE lets underscored types match (`US_SSN_2`).
 */
export const FOREIGN_MINTED_RE = /^([A-Z][A-Z0-9_]*?)_([a-z0-9]{5}|[0-9]{1,9})(_NAME|_SURNAME)?$/;

function fromPairs(pairs: Array<[string, string]>): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of pairs) out[k] = v;
	return out;
}

/** Own-property lookup: 'toString' / '__proto__' are never IDs. */
export function hasOwn(obj: unknown, key: unknown): boolean {
	return (
		typeof key === 'string' &&
		!!obj &&
		typeof obj === 'object' &&
		Object.prototype.hasOwnProperty.call(obj, key)
	);
}

function isObject(x: unknown): x is Record<string, unknown> {
	return !!x && typeof x === 'object' && !Array.isArray(x);
}

function strings(list: unknown): string[] {
	return Array.isArray(list) ? list.filter((x): x is string => typeof x === 'string') : [];
}

// --- Types and keys --------------------------------------------------------

/** Placeholder prefix of a type code: EMAIL_ADDRESS → EMAIL, PHONE_NUMBER → PHONE, else the code. */
export function prefixFor(type: string): string {
	return hasOwn(PREFIXES, type) ? PREFIXES[type] : type;
}

/** Inverse of prefixFor: EMAIL → EMAIL_ADDRESS; another TYPE_RE prefix → itself; else CUSTOM. */
export function typeFromPrefix(prefix: unknown): string {
	if (typeof prefix !== 'string') return 'CUSTOM';
	if (hasOwn(FROM_PREFIX, prefix)) return FROM_PREFIX[prefix];
	return TYPE_RE.test(prefix) ? prefix : 'CUSTOM';
}

/**
 * The type of a value typed by the user, worked out locally. Rules in order: email, IBAN, legal
 * form, amount with a currency, phone number, plain number, else CUSTOM.
 */
export function guessType(value: unknown): string {
	const s = typeof value === 'string' ? value.trim() : '';
	if (!s) return 'CUSTOM';
	const compact = s.replace(/\s+/g, '');
	if (EMAIL_RE.test(s)) return 'EMAIL_ADDRESS';
	if (IBAN_RE.test(compact)) return 'IBAN';
	if (companyName(s) || LEGAL_TYPED_RE.test(s)) return 'COMPANY';
	if (AMOUNT_RE.test(s)) return 'AMOUNT';
	if (PHONE_RE.test(s) && !DATE_RE.test(s)) {
		const digits = s.replace(/\D/g, '').length;
		if (digits >= 7 && digits <= 15 && (/^(?:\+|00)/.test(s) || /[\s()/-]/.test(s))) {
			return 'PHONE_NUMBER';
		}
	}
	if (NUMBER_RE.test(s)) return 'NUMBER';
	return 'CUSTOM';
}

/** Length of the legal form that follows text[end] (`, d.o.o.`), else 0. */
export function legalSuffixLength(text: string, end: number): number {
	const m = LEGAL_AFTER_RE.exec(String(text).slice(end, end + 40));
	return m ? m[0].length : 0;
}

/** Length of a whole legal form that starts exactly at text[pos] (`d.o.o.`), else 0. */
export function legalFormAt(text: string, pos: number): number {
	LEGAL_AT_RE.lastIndex = pos;
	return (LEGAL_AT_RE.exec(String(text)) || [''])[0].length;
}

/** "Modra Vila" of "Modra Vila d.o.o.", or '' when the value does not end in a legal form. */
export function companyName(value: unknown): string {
	const m = COMPANY_NAME_RE.exec(typeof value === 'string' ? value.trim() : '');
	return m ? m[1] : '';
}

/** The prefix part of a minted key (EMAIL in EMAIL_x7gs2, IBAN_CODE in IBAN_CODE_1), else the key. */
export function namePart(key: unknown): string {
	if (typeof key !== 'string') return '';
	const m = KEY_PARTS_RE.exec(key);
	return m ? m[1] : key;
}

/** The type a v1 key stands for: a known prefix or type (IBAN_CODE → IBAN), else CUSTOM. */
export function typeFromKey(key: unknown): string {
	const m = typeof key === 'string' ? KEY_PARTS_RE.exec(key) : null;
	if (!m) return 'CUSTOM';
	const prefix = m[1];
	if (hasOwn(PREFIXES, prefix) || hasOwn(FROM_PREFIX, prefix) || KNOWN_TYPES.includes(prefix)) {
		return typeFromPrefix(prefixFor(prefix)); // IBAN_CODE_1 → IBAN, like a found IBAN now
	}
	return 'CUSTOM';
}

// --- State -----------------------------------------------------------------

/** A fresh empty set. */
export function emptyContent(numbering: Numbering = 'random'): IdSetContent {
	return { numbering, ids: [], subKeys: {}, aliases: {}, used: [] };
}

export function isMasked(state: { numbering: Numbering }): boolean {
	return MASKED.includes(state.numbering);
}

/** The distinct record keys. */
export function liveKeys(state: Pick<IdSetContent, 'ids'>): Set<string> {
	return new Set(((state && state.ids) || []).map((r) => r.key));
}

/** Every key the set knows: used ∪ live ∪ sub-keys ∪ aliases. */
export function ownKeys(state: IdSetContent): Set<string> {
	const keys = new Set(strings(state && state.used));
	for (const key of liveKeys(state)) keys.add(key);
	for (const key of Object.keys((state && state.subKeys) || {})) keys.add(key);
	for (const key of Object.keys((state && state.aliases) || {})) keys.add(key);
	return keys;
}

/** Adds keys to `used` (in order, once each). */
export function addUsed(state: IdSetContent, ...keys: string[]): void {
	const used = new Set(state.used);
	for (const key of keys) {
		if (!used.has(key)) {
			used.add(key);
			state.used.push(key);
		}
	}
}

/**
 * The v1 sub-key rule: K_NAME / K_SURNAME is a sub-key only when K starts with PERSON_, K is in the
 * table and K is not mine.
 */
function v1SubKeyParent(key: string, table: PlaceholderTable, mine: Set<string>): string | null {
	const match = SUB_KEY_RE.exec(key);
	if (!match) return null;
	return hasOwn(table, match[1]) && !mine.has(match[1]) ? match[1] : null;
}

/** A flat v1 set: the reveal table, the hand-added keys, every used key and the numbering. */
export type FlatSet = {
	table: PlaceholderTable;
	used?: Iterable<string>;
	mine?: Iterable<string>;
};

/**
 * The type of a flat-map key (`fromV1` only): `typeFromKey`, except that any `TYPE_suffix` key
 * whose TYPE is an entity type code keeps that type (`SOCIAL_HANDLE_o1b30` → SOCIAL_HANDLE), so a
 * server-only type survives Protect's flat placeholderMap fed back as Existing Placeholder Map.
 */
export function flatTypeFromKey(key: unknown): string {
	const m = typeof key === 'string' ? KEY_PARTS_RE.exec(key) : null;
	return m ? typeFromPrefix(prefixFor(m[1])) : 'CUSTOM';
}

/**
 * A flat `{KEY: value}` set as v2 content (`anonIdModel.fromV1`, then the repair `normalize`
 * applies): values trimmed, blank values only used (tombstones), PERSON name parts by the v1 rule,
 * types from the key shape (`flatTypeFromKey`; a key with name parts is a PERSON), records newest
 * first (the table is oldest first). A value under several keys keeps the first key as its record;
 * the other keys become aliases, so they still reveal. A name part whose person did not become a
 * PERSON record joins the PERSON record holding that person's value, else becomes a record of its
 * own: every non-blank value stays protected, and only a value that is already a record value is
 * ever demoted to reveal-only. Masked sets keep no aliases (they reveal nothing).
 */
export function fromV1(flat: FlatSet, numbering: Numbering): IdSetContent {
	const table: PlaceholderTable = isObject(flat && flat.table) ? flat.table : {};
	const mine = new Set(strings(flat && flat.mine ? [...flat.mine] : []));
	const masked = MASKED.includes(numbering);
	const records: IdRecord[] = []; // oldest first while building
	const recordOf = new Map<string, IdRecord>(); // trimmed value → record
	const parts: Array<[string, string, string]> = []; // [key, parent, value]
	const leftovers: Array<[string, string]> = []; // [key, value] whose value a record holds
	const parents = new Set<string>();
	for (const key of Object.keys(table)) {
		const raw = table[key];
		if (typeof raw !== 'string' || !isValidKey(key) || !raw.trim()) continue;
		const parent = v1SubKeyParent(key, table, mine);
		if (parent) parents.add(parent);
	}
	const addRecord = (key: string, value: string, type: string): void => {
		const record: IdRecord = { value, key, type, mine: mine.has(key), main: true };
		recordOf.set(value, record);
		records.push(record);
	};
	for (const key of Object.keys(table)) {
		const raw = table[key];
		if (typeof raw !== 'string' || !isValidKey(key)) continue;
		const value = raw.trim();
		if (!value) continue; // a tombstone: only used
		const parent = v1SubKeyParent(key, table, mine);
		if (parent) {
			parts.push([key, parent, raw]);
			continue;
		}
		if (recordOf.has(value)) {
			leftovers.push([key, value]);
			continue;
		}
		// PERSON_CEO with PERSON_CEO_NAME / _SURNAME parts is a person, whatever its suffix.
		addRecord(key, value, parents.has(key) ? 'PERSON' : flatTypeFromKey(key));
	}
	const live = new Map(records.map((r) => [r.key, r]));
	const subKeys: Record<string, SubKey> = {};
	for (const [key, parent, value] of parts) {
		const direct = live.get(parent);
		// The person the part was split from: its own record, else the record holding its value.
		const owner =
			direct ||
			(typeof table[parent] === 'string' ? recordOf.get(table[parent].trim()) : undefined);
		if (owner && owner.type === 'PERSON') {
			subKeys[key] = {
				of: owner.key,
				value,
				rec: direct ? String(table[parent]) : owner.value,
			};
		} else if (recordOf.has(value.trim())) {
			leftovers.push([key, value]);
		} else {
			addRecord(key, value.trim(), 'PERSON');
		}
	}
	const aliases: Record<string, Alias> = {};
	if (!masked) {
		for (const [key, value] of leftovers) {
			const owner = recordOf.get(value.trim());
			if (owner && !hasOwn(subKeys, key)) {
				aliases[key] = { value, owner: owner.key };
			}
		}
	}
	const used = [
		...new Set([
			...strings(flat && flat.used ? [...flat.used] : []).filter(isValidKey),
			...Object.keys(table).filter(isValidKey),
		]),
	];
	return { numbering, ids: records.reverse(), subKeys, aliases, used };
}

/**
 * What Reveal uses: every live key → its main value, every alias → its frozen value, every sub-key
 * → its value. A masked set reveals nothing.
 */
export function revealTable(state: IdSetContent): Record<string, string> {
	const table: Record<string, string> = {};
	if (!state || MASKED.includes(state.numbering)) return table;
	for (const [key, s] of Object.entries(state.subKeys || {})) table[key] = s.value;
	for (const [key, a] of Object.entries(state.aliases || {})) table[key] = a.value;
	for (const r of state.ids || []) if (r.main) table[r.key] = r.value;
	return table;
}

/** The type behind any key of the set (record, sub-key, alias), else from its shape. */
export function typeOfKey(state: IdSetContent, key: string): string {
	const ids = (state && state.ids) || [];
	const record = ids.find((r) => r.key === key && r.main) || ids.find((r) => r.key === key);
	if (record) return record.type;
	if (hasOwn(state && state.subKeys, key)) return 'PERSON';
	if (hasOwn(state && state.aliases, key)) return typeOfKey(state, state.aliases[key].owner);
	return typeFromKey(key);
}

/** The placeholder shown for `key`: [KEY], or [PREFIX] (typed) / [REDACTED] (redacted). */
export function displayPlaceholder(state: IdSetContent, key: string): string {
	const numbering = state && state.numbering;
	if (numbering === 'redacted') return REDACTED_LABEL;
	if (numbering === 'typed') return `[${prefixFor(typeOfKey(state, key))}]`;
	return `[${key}]`;
}

// --- Own placeholders (lib/id-rules.js) ------------------------------------

/**
 * The `isOwnPlaceholder` predicate for this set. A token is Protect's own only on evidence from
 * THIS set: its bare key is one of the set's keys (live keys, name parts, aliases, tombstones); in
 * a masked set, `[REDACTED]` or `[TYPE]` for a bundled type or prefix; or a placeholder minted by
 * ANOTHER set, by shape, only where the shape cannot be a word (a bundled type plus a counter, or a
 * 5-character suffix with at least one digit; PERSON optionally with `_NAME` / `_SURNAME`).
 * Server-provided types never widen this test.
 */
export function ownPlaceholderTest(state: IdSetContent): (token: string) => boolean {
	const keys = ownKeys(state);
	const masked = MASKED.includes(state.numbering);
	const types = new Set(KNOWN_TYPES);
	return (token: string): boolean => {
		if (
			typeof token !== 'string' ||
			token.length < 3 ||
			token[0] !== '[' ||
			token[token.length - 1] !== ']'
		) {
			return false;
		}
		const bare = token.slice(1, -1);
		if (keys.has(bare)) return true;
		if (masked && (token === REDACTED_LABEL || types.has(bare))) return true;
		const m = FOREIGN_MINTED_RE.exec(bare);
		return !!m && types.has(m[1]) && /[0-9]/.test(m[2]) && (!m[3] || m[1] === 'PERSON');
	};
}

/**
 * What Additionally Protect must never cut into: `ownPlaceholderTest`, plus any token minted by
 * another set or an earlier Protect node for ANY entity type code (`[SOCIAL_HANDLE_1]`,
 * `[IT_FISCAL_CODE_a1b2c]`): a digit-bearing suffix, PERSON optionally with `_NAME` / `_SURNAME`.
 * The extension blocks only bundled types here, so its NUMBER rule turns `[SOCIAL_HANDLE_1]` into
 * `[SOCIAL_HANDLE_[NUMBER_1]]`; the node mints server-type placeholders and chains Protect nodes,
 * so it blocks them. Gateway spans keep the extension's narrower test.
 */
export function extraBlockTest(state: IdSetContent): (token: string) => boolean {
	const own = ownPlaceholderTest(state);
	return (token: string): boolean => {
		if (own(token)) return true;
		if (typeof token !== 'string' || token[0] !== '[' || token[token.length - 1] !== ']') {
			return false;
		}
		const m = FOREIGN_MINTED_RE.exec(token.slice(1, -1));
		return !!m && TYPE_RE.test(m[1]) && /[0-9]/.test(m[2]) && (!m[3] || m[1] === 'PERSON');
	};
}

// --- Companies (lib/id-names.js) -------------------------------------------

const COMPANY_FROM = ['PERSON', 'LOCATION'];

/** [start, end) without surrounding whitespace, as anonymizeFromSpans trims it. */
function trimmed(
	text: string,
	span: { start: number; end: number },
): { start: number; end: number } {
	let { start, end } = span;
	while (start < end && /\s/.test(text[start])) start++;
	while (end > start && /\s/.test(text[end - 1])) end--;
	return { start, end };
}

/**
 * Detected PERSON / LOCATION spans followed by a legal form become COMPANY spans that include the
 * form; spans reading a company's name without its form (in this text, or of a COMPANY already in
 * the set) become COMPANY. Returns new span objects; the others unchanged.
 */
export function companySpans(
	state: Pick<IdSetContent, 'ids'>,
	text: string,
	spans: Span[],
): Span[] {
	const list = Array.isArray(spans) ? spans : [];
	const names = new Set<string>();
	for (const r of state.ids) {
		if (r.type === 'COMPANY' && companyName(r.value)) names.add(companyName(r.value));
	}
	const candidate = (s: Span): boolean =>
		!!s &&
		COMPANY_FROM.includes(s.entity_type) &&
		Number.isInteger(s.start) &&
		Number.isInteger(s.end) &&
		s.start < s.end &&
		s.end <= text.length;
	const extended = list.map((s) => {
		if (!candidate(s)) return s;
		const { start, end } = trimmed(text, s);
		const form = start < end ? legalSuffixLength(text, end) : 0;
		if (!form) return s;
		names.add(text.slice(start, end));
		return { ...s, entity_type: 'COMPANY', start, end: end + form };
	});
	return extended.map((s) =>
		candidate(s) && names.has(text.slice(s.start, s.end).trim())
			? { ...s, entity_type: 'COMPANY' }
			: s,
	);
}

// splitPersonName is re-exported for the possible-ID rules.
export { splitPersonName };
