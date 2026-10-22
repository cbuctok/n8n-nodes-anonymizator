/**
 * Server capabilities (`GET /v1/capabilities`, signed document `pgw-capabilities-v1`; docs/HPKE.md
 * in the gateway repository, "Capabilities"). Port of `parseCapabilitiesDocument` and
 * `verifyCapabilitiesV1` from the extension's `lib/hpke.js`.
 *
 * The document lists what the current server supports (entity types with labels and groups,
 * languages, limits, feature flags, server_version), so a node release is not needed to learn new
 * types. It is signed by the same delegated key as keyconfig v2 and verified through the same chain
 * (pinned roots -> delegation -> document). Fail closed on verification, fail SAFE for protection:
 * a verified document may only ADD types, labels and groups; it never removes protection, and an
 * omitted `entities` filter still means every configured type on the server.
 */
import {
	documentLines,
	ed25519Verify,
	lineValue,
	ownField,
	parseUint,
	strictB64,
	verifyDelegationV2,
	V2_LIMITS,
	b64urlDecodeStrict,
} from './keyconfig';

/** Capabilities verification failure codes. */
export type CapabilitiesErrorCode = 'capabilities_unverified' | 'capabilities_stale';

/** Frozen header (20 bytes, exact, at offset 0). Never rename. */
export const CAPABILITIES_HEADER = 'pgw-capabilities-v1\n';

/** Limits of the v1 document (frozen; the gateway uses the same values). */
export const CAPABILITIES_LIMITS = {
	MAX_AGE_S: 7200,
	MAX_BYTES: 49152,
	MAX_B64: 65536,
	MAX_LINES: 4096,
	MAX_GROUPS: 32,
	MAX_ENTITIES: 256,
	MAX_POSSIBLE: 64,
	MAX_LANGUAGES: 16,
	MAX_LABEL_LANGUAGES: 8,
	MAX_FEATURES: 32,
	MAX_LABEL_SCALARS: 64,
} as const;

/** One group (category or country), in display order. */
export type CapabilitiesGroup = { id: string; kind: 'category' | 'country' };

/** One entity type the server detects; `default` is a client UI hint only. */
export type CapabilitiesEntity = { type: string; default: 'on' | 'opt_in'; groups: string[] };

/** One review-only type of the `possible` spans. */
export type CapabilitiesPossible = { type: string; groups: string[] };

/** A parsed and verified capabilities document. */
export type VerifiedCapabilities = {
	version: 1;
	serverVersion: string;
	issuedAt: number;
	languages: string[];
	labelLanguages: string[];
	maxTextChars: number;
	maxBodyBytes: number;
	features: string[];
	groups: CapabilitiesGroup[];
	entities: CapabilitiesEntity[];
	possible: CapabilitiesPossible[];
	/** ref (`type:<TYPE>` or `group:<gid>`) -> language -> label text. */
	labels: Map<string, Map<string, string>>;
};

export type CapabilitiesVerification =
	| {
			ok: true;
			/** The delegation serial (compared with the keyconfig serial floor, read only). */
			serial: number;
			issuedAt: number;
			/** The delegation's end, unix seconds. */
			notAfter: number;
			capabilities: VerifiedCapabilities;
	  }
	| { ok: false; error: CapabilitiesErrorCode };

// Lines 9-15: fixed literals in v1 (the placeholder format the extension's frozen anonymizer
// implements). Another format is pgw-capabilities-v2.
const CAPABILITIES_LITERALS: readonly string[] = [
	'placeholder_suffix_length=5',
	'placeholder_suffix_alphabet=abcdefghijklmnopqrstuvwxyz0123456789',
	'placeholder_counter_max_digits=9',
	'placeholder_sub_keys=NAME,SURNAME',
	'placeholder_fallback_type=PII',
	'masked_redacted=[REDACTED]',
	'masked_typed=[TYPE]',
];
const CAPABILITIES_V1_NAMES: ReadonlySet<string> = new Set([
	'version',
	'issued_at',
	'server_version',
	'languages',
	'label_languages',
	'max_text_chars',
	'max_body_bytes',
	'placeholder_suffix_length',
	'placeholder_suffix_alphabet',
	'placeholder_counter_max_digits',
	'placeholder_sub_keys',
	'placeholder_fallback_type',
	'masked_redacted',
	'masked_typed',
	'features',
	'group',
	'entity',
	'possible',
	'label',
]);
const SECTIONS: ReadonlyMap<string, number> = new Map([
	['group', 0],
	['entity', 1],
	['possible', 2],
	['label', 3],
]);
const TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const GID_RE = /^[a-z][a-z0-9_]{0,31}$/;
const COUNTRY_RE = /^[a-z]{2}$/;
const LANG_RE = /^[a-z]{2,3}$/;
const FLAG_RE = /^[a-z][a-z0-9_]{0,31}$/;
const EXT_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;
const RELEASE_RE = /^20[0-9]{2}\.(?:[1-9]|1[0-2])\.(?:[1-9]|[12][0-9]|3[01])(?:\.[1-9][0-9]?)?$/;
// Label text: literal 0x20-0x7E except '%' and ',', or %XX (uppercase hex).
const PCT_TEXT_RE = /^(?:[\x20-\x24\x26-\x2b\x2d-\x7e]|%[0-9A-F]{2})+$/;
const CAPS_B64_RE = /^[A-Za-z0-9_-]+$/;
// Explicit code-point allowlist: the same result in every Unicode version.
const LABEL_RANGES: ReadonlyArray<[number, number]> = [
	[0x20, 0x7e],
	[0xa1, 0xac],
	[0xae, 0x24f],
	[0x400, 0x45f],
];
const LABEL_SINGLES: ReadonlySet<number> = new Set([
	0x2013, 0x2014, 0x2018, 0x2019, 0x201c, 0x201d, 0x2026, 0x20ac,
]);

/** Reserved TYPE shapes: never a server type (they belong to the placeholder rules). */
function isReservedType(type: string): boolean {
	return (
		type === 'CUSTOM' ||
		type === 'PII' ||
		type === 'REDACTED' ||
		type === 'TYPE' ||
		type.endsWith('_NAME') ||
		type.endsWith('_SURNAME') ||
		type.startsWith('PERSON_')
	);
}

/** A well-formed, non-reserved capabilities TYPE. */
export function isCapabilitiesType(type: unknown): type is string {
	return typeof type === 'string' && TYPE_RE.test(type) && !isReservedType(type);
}

/** `sep`-separated, strictly ascending list of lo..hi tokens, or null. */
function tokenList(
	value: string | null,
	re: RegExp,
	lo: number,
	hi: number,
	sep = ',',
): string[] | null {
	if (value === null) return null;
	if (value === '') return lo === 0 ? [] : null;
	const parts = value.split(sep);
	if (parts.length < lo || parts.length > hi) return null;
	for (let i = 0; i < parts.length; i++) {
		if (!re.test(parts[i])) return null;
		// ASCII: code-unit order = byte order.
		if (i > 0 && !(parts[i - 1] < parts[i])) return null;
	}
	return parts;
}

/** A decoded label is valid: allowlisted scalars, 1-64 of them, single inner spaces. */
function labelValid(text: string): boolean {
	const scalars = Array.from(text);
	if (scalars.length < 1 || scalars.length > CAPABILITIES_LIMITS.MAX_LABEL_SCALARS) return false;
	for (const ch of scalars) {
		const cp = ch.codePointAt(0) as number;
		if (!LABEL_SINGLES.has(cp) && !LABEL_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi)) {
			return false;
		}
	}
	return text[0] !== ' ' && text[text.length - 1] !== ' ' && !text.includes('  ');
}

/**
 * Percent-encoded label -> text, or null. Canonical only (a byte that may be literal must be),
 * strict UTF-8 (fatal TextDecoder, never decodeURIComponent).
 */
function decodeLabel(value: string): string | null {
	if (!PCT_TEXT_RE.test(value)) return null;
	const raw: number[] = [];
	for (let i = 0; i < value.length;) {
		if (value[i] === '%') {
			// Two uppercase hex digits (checked by the regular expression).
			const octet = parseInt(value.slice(i + 1, i + 3), 16);
			if (octet >= 0x20 && octet <= 0x7e && octet !== 0x25 && octet !== 0x2c) return null;
			raw.push(octet);
			i += 3;
		} else {
			raw.push(value.charCodeAt(i));
			i += 1;
		}
	}
	let text: string | null;
	try {
		text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.from(raw));
	} catch {
		text = null;
	}
	return text !== null && labelValid(text) ? text : null;
}

/**
 * Strict parse of a pgw-capabilities-v1 document; null on any violation. Extension lines are
 * checked for their grammar, then dropped. Labels come back as a Map of Maps (ref -> lang -> text),
 * never an object keyed by server strings.
 */
export function parseCapabilitiesDocument(bytes: Buffer): VerifiedCapabilities | null {
	if (!Buffer.isBuffer(bytes) || bytes.length < CAPABILITIES_HEADER.length) return null;
	for (let i = 0; i < CAPABILITIES_HEADER.length; i++) {
		if (bytes[i] !== CAPABILITIES_HEADER.charCodeAt(i)) return null;
	}
	if (bytes.length > CAPABILITIES_LIMITS.MAX_BYTES) return null;
	const lines = documentLines(bytes);
	if (!lines || lines.length > CAPABILITIES_LIMITS.MAX_LINES || lines.length < 16) return null;

	if (lineValue(lines[1], 'version') !== '1') return null;
	const issuedAtRaw = lineValue(lines[2], 'issued_at');
	const issuedAt = issuedAtRaw === null ? null : parseUint(issuedAtRaw);
	const serverVersion = lineValue(lines[3], 'server_version');
	if (issuedAt === null || serverVersion === null || !RELEASE_RE.test(serverVersion)) return null;
	const languages = tokenList(
		lineValue(lines[4], 'languages'),
		LANG_RE,
		1,
		CAPABILITIES_LIMITS.MAX_LANGUAGES,
	);
	const labelLanguages = tokenList(
		lineValue(lines[5], 'label_languages'),
		LANG_RE,
		1,
		CAPABILITIES_LIMITS.MAX_LABEL_LANGUAGES,
	);
	if (!languages || !labelLanguages || !labelLanguages.includes('en')) return null;
	const maxTextRaw = lineValue(lines[6], 'max_text_chars');
	const maxBodyRaw = lineValue(lines[7], 'max_body_bytes');
	const maxTextChars = maxTextRaw === null ? null : parseUint(maxTextRaw);
	const maxBodyBytes = maxBodyRaw === null ? null : parseUint(maxBodyRaw);
	if (maxTextChars === null || maxBodyBytes === null || maxTextChars < 1 || maxBodyBytes < 1) {
		return null;
	}
	for (let i = 0; i < CAPABILITIES_LITERALS.length; i++) {
		if (lines[8 + i] !== CAPABILITIES_LITERALS[i]) return null;
	}
	const features = tokenList(
		lineValue(lines[15], 'features'),
		FLAG_RE,
		0,
		CAPABILITIES_LIMITS.MAX_FEATURES,
	);
	if (!features) return null;

	const groups: CapabilitiesGroup[] = [];
	const groupIds = new Set<string>();
	const entities: CapabilitiesEntity[] = [];
	const possible: CapabilitiesPossible[] = [];
	const labels = new Map<string, Map<string, string>>();
	let lastLabelKey: string | null = null;
	let labelCount = 0;
	let section = 0;
	let inExtensions = false;
	const groupRefs = (value: string): string[] | null => {
		const refs = tokenList(value, GID_RE, 1, CAPABILITIES_LIMITS.MAX_GROUPS, ';');
		return refs && refs.every((ref) => groupIds.has(ref)) ? refs : null;
	};

	for (const line of lines.slice(16)) {
		const eq = line.indexOf('=');
		if (eq < 0) return null;
		const name = line.slice(0, eq);
		const value = line.slice(eq + 1);
		const idx = SECTIONS.get(name);
		if (idx === undefined) {
			// Extension line: a new name, only after the last label.
			if (!EXT_NAME_RE.test(name) || CAPABILITIES_V1_NAMES.has(name)) return null;
			if (section !== 3 || labelCount === 0) return null;
			inExtensions = true;
			continue;
		}
		if (inExtensions || idx < section) return null;
		section = idx;
		const parts = value.split(',');
		if (idx === 0) {
			if (parts.length !== 2 || (parts[1] !== 'category' && parts[1] !== 'country')) return null;
			const [id, kind] = parts;
			if (!GID_RE.test(id) || (kind === 'country' && !COUNTRY_RE.test(id))) return null;
			if (groupIds.has(id) || groups.length >= CAPABILITIES_LIMITS.MAX_GROUPS) return null;
			groupIds.add(id);
			groups.push({ id, kind: kind as CapabilitiesGroup['kind'] });
		} else if (idx === 1) {
			if (parts.length !== 3 || (parts[1] !== 'on' && parts[1] !== 'opt_in')) return null;
			if (!isCapabilitiesType(parts[0])) return null;
			if (entities.length > 0 && !(entities[entities.length - 1].type < parts[0])) return null;
			if (entities.length >= CAPABILITIES_LIMITS.MAX_ENTITIES) return null;
			const refs = groupRefs(parts[2]);
			if (!refs) return null;
			entities.push({
				type: parts[0],
				default: parts[1] as CapabilitiesEntity['default'],
				groups: refs,
			});
		} else if (idx === 2) {
			if (parts.length !== 2 || !isCapabilitiesType(parts[0])) return null;
			if (possible.length > 0 && !(possible[possible.length - 1].type < parts[0])) return null;
			if (possible.length >= CAPABILITIES_LIMITS.MAX_POSSIBLE) return null;
			const refs = groupRefs(parts[1]);
			if (!refs) return null;
			possible.push({ type: parts[0], groups: refs });
		} else {
			if (parts.length !== 3) return null;
			const [ref, lang, encoded] = parts;
			const colon = ref.indexOf(':');
			if (colon < 0) return null;
			const kind = ref.slice(0, colon);
			const ident = ref.slice(colon + 1);
			const refOk = kind === 'type' ? TYPE_RE.test(ident) : kind === 'group' && GID_RE.test(ident);
			if (!refOk) return null;
			if (!LANG_RE.test(lang) || !labelLanguages.includes(lang)) return null;
			const text = decodeLabel(encoded);
			if (text === null) return null;
			const key = `${ref},${lang}`;
			if (lastLabelKey !== null && !(lastLabelKey < key)) return null;
			lastLabelKey = key;
			labelCount += 1;
			let byLang = labels.get(ref);
			if (!byLang) {
				byLang = new Map<string, string>();
				labels.set(ref, byLang);
			}
			byLang.set(lang, text);
		}
	}
	if (groups.length === 0 || entities.length === 0 || labelCount === 0) return null;

	const entityTypes = new Set(entities.map((e) => e.type));
	if (possible.some((p) => entityTypes.has(p.type))) return null;
	const members = new Set<string>();
	for (const row of [...entities, ...possible]) for (const g of row.groups) members.add(g);
	// Every group has a member (references are known to exist).
	if (members.size !== groupIds.size) return null;
	const refs = new Set<string>([
		...entities.map((e) => `type:${e.type}`),
		...possible.map((p) => `type:${p.type}`),
		...groups.map((g) => `group:${g.id}`),
	]);
	for (const [ref, byLang] of labels) {
		if (!refs.has(ref)) return null;
		if (!byLang.has('en')) return null;
	}
	// Every ref has (at least) an en label.
	if (labels.size !== refs.size) return null;

	return {
		version: 1,
		issuedAt,
		serverVersion,
		languages,
		labelLanguages,
		maxTextChars,
		maxBodyBytes,
		features,
		groups,
		entities,
		possible,
		labels,
	};
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Verifies a /v1/capabilities response (steps 1-11). Unknown top-level members and unknown members
 * inside `v1` are ignored. The delegation serial floor (step 12, read only) is the caller's.
 *
 * @param response parsed /v1/capabilities JSON
 * @param pinnedRoots trusted root public keys (base64url); empty -> nothing verifies
 * @param nowSeconds client clock, unix seconds
 * @param expectedAudience lowercase host of the API base URL, no port
 */
export function verifyCapabilitiesV1(
	response: unknown,
	pinnedRoots: readonly string[],
	nowSeconds: number,
	expectedAudience: string,
): CapabilitiesVerification {
	const unverified: CapabilitiesVerification = { ok: false, error: 'capabilities_unverified' };
	const now = Number(nowSeconds);
	if (!Number.isFinite(now)) return unverified;
	// 1. The v1 member with its four strings.
	if (!isRecord(response)) return unverified;
	const v1 = ownField(response, 'v1');
	if (!isRecord(v1)) return unverified;
	const delegation = ownField(v1, 'delegation');
	const delegationSig = ownField(v1, 'delegation_sig');
	const capabilities = ownField(v1, 'capabilities');
	const capabilitiesSig = ownField(v1, 'capabilities_sig');
	if (
		typeof delegation !== 'string' ||
		typeof delegationSig !== 'string' ||
		typeof capabilities !== 'string' ||
		typeof capabilitiesSig !== 'string'
	) {
		return unverified;
	}
	// 2. Size caps, canonical base64url, 64-byte signatures.
	if (
		delegation.length > V2_LIMITS.MAX_DOCUMENT_B64 ||
		capabilities.length > CAPABILITIES_LIMITS.MAX_B64
	) {
		return unverified;
	}
	const docBytes = b64urlDecodeStrict(capabilities, CAPS_B64_RE);
	const docSigBytes = strictB64.signature(capabilitiesSig);
	const delegationBytes = strictB64.document(delegation);
	const delegationSigBytes = strictB64.signature(delegationSig);
	if (!docBytes || !docSigBytes || !delegationBytes || !delegationSigBytes) return unverified;
	if (docBytes.length > CAPABILITIES_LIMITS.MAX_BYTES) return unverified;
	// 3-7. The delegation (shared with keyconfig v2).
	const delegationResult = verifyDelegationV2(
		delegationBytes,
		delegationSigBytes,
		pinnedRoots,
		now,
		expectedAudience,
	);
	if (!delegationResult.ok) {
		return delegationResult.error === 'hpke_stale_keyconfig'
			? { ok: false, error: 'capabilities_stale' }
			: unverified;
	}
	const d = delegationResult.delegation;
	// 8. Strict document grammar (header bytes first).
	const doc = parseCapabilitiesDocument(docBytes);
	if (!doc) return unverified;
	// 9. Delegated-key signature over the document bytes.
	if (!ed25519Verify(d.signingKey, docSigBytes, docBytes)) return unverified;
	// 10. Signed inside the delegation.
	if (doc.issuedAt < d.notBefore || doc.issuedAt > d.notAfter) return unverified;
	// 11. Fresh enough.
	if (
		now < doc.issuedAt - V2_LIMITS.CLIENT_SKEW_S ||
		now > doc.issuedAt + CAPABILITIES_LIMITS.MAX_AGE_S + V2_LIMITS.CLIENT_SKEW_S
	) {
		return { ok: false, error: 'capabilities_stale' };
	}
	return {
		ok: true,
		serial: d.serial,
		issuedAt: doc.issuedAt,
		notAfter: d.notAfter,
		capabilities: doc,
	};
}

/**
 * Whether a verified document is still inside its window: issued_at - skew ...
 * min(issued_at + max age, delegation end) + skew (the extension's `capabilitiesInWindow`).
 */
export function capabilitiesInWindow(
	result: { issuedAt: number; notAfter: number },
	now: number,
): boolean {
	const skew = V2_LIMITS.CLIENT_SKEW_S;
	const end = Math.min(result.issuedAt + CAPABILITIES_LIMITS.MAX_AGE_S, result.notAfter) + skew;
	return now >= result.issuedAt - skew && now <= end;
}
