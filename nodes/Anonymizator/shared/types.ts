/**
 * Shared types and constants for the Anonymizator node.
 *
 * Output shapes are `type` aliases rather than interfaces on purpose: an object type alias is
 * assignable to n8n's `IDataObject` (an index-signature type), an interface is not.
 */

/** The production privacy gateway. There is deliberately no base URL field (see critique O4). */
export const GATEWAY_BASE_URL = 'https://anon.prosecco37.com';

/** Credential type name. Frozen once published. */
export const CREDENTIAL_NAME = 'anonymizatorApi';

/** Default per-request timeout for gateway calls, in milliseconds. */
export const GATEWAY_TIMEOUT_MS = 30000;

/** One detected range as returned by `/v1/analyze`. Offsets index into the original text. */
export type Span = {
	entity_type: string;
	start: number;
	end: number;
	score?: number;
};

/**
 * Placeholder style. `random` and `sequential` pseudonymise (revealable through the map); `typed`
 * and `redacted` mask (nothing is kept, the output cannot be revealed).
 */
export type Numbering = 'random' | 'sequential' | 'typed' | 'redacted';

/** Placeholder styles that keep nothing and cannot be revealed. */
export type MaskMode = 'typed' | 'redacted';

/** Flat bare-key table, e.g. `{ PERSON_a7k2q: 'Janez Novak', PERSON_a7k2q_NAME: 'Janez' }`. */
export type PlaceholderTable = Record<string, string>;

/** One substituted range as produced by `anonymizeFromSpans` / `mask` (extension shape). */
export type LocalEntity = {
	entity_type: string;
	/** The bracketed token written into the output, e.g. `[PERSON_a7k2q]`. */
	replacement: string;
	/** Offsets into the OUTPUT text. */
	start: number;
	end: number;
	score: number;
};

/** Result of `anonymizeFromSpans`. `newEntries` holds only the keys minted by this call. */
export type AnonymizeResult = {
	text: string;
	entities: LocalEntity[];
	newEntries: PlaceholderTable;
};

/** Result of `mask`: no entries are minted. */
export type MaskResult = {
	text: string;
	entities: LocalEntity[];
};

export type AnonymizeOptions = {
	sequential?: boolean;
};

/** Result of `gateway.analyze`. */
export type AnalyzeResult = {
	spans: Span[];
	/** True when a sealed `invalid_entities` made the gateway retry without the type filter. */
	entityFilterIgnored: boolean;
};

/** One entity in the node's Protect output. */
export type OutputEntity = {
	entityType: string;
	placeholder: string;
	/** Offsets into `protectedText`. */
	start: number;
	end: number;
	score: number;
};

/** One row of an extension ID file v1. */
export type IdFileEntry = {
	value: string;
	placeholder: string;
	addedByYou: boolean;
};

/** Extension-compatible ID file, version 1 (`sidepanel/sidepanel-idfile.js`). */
export type IdFileV1 = {
	format: 'anonymizator-id-file';
	version: 1;
	name: string;
	numbering: Numbering;
	ids: IdFileEntry[];
	usedPlaceholders: string[];
};

/** Protect output item json (before optional input fields are merged in). */
export type ProtectResult = {
	protectedText: string;
	placeholderMap: PlaceholderTable;
	entities: OutputEntity[];
	entityFilterIgnored?: true;
	idFile?: IdFileV1;
};

/** Reveal output item json (before optional input fields are merged in). */
export type RevealResult = {
	revealedText: string;
	unresolvedPlaceholders: string[];
};

/** HPKE suite identifiers as carried in the keyconfig. Only `{kem:32,kdf:1,aead:2}` is accepted. */
export type HpkeSuite = {
	kem: number;
	kdf: number;
	aead: number;
};

/** One key in the gateway's `/v1/keyconfig`. `public_key` is raw X25519, base64url. */
export type KeyconfigEntry = {
	key_id: number;
	public_key: string;
	suite?: HpkeSuite;
	/** Not covered by the signature: never trust it for security decisions. */
	not_after?: string;
};

/** The gateway's `/v1/keyconfig` document. */
export type Keyconfig = {
	version?: number;
	keys: KeyconfigEntry[];
	sig_alg?: unknown;
	signature?: unknown;
};
