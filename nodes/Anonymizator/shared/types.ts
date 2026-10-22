/**
 * Shared types and constants for the Anonymizator node.
 *
 * Output shapes are `type` aliases rather than interfaces on purpose: an object type alias is
 * assignable to n8n's `IDataObject` (an index-signature type), an interface is not.
 */
import type { IdFileV2 } from './placeholderMap';

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

/**
 * One possible ID in the Protect output: text left in clear that a person should check (a prompt to
 * look, not a score). Offsets into `protectedText`.
 */
export type ProtectPossibleId = {
	start: number;
	end: number;
	value: string;
	/** company-name, surname, title-surname, case-form, number, amount, company or detected. */
	kind: string;
	/** An ID type code (PERSON, COMPANY, NUMBER, ...), or null when unknown. */
	type: string | null;
};

/** Protect output item json (before optional input fields are merged in). */
export type ProtectResult = {
	protectedText: string;
	/** Omitted when Include Placeholder Map is off. */
	placeholderMap?: PlaceholderTable;
	entities: OutputEntity[];
	entityFilterIgnored?: true;
	/** With Include ID File (and Include Placeholder Map on), Random and Numbers in Order only. */
	idFile?: IdFileV2;
	/** With Include Possible IDs. */
	possibleIds?: ProtectPossibleId[];
	/** With Include Possible IDs, only when the list was capped. */
	possibleIdsTruncated?: true;
};

/** One entity in the node's Detect output. */
export type DetectEntity = {
	entityType: string;
	/** UTF-16 offsets into the ORIGINAL text (String#slice). */
	start: number;
	end: number;
	score: number;
	/** The matched text; present only with Include Values. */
	value?: string;
};

/** One possible ID in the Detect output: a gateway review-only span, never counted as found. */
export type DetectPossibleId = {
	entityType: string;
	/** UTF-16 offsets into the ORIGINAL text (String#slice). */
	start: number;
	end: number;
	/** The text; present only with Include Values. */
	value?: string;
};

/** Detect output item json (before optional input fields are merged in). */
export type DetectResult = {
	hasPersonalData: boolean;
	entityCount: number;
	countsByType: Record<string, number>;
	entities: DetectEntity[];
	entityFilterIgnored?: true;
	/** With Include Possible IDs. */
	possibleIds?: DetectPossibleId[];
};

/** Reveal output item json (before optional input fields are merged in). */
export type RevealResult = {
	revealedText: string;
	unresolvedPlaceholders: string[];
};
