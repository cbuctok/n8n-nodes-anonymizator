/**
 * Protect: detect personal data through the gateway (ranges only) and substitute it locally.
 *
 * Only detection leaves n8n: the gateway receives the HPKE-sealed text and answers with ranges.
 * Substitution, the placeholder map, Additionally Protect, possible IDs and the ID file are all
 * produced here, by the port of the extension's Protect pipeline (`shared/protectPipeline.ts`).
 *
 * Also home of the helpers Protect shares with Detect and Reveal: the text and map readers, the
 * entity-type list and filter, the gateway call (`detectRemotely`) and the error mapping
 * (`gatewayFailure`).
 */
import type {
	IDataObject,
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INodeExecutionData,
	INodeProperties,
	INodePropertyOptions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';

import { entityFilter, entityOptions, mergeCatalog } from '../shared/entities';
import type { MergedCatalog } from '../shared/entities';
import { errorNode, GatewayError } from '../shared/errors';
import type { ExtraOptions } from '../shared/extraDetect';
import { analyze, effectiveMaxTextChars, fetchCapabilities } from '../shared/gateway';
import type { PossibleSpan } from '../shared/gateway';
import { failedPartText, gatewayErrorText, LOCAL_FAILURES } from '../shared/gatewayMessages';
import { ignoredTermTest, parseIgnoreTerms } from '../shared/ignoreTerms';
import { parsePlaceholderMap, toIdFile } from '../shared/placeholderMap';
import type { ParsedPlaceholderMap } from '../shared/placeholderMap';
import { detectedValues, fromFlatMap, protect, revealTable } from '../shared/protectPipeline';
import type { PipelineState } from '../shared/protectPipeline';
import type { Alias, IdRecord } from '../shared/idModel';
import { CREDENTIAL_NAME } from '../shared/types';
import type { Numbering, PlaceholderTable, ProtectResult, Span } from '../shared/types';

const showForProtect = { show: { operation: ['protect'] } };
const showForGateway = { show: { operation: ['protect', 'detect'] } };

/** Accepted map formats, quoted in every map error so the user knows what to send. */
export const MAP_FORMATS_HINT =
	'Accepted formats: a JSON object of placeholders to values (bare or [bracketed] keys, e.g. {"PERSON_a7k2q": "Janez Novak"}), an array of {placeholder, value} objects, or an ID file saved by the Anonymizator browser extension.';

/** Ignore Terms option, shared by Protect and Detect. */
export const IGNORE_TERMS_OPTION: INodeProperties = {
	displayName: 'Ignore Terms',
	name: 'ignoreTerms',
	type: 'string',
	typeOptions: { rows: 2 },
	default: '',
	placeholder: 'e.g. Acme, Acme Cloud',
	description:
		'Terms that are never treated as personal data, such as your company or product names. Separate them with commas or new lines. A detection is dropped when its whole text equals a term (ignoring case). The text is still sent to the gateway as is; the terms never leave n8n.',
};

/** Include Possible IDs: Protect and Detect word it differently, the name and default are shared. */
export function includePossibleIdsOption(description: string): INodeProperties {
	return {
		displayName: 'Include Possible IDs',
		name: 'includePossibleIds',
		type: 'boolean',
		default: false,
		description,
	};
}

export const protectDescription: INodeProperties[] = [
	{
		displayName: 'Text',
		name: 'text',
		type: 'string',
		required: true,
		default: '',
		typeOptions: { rows: 4 },
		placeholder: 'e.g. Janez Novak (ana.kovac@example.com) asked about his invoice',
		description: 'The text to protect',
		displayOptions: showForProtect,
	},
	{
		displayName: 'Detect',
		name: 'detect',
		type: 'options',
		options: [
			{
				name: 'All Types',
				value: 'all',
				description: 'Detect every type of personal data the gateway supports',
			},
			{
				name: 'Selected Types',
				value: 'selected',
				description: 'Detect only the types you pick',
			},
		],
		default: 'all',
		description: 'Which kinds of personal data to look for',
		displayOptions: showForGateway,
	},
	{
		displayName: 'Entity Type Names or IDs',
		name: 'entityTypes',
		type: 'multiOptions',
		required: true,
		typeOptions: { loadOptionsMethod: 'getEntityTypes' },
		default: [],
		description:
			"The kinds of personal data to detect. Selecting every built-in type is the same as 'All Types'; types the server adds later are then detected too. The list holds the types built into the node plus any the gateway's signed capabilities add. Choose from the list, or specify IDs using an <a href=\"https://docs.n8n.io/code/expressions/\">expression</a>.",
		displayOptions: { show: { operation: ['protect', 'detect'], detect: ['selected'] } },
	},
	{
		displayName: 'Placeholder Style',
		name: 'placeholderStyle',
		type: 'options',
		options: [
			{
				name: 'Random',
				value: 'random',
				description:
					"[PERSON_a7k2q], the default. Doesn't show the order IDs were added. Can be revealed with the placeholder map.",
			},
			{
				name: 'Numbers in Order',
				value: 'sequential',
				description:
					'[PERSON_1]. Easier to follow, but shows the order IDs were added. Can be revealed with the placeholder map.',
			},
			{
				name: 'Type Only',
				value: 'typed',
				description:
					"[PERSON], [PHONE], ... Hides which ID is which, so AI answers may be noticeably worse, and the text can't be revealed.",
			},
			{
				name: 'Redacted',
				value: 'redacted',
				description:
					"[REDACTED]. Hides even the kind of ID, and the text can't be revealed. For the most sensitive text.",
			},
		],
		default: 'random',
		description:
			"How found IDs are replaced. Random doesn't show the order IDs were added. Numbers in Order is easier to follow, but shows that order. Type Only and Redacted hide which ID is which, so AI answers may be noticeably worse, and the text can't be revealed. No option makes text anonymous.",
		displayOptions: showForProtect,
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: showForProtect,
		options: [
			{
				displayName: 'Additionally Protect',
				name: 'additionallyProtect',
				type: 'multiOptions',
				options: [
					{
						name: 'All Currency Values',
						value: 'AMOUNT',
						description:
							'Amounts with a currency before or after them, such as 4.800,00 EUR, €4.800 or CHF 300 ([AMOUNT_...])',
					},
					{
						name: 'All Numbers',
						value: 'NUMBER',
						description:
							'Every number left in the text, including numbers inside codes such as K101, INV-2024-118 or 15.5.2026 (each as one [NUMBER_...]). In info@acme2.si the part acme2.si is protected too.',
					},
					{
						name: 'Company Names (With Legal Suffixes Only)',
						value: 'COMPANY',
						description:
							'Names that end in a legal form such as d.o.o., d.d., GmbH or Ltd ([COMPANY_...])',
					},
				],
				default: [],
				description:
					'More to protect besides what the gateway finds. Off unless selected. Worked out here in n8n: these settings are never sent to the gateway.',
			},
			{
				displayName: 'Existing Placeholder Map',
				name: 'existingPlaceholderMap',
				type: 'json',
				default: '{}',
				placeholder: "e.g. {{ $('Protect').item.json.placeholderMap }}",
				description:
					'Continue an earlier map: values it already holds keep their placeholders, new placeholders never collide with it, and numbering in order carries on. Values in this map are always replaced, even when they are also listed in Ignore Terms. Accepts the same formats as Reveal, including an ID file from the browser extension (version 1 or 2). To keep groups and types, pass the idFile (or the whole Protect item) rather than placeholderMap alone.',
			},
			IGNORE_TERMS_OPTION,
			{
				displayName: 'Include ID File',
				name: 'includeIdFile',
				type: 'boolean',
				default: false,
				description:
					"Whether to add an idFile field (ID file version 2) that the Anonymizator browser extension can open with Load IDs. To save it, use Convert to File → Convert to Text File with 'Text Input Field' set to idFile (Convert to JSON wraps it in the item, and the extension refuses that file). Only for the Random and Numbers in Order styles, and only when there are IDs: Type Only and Redacted add no file. The file holds the real values, so it needs 'Include Placeholder Map' on.",
			},
			{
				displayName: 'Include Input Fields',
				name: 'includeInputFields',
				type: 'boolean',
				default: false,
				description: 'Whether to copy the fields of the input item into the output item',
			},
			{
				displayName: 'Include Placeholder Map',
				name: 'includePlaceholderMap',
				type: 'boolean',
				default: true,
				description:
					'Whether to output placeholderMap, which holds the real values. Turn it off when the output goes back to an LLM, for example when an AI agent calls this node as a tool: returning the map would hand the real values to the model. Without the map, the protected text cannot be revealed later.',
			},
			includePossibleIdsOption(
				'Whether to add possibleIds: text left in clear that you may want to check, such as "Luki" next to the ID "Luka Zupan", "Mr. Zupan", or "Modra Vila" without its d.o.o., plus what the gateway flags for review when it offers that. Possible IDs are a prompt to look, not a score: they are never replaced, and text that is not listed can still hold personal data.',
			),
			{
				displayName: 'Share Map Across Items',
				name: 'shareMapAcrossItems',
				type: 'boolean',
				default: false,
				description:
					'Whether all items of this execution share one running map, so the same value gets the same placeholder in every item. Each item outputs the map as it stands after that item.',
			},
		],
	},
];

// ---------------------------------------------------------------------------------------------
// Entity types

/**
 * Load-options method `getEntityTypes`: the bundled catalog merged with the gateway's verified
 * capabilities (only the bundled catalog when they cannot be fetched or verified).
 */
export async function loadEntityTypeOptions(
	this: ILoadOptionsFunctions,
): Promise<INodePropertyOptions[]> {
	// The editor also asks before a credential is selected. That request cannot be made, and a
	// failed attempt holds the bundled list for the retry interval, even after one is selected.
	let hasCredential = true;
	try {
		await this.getCredentials(CREDENTIAL_NAME);
	} catch {
		hasCredential = false;
	}
	return entityOptions(mergeCatalog(hasCredential ? await fetchCapabilities(this) : null));
}

/** Reads Detect and Entity Types into the gateway filter (undefined = all types). */
export function readEntityTypes(
	ctx: IExecuteFunctions,
	itemIndex: number,
	merged: MergedCatalog,
): string[] | undefined {
	const detect = ctx.getNodeParameter('detect', itemIndex, 'all') as string;
	if (detect !== 'selected') return undefined;
	const raw: unknown = ctx.getNodeParameter('entityTypes', itemIndex, []);
	// An expression may give one id as a string.
	const ids = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[,\s]+/) : [];
	return entityFilter(merged, ids);
}

// ---------------------------------------------------------------------------------------------
// Gateway

/** What `detectRemotely` returns: the gateway's findings for one item. */
export type GatewayDetection = {
	spans: Span[];
	/** Review-only spans of the types the capabilities list; [] unless asked for. */
	possible: PossibleSpan[];
	entityFilterIgnored: boolean;
};

/**
 * The gateway call of Protect and Detect. Blank text never leaves n8n (no request at all).
 * Otherwise the verified capabilities (cached; null on any failure) give the entity list, the
 * per-request text cap and the possible types; `possible: true` is requested only when asked for
 * AND the capabilities list possible types, as the extension does. A text longer than one request
 * is sent in parts and the spans come back merged onto the whole text (`analyze`); any failed part
 * fails the item, so the caller's local steps run once over the whole text or not at all.
 */
export async function detectRemotely(
	ctx: IExecuteFunctions,
	itemIndex: number,
	text: string,
	wantPossible: boolean,
): Promise<GatewayDetection> {
	if (text.trim() === '') return { spans: [], possible: [], entityFilterIgnored: false };
	const caps = await fetchCapabilities(ctx);
	const entityTypes = readEntityTypes(ctx, itemIndex, mergeCatalog(caps));
	const possibleTypes = new Set((caps?.possible ?? []).map((p) => p.type));
	const askPossible = wantPossible && possibleTypes.size > 0;
	const maxTextChars = effectiveMaxTextChars(caps);
	let result;
	try {
		result = await analyze(
			ctx,
			text,
			entityTypes,
			askPossible ? { possible: true, maxTextChars } : { maxTextChars },
		);
	} catch (error) {
		throw gatewayFailure(ctx, error, itemIndex);
	}
	return {
		spans: result.spans,
		possible: askPossible
			? (result.possible ?? []).filter((p) => possibleTypes.has(p.entity_type))
			: [],
		entityFilterIgnored: result.entityFilterIgnored,
	};
}

/**
 * Turns a failure from `gateway.analyze` into the n8n error to throw, worded by
 * `shared/gatewayMessages.ts`. Failures with an HTTP status become NodeApiError, the rest (local
 * checks, keyconfig verification, offline, timeout) NodeOperationError.
 */
export function gatewayFailure(
	ctx: IExecuteFunctions,
	error: unknown,
	itemIndex: number,
): NodeApiError | NodeOperationError {
	const node = errorNode(ctx);
	if (error instanceof NodeApiError || error instanceof NodeOperationError) return error;

	if (error instanceof GatewayError) {
		const text = gatewayErrorText(error.code, {
			retryAfter: error.retryAfter,
			httpCode: error.httpCode,
		});
		const parts = [text.description];
		// Client-side detail only: the gateway layer never keeps server text.
		if (error.detail) parts.push(error.detail);
		// A text sent in parts: which part failed (numbers only).
		const partText = failedPartText(error.failedPart, error.parts);
		if (partText) parts.push(partText);
		parts.push(`(code: ${error.code})`);
		const description = parts.join(' ');

		if (typeof error.httpCode === 'number' && !LOCAL_FAILURES.has(error.code)) {
			return new NodeApiError(
				node,
				{ message: error.message, code: error.code, httpCode: String(error.httpCode) },
				{ message: text.message, description, httpCode: String(error.httpCode), itemIndex },
			);
		}
		return new NodeOperationError(node, text.message, { itemIndex, description });
	}

	const hasResponse =
		typeof error === 'object' &&
		error !== null &&
		typeof (error as { response?: unknown }).response === 'object';
	if (hasResponse) {
		return new NodeApiError(node, error as JsonObject, { itemIndex });
	}
	return new NodeOperationError(node, error as Error, { itemIndex });
}

// ---------------------------------------------------------------------------------------------
// Parameters

const NUMBERINGS: readonly Numbering[] = ['random', 'sequential', 'typed', 'redacted'];

function hasOwn(object: object, key: string): boolean {
	return Object.prototype.hasOwnProperty.call(object, key);
}

function isMasked(style: Numbering): boolean {
	return style === 'typed' || style === 'redacted';
}

/** Reads a text parameter, accepting numbers and booleans from expressions. */
export function readTextParameter(
	ctx: IExecuteFunctions,
	itemIndex: number,
	label: string,
): string {
	const raw: unknown = ctx.getNodeParameter('text', itemIndex, '');
	if (typeof raw === 'string') return raw;
	if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
	if (raw === null || raw === undefined) return '';
	throw new NodeOperationError(errorNode(ctx), `${label} must be text`, {
		itemIndex,
		description: `The expression in ${label} resolved to ${Array.isArray(raw) ? 'an array' : 'an object'}. Point it at a text field, or wrap it in JSON.stringify() if you really want to process the JSON.`,
	});
}

/**
 * Parses a user-supplied placeholder map and turns any refusal into a NodeOperationError that names
 * the parameter. Shared with Reveal.
 */
export function parseMapParameter(
	ctx: IExecuteFunctions,
	input: unknown,
	itemIndex: number,
	label: string,
): ParsedPlaceholderMap {
	try {
		return parsePlaceholderMap(input);
	} catch (error) {
		throw new NodeOperationError(errorNode(ctx), `${label}: ${(error as Error).message}`, {
			itemIndex,
			description: MAP_FORMATS_HINT,
		});
	}
}

const EXTRA_VALUES = ['NUMBER', 'AMOUNT', 'COMPANY'] as const;

/**
 * Additionally Protect as the pipeline's three booleans. An expression may give a list or a
 * comma-separated string; values are trimmed and upper-cased. Anything else is refused, because a
 * silently dropped value would protect less than the user asked for.
 */
function readExtra(ctx: IExecuteFunctions, raw: unknown, itemIndex: number): ExtraOptions {
	const refuse = (what: string): NodeOperationError =>
		new NodeOperationError(errorNode(ctx), `Additionally Protect: ${what}`, {
			itemIndex,
			description: `Use a list (or a comma-separated text) of these values: ${EXTRA_VALUES.join(', ')}. Nothing was sent to the gateway.`,
		});
	let values: unknown[];
	if (raw === undefined || raw === null) values = [];
	else if (Array.isArray(raw)) values = raw;
	else if (typeof raw === 'string') values = raw.split(/[,\s]+/);
	else throw refuse('the expression must give a list or a text');
	const wanted = new Set<string>();
	values.forEach((value, i) => {
		if (typeof value !== 'string') throw refuse(`entry ${i + 1} is not text`);
		const id = value.trim().toUpperCase();
		if (id === '') return;
		if (!(EXTRA_VALUES as readonly string[]).includes(id)) {
			throw refuse(`entry ${i + 1} is not one of the values`);
		}
		wanted.add(id);
	});
	return {
		NUMBER: wanted.has('NUMBER'),
		AMOUNT: wanted.has('AMOUNT'),
		COMPANY: wanted.has('COMPANY'),
	};
}

// ---------------------------------------------------------------------------------------------
// The ID set

/**
 * Running state for one execution when maps are shared across items. Created once by the execute
 * loop with `createProtectRunState()` and passed to every Protect item.
 */
export type ProtectRunState = {
	/** The shared ID set, from the first item that shares on. */
	state: PipelineState | null;
};

export function createProtectRunState(): ProtectRunState {
	return { state: null };
}

/**
 * The ID set an item starts from: the set of an ID file input, else the flat map as a set
 * (`fromFlatMap`). The node's Placeholder Style always wins over a file's numbering; a masked style
 * keeps no reveal-only placeholders (they reveal nothing; their keys stay used).
 */
function itemState(parsed: ParsedPlaceholderMap, style: Numbering): PipelineState {
	if (!parsed.set) {
		return fromFlatMap({ table: parsed.table, used: parsed.used, mine: parsed.mine }, style);
	}
	const set = parsed.set;
	return {
		numbering: style,
		ids: set.ids.map((r) => ({ ...r })),
		subKeys: { ...set.subKeys },
		aliases: isMasked(style) ? {} : { ...set.aliases },
		used: [...set.used],
	};
}

/** What a key reveals in `state` (main record, name part or reveal-only), or undefined. */
function liveValue(state: PipelineState, key: string): string | undefined {
	const main = state.ids.find((r) => r.main && r.key === key);
	if (main) return main.value;
	if (hasOwn(state.subKeys, key)) return state.subKeys[key].value;
	if (hasOwn(state.aliases, key)) return state.aliases[key].value;
	return undefined;
}

/**
 * Merges an item's set into the shared one. A key the shared set already reveals as a different
 * value is refused (nothing is merged then); the same key with the same value is kept once.
 * Everything else (records, group members, name parts, reveal-only placeholders, used keys) is
 * added, with the rules `fromFlatMap` applies inside one map, so the merged set stays one the
 * extension would load:
 * - a value the shared set already holds under another key keeps that key; the incoming key
 *   becomes reveal-only for it (and its group members and name parts move to that key);
 * - a live incoming key the shared set has only as reveal-only takes it back (the extension's
 *   reclaim), so its value is replaced again;
 * - name parts and reveal-only placeholders whose owner is not a live record are dropped.
 */
function mergeState(
	ctx: IExecuteFunctions,
	shared: PipelineState,
	incoming: PipelineState,
	itemIndex: number,
): void {
	const keys: Array<[string, string]> = [
		...incoming.ids.filter((r) => r.main).map((r): [string, string] => [r.key, r.value]),
		...Object.entries(incoming.subKeys).map(([k, s]): [string, string] => [k, s.value]),
		...Object.entries(incoming.aliases).map(([k, a]): [string, string] => [k, a.value]),
	];
	for (const [key, value] of keys) {
		const current = liveValue(shared, key);
		if (current !== undefined && current.trim() !== value.trim()) {
			throw new NodeOperationError(
				errorNode(ctx),
				`Existing Placeholder Map conflicts with the shared map: ${key} already stands for a different value`,
				{
					itemIndex,
					description:
						'With Share Map Across Items on, the existing map of every item is merged into one running map, so a placeholder can only stand for one value. Turn the option off or remove the conflicting entry.',
				},
			);
		}
	}

	const byValue = new Map<string, IdRecord>();
	const mains = new Map<string, IdRecord>();
	for (const r of shared.ids) {
		if (!byValue.has(r.value)) byValue.set(r.value, r);
		if (r.main) mains.set(r.key, r);
	}
	// Incoming keys whose main value the shared set holds under another key: they now stand for it.
	const redirect = new Map<string, string>();
	const redirectAliases: Array<[string, Alias]> = [];
	for (const record of incoming.ids) {
		const holder = byValue.get(record.value);
		if (holder && record.main && holder.key !== record.key) {
			redirect.set(record.key, holder.key);
			redirectAliases.push([record.key, { value: record.value, owner: holder.key }]);
		}
	}
	const target = (key: string): string => redirect.get(key) ?? key;

	const added: IdRecord[] = [];
	for (const record of incoming.ids) {
		const holder = byValue.get(record.value);
		if (holder) {
			// Already protected: by the same key (kept once), or by another one (reveal-only below).
			if (holder.key === record.key && record.mine) holder.mine = true;
			continue;
		}
		if (hasOwn(shared.subKeys, record.key)) continue; // the same value, as a name part
		const key = target(record.key);
		const main = mains.get(key);
		if (hasOwn(shared.aliases, key)) delete shared.aliases[key]; // reclaim
		// A group keeps its shared main and its type (one type per key, as the extension repairs).
		const copy: IdRecord = {
			...record,
			key,
			type: main ? main.type : record.type,
			main: record.main && !main,
		};
		added.push(copy);
		byValue.set(copy.value, copy);
		if (copy.main) mains.set(key, copy);
	}
	shared.ids = [...added, ...shared.ids];

	const free = (key: string): boolean =>
		!mains.has(key) && !hasOwn(shared.subKeys, key) && !hasOwn(shared.aliases, key);
	for (const [key, part] of Object.entries(incoming.subKeys)) {
		const owner = mains.get(target(part.of));
		if (!free(key) || !owner || owner.type !== 'PERSON') continue;
		shared.subKeys[key] = { of: owner.key, value: part.value, rec: owner.value };
	}
	for (const [key, alias] of [...Object.entries(incoming.aliases), ...redirectAliases]) {
		const owner = target(alias.owner);
		if (!free(key) || !mains.has(owner)) continue;
		shared.aliases[key] = { value: alias.value, owner };
	}

	const used = new Set(shared.used);
	for (const key of incoming.used) {
		if (!used.has(key)) {
			used.add(key);
			shared.used.push(key);
		}
	}
}

/**
 * The output map: what Reveal needs (`revealTable`: every main value with its name parts, oldest
 * first, then the reveal-only placeholders), plus every retired key as an empty value, the format's
 * way of saying "never reuse", so a map passed back in as Existing Placeholder Map keeps them
 * retired. Empty for masked styles: nothing can be revealed.
 */
export function outputMap(state: PipelineState): PlaceholderTable {
	const reveal = revealTable(state);
	const out: PlaceholderTable = {};
	if (isMasked(state.numbering)) return out;
	const put = (key: string): void => {
		if (hasOwn(reveal, key) && !hasOwn(out, key)) out[key] = reveal[key];
	};
	// Name parts grouped by owner once, so this stays linear in records plus name parts.
	const partsOf = new Map<string, string[]>();
	for (const [key, part] of Object.entries(state.subKeys)) {
		const parts = partsOf.get(part.of);
		if (parts) parts.push(key);
		else partsOf.set(part.of, [key]);
	}
	for (let i = state.ids.length - 1; i >= 0; i--) {
		const record = state.ids[i];
		if (!record.main) continue;
		put(record.key);
		for (const key of partsOf.get(record.key) ?? []) put(key);
	}
	for (const key of Object.keys(reveal)) put(key);
	for (const key of state.used) if (!hasOwn(out, key)) out[key] = '';
	return out;
}

/**
 * Output fields Protect writes only in some runs. Include Input Fields must not carry them over from
 * the input item (for example an earlier Protect), where they would describe another text.
 */
const PROTECT_FIELDS = ['entityFilterIgnored', 'idFile', 'possibleIds', 'possibleIdsTruncated'];

/** A copy of an input item's json without `fields`, for Include Input Fields. */
export function withoutFields(
	json: IDataObject | undefined,
	fields: readonly string[],
): IDataObject {
	const copy: IDataObject = { ...(json ?? {}) };
	for (const field of fields) delete copy[field];
	return copy;
}

// ---------------------------------------------------------------------------------------------

export async function executeProtect(
	this: IExecuteFunctions,
	itemIndex: number,
	runState: ProtectRunState,
): Promise<INodeExecutionData[]> {
	const text = readTextParameter(this, itemIndex, 'Text');

	const style = this.getNodeParameter('placeholderStyle', itemIndex, 'random') as Numbering;
	if (!NUMBERINGS.includes(style)) {
		throw new NodeOperationError(errorNode(this), `Unknown placeholder style "${String(style)}"`, {
			itemIndex,
			description: 'Use one of: random, sequential, typed, redacted.',
		});
	}

	const options = this.getNodeParameter('options', itemIndex, {}) as IDataObject;
	// Default on: an absent option (older saved workflows) keeps the map in the output.
	const includeMap = options.includePlaceholderMap !== false;
	if (!includeMap && options.includeIdFile === true) {
		throw new NodeOperationError(
			errorNode(this),
			"'Include ID File' needs 'Include Placeholder Map' on",
			{
				itemIndex,
				description:
					"The ID file holds the same real values as the placeholder map. Turn off 'Include ID File', or turn 'Include Placeholder Map' back on. Nothing was sent to the gateway.",
			},
		);
	}
	const isSkipped = ignoredTermTest(parseIgnoreTerms(options.ignoreTerms));
	const extra = readExtra(this, options.additionallyProtect, itemIndex);
	const includePossible = options.includePossibleIds === true;
	const existing = parseMapParameter(
		this,
		options.existingPlaceholderMap,
		itemIndex,
		'Existing Placeholder Map',
	);

	let state = itemState(existing, style);
	if (options.shareMapAcrossItems === true) {
		if (runState.state) {
			mergeState(this, runState.state, state, itemIndex);
			runState.state.numbering = style;
		} else {
			runState.state = state;
		}
		state = runState.state;
	}

	// Only detection happens remotely; blank text never leaves n8n.
	const found = await detectRemotely(this, itemIndex, text, includePossible);

	// Ignore Terms is the pipeline's skipped test: gateway detections, companies and Additionally
	// Protect matches equal to a term are left alone, but values of the existing (or shared) map are
	// still replaced: the map wins.
	// `findPossible`: the pipeline may skip the possible-ID search when nobody reads it.
	const pipelineOptions = {
		extra,
		detected: includePossible ? detectedValues(text, found.possible) : [],
		findPossible: includePossible,
		...(isSkipped ? { isSkipped } : {}),
	};
	const out = protect(state, text, found.spans, pipelineOptions);

	const result: ProtectResult = {
		protectedText: out.text,
		placeholderMap: outputMap(state),
		// Never `value` or `key`: with Include Placeholder Map off the output holds no real value.
		entities: out.entities.map((entity) => ({
			entityType: entity.entityType,
			placeholder: entity.placeholder,
			start: entity.start,
			end: entity.end,
			score: entity.score,
		})),
	};
	if (found.entityFilterIgnored) result.entityFilterIgnored = true;
	if (includePossible) {
		result.possibleIds = out.possible.map((p) => ({
			start: p.start,
			end: p.end,
			value: p.value,
			kind: p.kind,
			type: p.type,
		}));
		if (out.possibleMore) result.possibleIdsTruncated = true;
	}

	// As before the extension parity: masked styles write no ID file, so a workflow saved with
	// Type Only or Redacted never starts to output every real value.
	if (options.includeIdFile === true && !isMasked(style) && state.ids.length > 0) {
		try {
			result.idFile = toIdFile(state);
		} catch (error) {
			// The extension's Load IDs would refuse such a file (e.g. one value under two placeholders
			// inherited from merged existing maps), so say which option failed and why.
			throw new NodeOperationError(
				errorNode(this),
				`Include ID File: ${(error as Error).message}`,
				{
					itemIndex,
					description:
						'The map cannot be saved as an ID file the browser extension would load. Turn off Include ID File, or clean up the Existing Placeholder Map so every value has a single placeholder.',
				},
			);
		}
	}

	const json: IDataObject =
		options.includeInputFields === true
			? { ...withoutFields(this.getInputData()[itemIndex]?.json, PROTECT_FIELDS), ...result }
			: { ...result };

	if (!includeMap) {
		// Also removes a placeholderMap or idFile copied from the input item by Include Input Fields,
		// so the output never carries real values in these fields.
		delete json.placeholderMap;
		delete json.idFile;
	}

	return [{ json, pairedItem: { item: itemIndex } }];
}
