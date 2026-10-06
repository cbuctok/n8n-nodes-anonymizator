/**
 * Protect: detect personal data through the gateway (ranges only) and substitute it locally.
 *
 * Only detection leaves n8n: the gateway receives the HPKE-sealed text and answers with ranges.
 * Substitution, the placeholder map and the ID file are all produced here, by the ported extension
 * engine in `shared/anonymizer.ts`.
 */
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';

import { anonymizeFromSpans, mask } from '../shared/anonymizer';
import { ENTITY_OPTIONS, selectionToEntityTypes } from '../shared/entities';
import { errorNode, GatewayError } from '../shared/errors';
import { analyze } from '../shared/gateway';
import { parsePlaceholderMap, toIdFile } from '../shared/placeholderMap';
import type { ParsedPlaceholderMap } from '../shared/placeholderMap';
import type {
	LocalEntity,
	Numbering,
	OutputEntity,
	PlaceholderTable,
	ProtectResult,
	Span,
} from '../shared/types';

const showForProtect = { show: { operation: ['protect'] } };

/** Accepted map formats, quoted in every map error so the user knows what to send. */
export const MAP_FORMATS_HINT =
	'Accepted formats: a JSON object of placeholders to values (bare or [bracketed] keys, e.g. {"PERSON_a7k2q": "Janez Novak"}), an array of {placeholder, value} objects, or an ID file saved by the Anonymizator browser extension.';

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
		displayOptions: showForProtect,
	},
	{
		displayName: 'Entity Types',
		name: 'entityTypes',
		type: 'multiOptions',
		required: true,
		options: ENTITY_OPTIONS,
		default: [],
		description:
			'The kinds of personal data to detect. Selecting every type is the same as All Types.',
		displayOptions: { show: { operation: ['protect'], detect: ['selected'] } },
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
					'Pseudonymise with a random suffix, e.g. [PERSON_a7k2q]. Revealable with the placeholder map, and maps from separate runs do not collide.',
			},
			{
				name: 'Sequential',
				value: 'sequential',
				description:
					'Pseudonymise with a running number, e.g. [PERSON_1]. Revealable with the placeholder map.',
			},
			{
				name: 'Type Only',
				value: 'typed',
				description:
					'Mask with the type only, e.g. [PERSON]. Nothing is kept, so the text cannot be revealed.',
			},
			{
				name: 'Redacted',
				value: 'redacted',
				description:
					'Mask everything as [REDACTED]. Nothing is kept, so the text cannot be revealed.',
			},
		],
		default: 'random',
		description:
			'How detected values are replaced. Random and Sequential pseudonymise (you can reveal them later); Type Only and Redacted mask (permanent).',
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
				displayName: 'Existing Placeholder Map',
				name: 'existingPlaceholderMap',
				type: 'json',
				default: '{}',
				description:
					'Continue an earlier map: values it already holds keep their placeholders, new placeholders never collide with it, and sequential numbering carries on. Accepts the same formats as Reveal, including an ID file from the browser extension.',
			},
			{
				displayName: 'Include ID File',
				name: 'includeIdFile',
				type: 'boolean',
				default: false,
				description:
					'Whether to add an idFile field that the Anonymizator browser extension can open with Load IDs. To save it, use Convert to File → Convert to Text File with Text Input Field set to idFile (Convert to JSON wraps it in the item, and the extension refuses that file). Only for Random and Sequential styles, and only when the map is not empty.',
			},
			{
				displayName: 'Include Input Fields',
				name: 'includeInputFields',
				type: 'boolean',
				default: false,
				description: 'Whether to copy the fields of the input item into the output item',
			},
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

/**
 * Running state for one execution when maps are shared across items. Created once by the execute
 * loop with `createProtectRunState()` and passed to every Protect item.
 */
export type ProtectRunState = {
	/** Running bare-key table (existing + minted so far). */
	table: PlaceholderTable;
	/** Every key used so far, tombstones included; minting avoids all of them. */
	used: Set<string>;
	/** Keys the user added by hand in an extension ID file (`addedByYou: true`). */
	mine: Set<string>;
};

export function createProtectRunState(): ProtectRunState {
	return { table: {}, used: new Set<string>(), mine: new Set<string>() };
}

const NUMBERINGS: readonly Numbering[] = ['random', 'sequential', 'typed', 'redacted'];

function hasOwn(object: object, key: string): boolean {
	return Object.prototype.hasOwnProperty.call(object, key);
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

/** User-facing wording for each gateway failure. */
const GATEWAY_MESSAGES: Record<string, { message: string; description: string }> = {
	auth_required: {
		message: 'The Anonymizator API key was rejected',
		description:
			'Check the API key in the Anonymizator API credential. The gateway did not accept it (it answered with a login redirect or 401).',
	},
	no_access: {
		message: 'This API key has no access to Anonymizator',
		description:
			'The key is valid but is missing the Anonymizator role. Ask whoever issued the key to grant access.',
	},
	hpke_stale: {
		message: "The gateway refused the request because the n8n host's clock is off",
		description:
			'Requests carry a timestamp and the gateway only accepts recent ones. Synchronise the clock of the machine running n8n (for example with NTP) and try again.',
	},
	hpke_unverified_keyconfig: {
		message: "The gateway's encryption key could not be verified, so nothing was sent",
		description:
			"The key configuration's signature does not match the pinned Anonymizator trust root. This can mean the connection is being intercepted (for example by a TLS-inspecting proxy). The text was not sent.",
	},
	hpke_bad_keyconfig: {
		message: "The gateway's encryption key configuration is invalid, so nothing was sent",
		description:
			'The key configuration is missing, malformed or uses an unsupported cipher suite. The text was not sent. Try again later.',
	},
	hpke_seal_failed: {
		message: 'The text could not be encrypted for the gateway, so nothing was sent',
		description: 'The text could not be encrypted on this n8n host, so it was not sent.',
	},
	hpke_bad_response: {
		message: "The gateway's response could not be decrypted",
		description: 'The response was not a valid encrypted reply. Try again later.',
	},
	hpke_required: {
		message: 'The gateway refused the request format',
		description:
			'The gateway expected an encrypted request. Update the node to the latest version.',
	},
	hpke_open_failed: {
		message: 'The gateway could not decrypt the request',
		description: 'Try again. If this keeps happening, update the node to the latest version.',
	},
	hpke_unknown_key: {
		message: 'The gateway does not recognise its own encryption key',
		description:
			'The gateway rotated its key and still rejected the request after the new key was fetched. Try again in a minute.',
	},
	invalid_entities: {
		message: 'The gateway refused the selected entity types',
		description: 'Choose All Types under Detect, or a smaller selection, and try again.',
	},
	text_too_large: {
		message: 'The text is too large for the gateway',
		description:
			'Split the text into smaller items (under about 100,000 characters each) and protect them one by one.',
	},
	rate_limited: {
		message: 'Too many requests to the Anonymizator gateway',
		description:
			'Wait a moment and try again. Enable Retry On Fail with a wait between tries, or send fewer items at once.',
	},
	server_error: {
		message: 'The Anonymizator gateway is temporarily unavailable',
		description: 'The gateway answered with HTTP 5xx twice in a row. Try again later.',
	},
	timeout: {
		message: 'The Anonymizator gateway did not answer in time',
		description: 'Try again. Very long texts take longer; consider splitting them.',
	},
	offline: {
		message: 'Could not reach the Anonymizator gateway',
		description:
			'Check that the n8n host can reach https://anon.prosecco37.com (network, DNS, proxy or firewall).',
	},
};

/**
 * Failures decided on the n8n side, even when a response was received (an unverifiable keyconfig
 * arrives with HTTP 200). They are reported as NodeOperationError, not as an API error.
 */
const LOCAL_FAILURES: ReadonlySet<string> = new Set([
	'hpke_unverified_keyconfig',
	'hpke_bad_keyconfig',
	'hpke_seal_failed',
	'hpke_bad_response',
	'timeout',
	'offline',
]);

/**
 * Turns a failure from `gateway.analyze` into the n8n error to throw. Failures with an HTTP status
 * become NodeApiError, the rest (keyconfig verification, offline, timeout) NodeOperationError.
 */
export function gatewayFailure(
	ctx: IExecuteFunctions,
	error: unknown,
	itemIndex: number,
): NodeApiError | NodeOperationError {
	const node = errorNode(ctx);
	if (error instanceof NodeApiError || error instanceof NodeOperationError) return error;

	if (error instanceof GatewayError) {
		const known = GATEWAY_MESSAGES[error.code];
		const message =
			known?.message ??
			`The Anonymizator gateway answered with an unexpected status${error.httpCode ? ` (HTTP ${error.httpCode})` : ''}`;
		const parts = [known?.description ?? error.message];
		if (error.detail) parts.push(`Gateway detail: ${error.detail}`);
		parts.push(`(code: ${error.code})`);
		const description = parts.join(' ');

		if (typeof error.httpCode === 'number' && !LOCAL_FAILURES.has(error.code)) {
			return new NodeApiError(
				node,
				{ message: error.message, code: error.code, httpCode: String(error.httpCode) },
				{ message, description, httpCode: String(error.httpCode), itemIndex },
			);
		}
		return new NodeOperationError(node, message, { itemIndex, description });
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

/** Adds `parsed` to `state`, refusing a key that already maps to a different value. */
function seedState(
	ctx: IExecuteFunctions,
	state: ProtectRunState,
	parsed: ParsedPlaceholderMap,
	itemIndex: number,
): void {
	for (const [key, value] of Object.entries(parsed.table)) {
		if (hasOwn(state.table, key) && state.table[key] !== value) {
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
	for (const [key, value] of Object.entries(parsed.table)) {
		if (!hasOwn(state.table, key)) state.table[key] = value;
	}
	for (const key of parsed.used) state.used.add(key);
	for (const key of Object.keys(parsed.table)) state.used.add(key);
	for (const key of parsed.mine) state.mine.add(key);
}

function toOutputEntities(entities: LocalEntity[]): OutputEntity[] {
	return entities.map((entity) => ({
		entityType: entity.entity_type,
		placeholder: entity.replacement,
		start: entity.start,
		end: entity.end,
		score: entity.score,
	}));
}

export async function executeProtect(
	this: IExecuteFunctions,
	itemIndex: number,
	runState: ProtectRunState,
): Promise<INodeExecutionData[]> {
	const text = readTextParameter(this, itemIndex, 'Text');

	const detect = this.getNodeParameter('detect', itemIndex, 'all') as string;
	const entityTypes =
		detect === 'selected'
			? selectionToEntityTypes(this.getNodeParameter('entityTypes', itemIndex, []) as string[])
			: undefined;

	const style = this.getNodeParameter('placeholderStyle', itemIndex, 'random') as Numbering;
	if (!NUMBERINGS.includes(style)) {
		throw new NodeOperationError(errorNode(this), `Unknown placeholder style "${String(style)}"`, {
			itemIndex,
			description: 'Use one of: random, sequential, typed, redacted.',
		});
	}

	const options = this.getNodeParameter('options', itemIndex, {}) as IDataObject;
	const existing = parseMapParameter(
		this,
		options.existingPlaceholderMap,
		itemIndex,
		'Existing Placeholder Map',
	);
	const state = options.shareMapAcrossItems === true ? runState : createProtectRunState();
	seedState(this, state, existing, itemIndex);

	// Only detection happens remotely. Blank text has nothing to detect, so it never leaves n8n.
	let spans: Span[] = [];
	let entityFilterIgnored = false;
	if (text.trim() !== '') {
		try {
			({ spans, entityFilterIgnored } = await analyze(this, text, entityTypes));
		} catch (error) {
			throw gatewayFailure(this, error, itemIndex);
		}
	}

	// Tombstones (keys used before but no longer in the table) are passed as empty values so new
	// placeholders never reuse them; empty values are never matched in the text.
	const working: PlaceholderTable = { ...state.table };
	for (const key of state.used) {
		if (!hasOwn(working, key)) working[key] = '';
	}

	const local = anonymizeFromSpans(text, spans, working, {
		sequential: style === 'sequential',
	});

	let live: PlaceholderTable = {};
	const result: ProtectResult = {
		protectedText: local.text,
		placeholderMap: {},
		entities: [],
	};

	if (style === 'typed' || style === 'redacted') {
		const masked = mask(local, style);
		result.protectedText = masked.text;
		result.entities = toOutputEntities(masked.entities);
	} else {
		for (const [key, value] of Object.entries(local.newEntries)) {
			state.table[key] = value;
			state.used.add(key);
		}
		live = { ...state.table };
		// Retired placeholders (tombstones) are written back as empty values, the format's way of
		// saying "never reuse", so a map passed back in as Existing Placeholder Map keeps them retired.
		const output: PlaceholderTable = { ...live };
		for (const key of state.used) {
			if (!hasOwn(output, key)) output[key] = '';
		}
		result.placeholderMap = output;
		result.entities = toOutputEntities(local.entities);
	}

	if (entityFilterIgnored) result.entityFilterIgnored = true;

	if (
		options.includeIdFile === true &&
		(style === 'random' || style === 'sequential') &&
		Object.keys(live).length > 0
	) {
		try {
			result.idFile = toIdFile(live, style, undefined, {
				mine: [...state.mine],
				used: [...state.used],
			});
		} catch (error) {
			// The extension's Load IDs would refuse such a file (e.g. two placeholders for one value
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
			? { ...(this.getInputData()[itemIndex]?.json ?? {}), ...result }
			: { ...result };

	return [{ json, pairedItem: { item: itemIndex } }];
}
