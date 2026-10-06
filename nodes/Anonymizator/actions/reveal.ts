/**
 * Reveal: put the original values back using a placeholder map. Local only: never touches the
 * network or the credential.
 */
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
} from 'n8n-workflow';

import { revealText } from '../shared/anonymizer';
import type { PlaceholderTable, RevealResult } from '../shared/types';
import { parseMapParameter, readTextParameter } from './protect';

const showForReveal = { show: { operation: ['reveal'] } };

/** A bracketed placeholder token as the node and the extension write them. */
const PLACEHOLDER_TOKEN_RE = /\[([A-Z][A-Za-z0-9_]*)\]/g;

export const revealDescription: INodeProperties[] = [
	{
		displayName: 'Text',
		name: 'text',
		type: 'string',
		required: true,
		default: '',
		typeOptions: { rows: 4 },
		placeholder: 'e.g. Dear [PERSON_a7k2q], your invoice is ready',
		description: 'The text containing placeholders to reveal',
		displayOptions: showForReveal,
	},
	{
		displayName: 'Placeholder Map',
		name: 'placeholderMap',
		type: 'json',
		required: true,
		default: '{}',
		placeholder: 'e.g. {{ $("Anonymizator").item.json.placeholderMap }}',
		description:
			'The map that Protect produced. Accepts a JSON object of placeholders to values (bare or [bracketed] keys), an array of {placeholder, value} objects, or an ID file saved by the Anonymizator browser extension.',
		hint: 'Reveal runs entirely inside n8n: nothing is sent to the gateway',
		displayOptions: showForReveal,
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: showForReveal,
		options: [
			{
				displayName: 'Include Input Fields',
				name: 'includeInputFields',
				type: 'boolean',
				default: false,
				description: 'Whether to copy the fields of the input item into the output item',
			},
		],
	},
];

/**
 * Bracketed tokens in `text` that `table` cannot resolve, in order of first appearance. Masked
 * placeholders such as [PERSON] or [REDACTED] are listed too: they were never revealable.
 */
export function findUnresolvedPlaceholders(text: string, table: PlaceholderTable): string[] {
	const unresolved: string[] = [];
	for (const match of text.matchAll(PLACEHOLDER_TOKEN_RE)) {
		const token = match[0];
		if (Object.prototype.hasOwnProperty.call(table, match[1])) continue;
		if (!unresolved.includes(token)) unresolved.push(token);
	}
	return unresolved;
}

export async function executeReveal(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const text = readTextParameter(this, itemIndex, 'Text');
	const { table } = parseMapParameter(
		this,
		this.getNodeParameter('placeholderMap', itemIndex, '{}'),
		itemIndex,
		'Placeholder Map',
	);
	const options = this.getNodeParameter('options', itemIndex, {}) as IDataObject;

	const result: RevealResult = {
		revealedText: revealText(text, table),
		// Computed on the input so a revealed value that happens to contain brackets is not listed.
		unresolvedPlaceholders: findUnresolvedPlaceholders(text, table),
	};

	const json: IDataObject =
		options.includeInputFields === true
			? { ...(this.getInputData()[itemIndex]?.json ?? {}), ...result }
			: { ...result };

	return [{ json, pairedItem: { item: itemIndex } }];
}
