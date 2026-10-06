/**
 * Detect: run the same gateway analysis as Protect and report what was found, without changing the
 * text. Meant for routing (for example an IF node before an LLM call).
 *
 * Only the gateway's findings are reported: there is no placeholder map, so values that only an
 * existing map would have matched are not listed. Ignore Terms applies as in Protect.
 */
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
} from 'n8n-workflow';

import { analyze } from '../shared/gateway';
import { filterIgnoredSpans, parseIgnoreTerms } from '../shared/ignoreTerms';
import type { DetectEntity, DetectResult, Span } from '../shared/types';
import { gatewayFailure, IGNORE_TERMS_OPTION, readEntityTypes, readTextParameter } from './protect';

const showForDetect = { show: { operation: ['detect'] } };

export const detectDescription: INodeProperties[] = [
	{
		displayName: 'Text',
		name: 'text',
		type: 'string',
		required: true,
		default: '',
		typeOptions: { rows: 4 },
		placeholder: 'e.g. Janez Novak (ana.kovac@example.com) asked about his invoice',
		description: 'The text to check for personal data. It is not changed.',
		displayOptions: showForDetect,
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: showForDetect,
		options: [
			IGNORE_TERMS_OPTION,
			{
				displayName: 'Include Input Fields',
				name: 'includeInputFields',
				type: 'boolean',
				default: false,
				description: 'Whether to copy the fields of the input item into the output item',
			},
			{
				displayName: 'Include Values',
				name: 'includeValues',
				type: 'boolean',
				default: false,
				description:
					'Whether to add the matched text to each entity as value. These values are the personal data itself: leave this off when the output goes to an LLM, an AI agent or a log.',
			},
		],
	},
];

/**
 * Keeps the spans Protect would substitute: sorted by start, then longest first; a span that
 * overlaps an earlier one, is empty or runs past the text is skipped.
 */
export function nonOverlappingSpans(spans: Span[], textLength: number): Span[] {
	const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
	const kept: Span[] = [];
	let cursor = 0;
	for (const span of sorted) {
		if (!(span.start >= cursor && span.end > span.start && span.end <= textLength)) continue;
		kept.push(span);
		cursor = span.end;
	}
	return kept;
}

export async function executeDetect(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const text = readTextParameter(this, itemIndex, 'Text');
	const entityTypes = readEntityTypes(this, itemIndex);
	const options = this.getNodeParameter('options', itemIndex, {}) as IDataObject;
	const ignoreTerms = parseIgnoreTerms(options.ignoreTerms);
	const includeValues = options.includeValues === true;

	// Blank text has nothing to detect, so it never leaves n8n.
	let spans: Span[] = [];
	let entityFilterIgnored = false;
	if (text.trim() !== '') {
		try {
			({ spans, entityFilterIgnored } = await analyze(this, text, entityTypes));
		} catch (error) {
			throw gatewayFailure(this, error, itemIndex);
		}
	}
	spans = nonOverlappingSpans(filterIgnoredSpans(text, spans, ignoreTerms), text.length);

	const countsByType: Record<string, number> = {};
	const entities: DetectEntity[] = spans.map((span) => {
		countsByType[span.entity_type] = (countsByType[span.entity_type] ?? 0) + 1;
		const entity: DetectEntity = {
			entityType: span.entity_type,
			start: span.start,
			end: span.end,
			// Rounded like Protect's entities.
			score: typeof span.score === 'number' ? Math.round(span.score * 100) / 100 : 0,
		};
		if (includeValues) entity.value = text.slice(span.start, span.end);
		return entity;
	});

	const result: DetectResult = {
		hasPersonalData: entities.length > 0,
		entityCount: entities.length,
		countsByType,
		entities,
	};
	if (entityFilterIgnored) result.entityFilterIgnored = true;

	const json: IDataObject =
		options.includeInputFields === true
			? { ...(this.getInputData()[itemIndex]?.json ?? {}), ...result }
			: { ...result };

	return [{ json, pairedItem: { item: itemIndex } }];
}
