/**
 * Detect: run the same gateway analysis as Protect and report what was found, without changing the
 * text. Meant for routing (for example an IF node before an LLM call).
 *
 * Only the gateway's findings are reported: there is no placeholder map, so values that only an
 * existing map would have matched are not listed, and Additionally Protect does not apply. The
 * gateway's spans go through the steps Protect applies to them: companies by legal form first, then
 * Ignore Terms (a detection whose whole text equals a term is dropped, possible IDs too), then edge
 * trimming and the overlap rule. A type outside the gateway's TYPE grammar is reported as PII, the
 * type Protect would protect it as.
 */
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
} from 'n8n-workflow';

import { pgwEntityType } from '../shared/anonymizer';
import { filterIgnoredSpans, parseIgnoreTerms } from '../shared/ignoreTerms';
import { companySpans, emptyState } from '../shared/protectPipeline';
import type { DetectEntity, DetectPossibleId, DetectResult, Span } from '../shared/types';
import {
	detectRemotely,
	IGNORE_TERMS_OPTION,
	includePossibleIdsOption,
	readTextParameter,
	withoutFields,
} from './protect';

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
			includePossibleIdsOption(
				"Whether to add possibleIds: text the gateway flags for review without counting it as personal data (for example an organisation name), when the gateway offers that. Possible IDs are a prompt to look, not a score: they are not in entities, entityCount or countsByType, and text that is not listed can still hold personal data. Each has a value only with 'Include Values'.",
			),
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
 * Output fields Detect writes only in some runs. Include Input Fields must not carry them over from
 * the input item, where they would describe another text.
 */
const DETECT_FIELDS = ['entityFilterIgnored', 'possibleIds', 'possibleIdsTruncated'];

/** A span without leading and trailing whitespace; possibly empty. */
function trimSpan<T extends { start: number; end: number }>(text: string, span: T): T {
	let start = span.start;
	let end = span.end;
	while (start < end && /\s/.test(text[start])) start++;
	while (end > start && /\s/.test(text[end - 1])) end--;
	return { ...span, start, end };
}

/**
 * Keeps the spans Protect would substitute, as `anonymizeFromSpans` does: sorted by start, then
 * longest first; a span that overlaps the previous kept one, is empty or runs past the text is
 * skipped; edges are trimmed of whitespace (a span that is only whitespace is skipped).
 */
export function nonOverlappingSpans(text: string, spans: Span[]): Span[] {
	const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
	const kept: Span[] = [];
	let cursor = 0;
	for (const span of sorted) {
		if (!(span.start >= cursor && span.end > span.start && span.end <= text.length)) continue;
		const trimmed = trimSpan(text, span);
		if (trimmed.start >= trimmed.end) continue;
		kept.push(trimmed);
		cursor = trimmed.end;
	}
	return kept;
}

export async function executeDetect(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const text = readTextParameter(this, itemIndex, 'Text');
	const options = this.getNodeParameter('options', itemIndex, {}) as IDataObject;
	const ignoreTerms = parseIgnoreTerms(options.ignoreTerms);
	const includeValues = options.includeValues === true;
	const includePossible = options.includePossibleIds === true;

	// Blank text has nothing to detect, so it never leaves n8n.
	const found = await detectRemotely(this, itemIndex, text, includePossible);
	// Companies first, as in Protect: an ignored "Modra" never hides "Modra d.o.o.".
	const companies = companySpans(emptyState('random'), text, found.spans);
	const spans = nonOverlappingSpans(text, filterIgnoredSpans(text, companies, ignoreTerms));

	const countsByType: Record<string, number> = {};
	const entities: DetectEntity[] = spans.map((span) => {
		const entityType = pgwEntityType(span.entity_type);
		countsByType[entityType] = (countsByType[entityType] ?? 0) + 1;
		const entity: DetectEntity = {
			entityType,
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
	if (found.entityFilterIgnored) result.entityFilterIgnored = true;
	if (includePossible) {
		const possible = filterIgnoredSpans(
			text,
			found.possible.map((p) => trimSpan(text, p)).filter((p) => p.start < p.end),
			ignoreTerms,
		).sort((a, b) => a.start - b.start || b.end - a.end);
		result.possibleIds = possible.map((p) => {
			const entry: DetectPossibleId = {
				entityType: pgwEntityType(p.entity_type),
				start: p.start,
				end: p.end,
			};
			if (includeValues) entry.value = text.slice(p.start, p.end);
			return entry;
		});
	}

	const json: IDataObject =
		options.includeInputFields === true
			? { ...withoutFields(this.getInputData()[itemIndex]?.json, DETECT_FIELDS), ...result }
			: { ...result };

	return [{ json, pairedItem: { item: itemIndex } }];
}
