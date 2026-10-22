/**
 * Entity-type selection: the bundled catalog, the merge with the gateway's verified capabilities
 * document, and the `entities` filter sent in the sealed payload. A port of the extension's
 * `lib/entities.js` (`ANON_ENTITY_CATALOG`, `ANON_BUNDLED_ENTITY_GROUPS`, `anonMergeCatalog`,
 * `anonEntityFilter`), with the labels and groups the extension shows.
 *
 * The capabilities document can only ADD: bundled rows always stay, in order, and always send their
 * own types when selected (never intersected with the document); a server type no bundled row lists
 * becomes a server-only row after them. `possible` types never become rows. Labels and groups only
 * fill gaps.
 *
 * Filter semantics (as the extension): the selection is the set of enabled row ids. Nothing
 * selected, or every row selected, omits the `entities` field, so the gateway detects everything it
 * is configured with (fail open to complete protection, never to none). Otherwise the field is the
 * sorted, unique list of the selected bundled rows' types plus the selected server-only ids.
 *
 * Not ported (no n8n equivalent): the stored deviations in chrome.storage, the seen-on set, the
 * `opt_in` default (a selection in n8n is explicit) and the side panel view.
 */
import type { INodePropertyOptions } from 'n8n-workflow';

import type { VerifiedCapabilities } from './capabilities';

/** TYPE grammar: the gateway's entity names, and the ids a selection may hold. */
export const ENTITY_TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export type EntityGroupKind = 'category' | 'country';

/** One bundled group, in display order. */
export type EntityGroup = { id: string; kind: EntityGroupKind; label: string };

/** One bundled row: a user-facing toggle and the server types it maps to. */
export type EntityCatalogRow = {
	/** Stable toggle id, used as the multiOptions value (saved in workflows). */
	id: string;
	/** The extension's English label. */
	label: string;
	/** Server entity types sent in the `entities` filter. */
	types: string[];
	/** Group ids (ENTITY_GROUPS). */
	groups: string[];
};

/** Bundled groups, in display order (the same ids as the gateway's defaults). */
export const ENTITY_GROUPS: readonly EntityGroup[] = [
	{ id: 'general', kind: 'category', label: 'General' },
	{ id: 'finance', kind: 'category', label: 'Finance' },
	{ id: 'tech', kind: 'category', label: 'Technical' },
	{ id: 'si', kind: 'country', label: 'Slovenia' },
	{ id: 'hr', kind: 'country', label: 'Croatia' },
	{ id: 'at', kind: 'country', label: 'Austria' },
	{ id: 'us', kind: 'country', label: 'United States' },
];

/** The extension's 16 toggles, in its order, with its labels and groups. */
export const ENTITY_CATALOG: readonly EntityCatalogRow[] = [
	{ id: 'PERSON', label: 'Names', types: ['PERSON'], groups: ['general'] },
	{ id: 'EMAIL_ADDRESS', label: 'Email addresses', types: ['EMAIL_ADDRESS'], groups: ['general'] },
	{ id: 'PHONE_NUMBER', label: 'Phone numbers', types: ['PHONE_NUMBER'], groups: ['general'] },
	{ id: 'CREDIT_CARD', label: 'Credit cards', types: ['CREDIT_CARD'], groups: ['finance'] },
	{ id: 'IBAN', label: 'Bank accounts (IBAN)', types: ['IBAN', 'IBAN_CODE'], groups: ['finance'] },
	{ id: 'US_SSN', label: 'US SSN', types: ['US_SSN'], groups: ['us'] },
	{ id: 'API_KEY', label: 'API keys', types: ['API_KEY'], groups: ['tech'] },
	{ id: 'URL', label: 'URLs', types: ['URL'], groups: ['tech'] },
	{ id: 'EMSO', label: 'EMŠO (personal ID)', types: ['EMSO'], groups: ['si'] },
	{ id: 'SI_TAX_ID', label: 'Tax number (davčna)', types: ['SI_TAX_ID'], groups: ['si'] },
	{ id: 'OIB', label: 'OIB (HR personal ID)', types: ['OIB'], groups: ['hr'] },
	{ id: 'AT_SVN', label: 'AT SVN (insurance no.)', types: ['AT_SVN'], groups: ['at'] },
	{ id: 'ZZZS', label: 'ZZZS (health insurance no.)', types: ['ZZZS'], groups: ['si'] },
	{ id: 'BIRTH_DATE', label: 'Birth dates', types: ['BIRTH_DATE'], groups: ['general'] },
	{ id: 'LOCATION', label: 'Places / locations', types: ['LOCATION'], groups: ['general'] },
	{ id: 'IP_ADDRESS', label: 'IP addresses', types: ['IP_ADDRESS'], groups: ['tech'] },
];

/** One group of the merged catalog; labels by language (only ever from Maps). */
export type MergedGroup = { id: string; kind: EntityGroupKind; labels: Map<string, string> };

/** One row of the merged catalog. */
export type MergedRow = {
	id: string;
	types: string[];
	groups: string[];
	serverOnly: boolean;
	labels: Map<string, string>;
};

export type MergedCatalog = {
	source: 'server' | 'bundled';
	groups: MergedGroup[];
	rows: MergedRow[];
	/** Every type a bundled row lists (the bundled row ids among them). */
	bundledTypes: Set<string>;
};

export function isEntityType(value: unknown): value is string {
	return typeof value === 'string' && ENTITY_TYPE_RE.test(value);
}

function labelMap(
	source: Map<string, Map<string, string>> | null | undefined,
	ref: string,
): Map<string, string> | null {
	const labels = source instanceof Map ? source.get(ref) : undefined;
	return labels instanceof Map ? labels : null;
}

function fillLabels(target: Map<string, string>, labels: Map<string, string> | null): void {
	if (!labels) return;
	for (const [lang, text] of labels) {
		if (typeof lang === 'string' && typeof text === 'string' && !target.has(lang)) {
			target.set(lang, text);
		}
	}
}

/**
 * The bundled catalog merged with a verified capabilities document (`anonMergeCatalog`), or the
 * bundled catalog alone for null. A type covered by a bundled row only extends that row's groups;
 * an uncovered type becomes a server-only row after the bundled ones, ordered by first group, then
 * id.
 */
export function mergeCatalog(caps: VerifiedCapabilities | null | undefined): MergedCatalog {
	const doc = caps && typeof caps === 'object' && Array.isArray(caps.entities) ? caps : null;
	const capLabels = doc ? doc.labels : null;

	const groups: MergedGroup[] = ENTITY_GROUPS.map((g) => ({
		id: g.id,
		kind: g.kind,
		labels: new Map([['en', g.label]]),
	}));
	const groupById = new Map(groups.map((g) => [g.id, g]));
	for (const g of doc && Array.isArray(doc.groups) ? doc.groups : []) {
		if (!g || typeof g.id !== 'string' || groupById.has(g.id)) continue;
		const added: MergedGroup = {
			id: g.id,
			kind: g.kind === 'country' ? 'country' : 'category',
			labels: new Map(),
		};
		groups.push(added);
		groupById.set(g.id, added);
	}
	for (const g of groups) fillLabels(g.labels, labelMap(capLabels, `group:${g.id}`));

	const rows: MergedRow[] = ENTITY_CATALOG.map((item) => ({
		id: item.id,
		types: item.types.slice(),
		groups: item.groups.slice(),
		serverOnly: false,
		labels: new Map([['en', item.label]]),
	}));
	const bundledTypes = new Set(rows.flatMap((row) => row.types));
	const rowByType = new Map<string, MergedRow>();
	for (const row of rows) for (const type of row.types) rowByType.set(type, row);

	const serverRows: MergedRow[] = [];
	for (const entity of doc ? doc.entities : []) {
		if (!entity || !isEntityType(entity.type)) continue;
		const entityGroups = (Array.isArray(entity.groups) ? entity.groups : []).filter((g) =>
			groupById.has(g),
		);
		const covering = rowByType.get(entity.type);
		if (covering) {
			for (const g of entityGroups) if (!covering.groups.includes(g)) covering.groups.push(g);
			continue;
		}
		if (serverRows.some((row) => row.id === entity.type)) continue;
		serverRows.push({
			id: entity.type,
			types: [entity.type],
			groups: entityGroups,
			serverOnly: true,
			labels: new Map(),
		});
	}
	const groupOrder = new Map(groups.map((g, i) => [g.id, i]));
	const firstGroup = (row: MergedRow): number =>
		Math.min(...row.groups.map((g) => groupOrder.get(g) ?? groups.length), groups.length);
	serverRows.sort(
		(a, b) => firstGroup(a) - firstGroup(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
	);

	const all = rows.concat(serverRows);
	for (const row of all) fillLabels(row.labels, labelMap(capLabels, `type:${row.id}`));
	return { source: doc ? 'server' : 'bundled', groups, rows: all, bundledTypes };
}

/** The English label of a row or group, falling back to its id. */
function en(labels: Map<string, string>, fallback: string): string {
	return labels.get('en') || fallback;
}

/**
 * The merged catalog as node options, sorted by name: name = the English label (the type id when
 * the server sends none), value = the row id, description = its group labels and server types.
 */
export function entityOptions(merged: MergedCatalog): INodePropertyOptions[] {
	const groupLabel = new Map(merged.groups.map((g) => [g.id, en(g.labels, g.id)]));
	return merged.rows
		.map((row) => {
			const groups = row.groups.map((g) => groupLabel.get(g) ?? g).join(', ');
			const plural = row.types.length > 1 ? 'types' : 'type';
			const types = `Server ${plural}: ${row.types.join(', ')}.`;
			return {
				name: en(row.labels, row.id),
				value: row.id,
				description: groups ? `${groups}. ${types}` : types,
			};
		})
		.sort((a, b) => a.name.localeCompare(b.name, 'en'));
}

/** The bundled catalog as node options (what the list shows without a verified document). */
export const ENTITY_OPTIONS: INodePropertyOptions[] = entityOptions(mergeCatalog(null));

/**
 * The `entities` field for the sealed payload, or undefined to OMIT it (complete detection):
 * nothing selected (fail open), or every bundled row selected, whatever server-only rows the
 * document adds and whichever of them are selected. A saved "every built-in type" selection thus
 * keeps meaning All Types, with or without a verified document (the server only ADDS). n8n stores
 * no explicit off for server-only rows, so this departs from `anonEntityFilter` there. Otherwise
 * exactly what is selected: the sorted, unique types of the selected bundled rows plus the
 * selected server-only ids. A selected id that is TYPE-shaped but unknown to the merged catalog
 * (a server type seen earlier, or one given by expression) is sent too: if the gateway does not
 * know it, its `invalid_entities` answer makes `analyze` retry with every type. Ids that are not
 * TYPE-shaped, and ids naming a type a bundled row covers without being its id (IBAN_CODE), are
 * ignored.
 */
export function entityFilter(
	merged: MergedCatalog,
	selection: readonly unknown[] | null | undefined,
): string[] | undefined {
	const selected = new Set((Array.isArray(selection) ? selection : []).filter(isEntityType));
	const bundled = merged.rows.filter((row) => !row.serverOnly);
	const bundledOn = bundled.filter((row) => selected.has(row.id));
	if (bundledOn.length === bundled.length) return undefined; // every built-in type: All Types
	const otherOn = [...selected].filter((id) => !merged.bundledTypes.has(id));
	if (bundledOn.length === 0 && otherOn.length === 0) return undefined; // never zero: fail open
	return [...new Set([...bundledOn.flatMap((row) => row.types), ...otherOn])].sort();
}

/** `entityFilter` over the bundled catalog alone. */
export function selectionToEntityTypes(ids: readonly unknown[] | undefined): string[] | undefined {
	return entityFilter(mergeCatalog(null), ids);
}
