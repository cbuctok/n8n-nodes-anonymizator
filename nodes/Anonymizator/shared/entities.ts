/**
 * Entity catalog: the 16 detection toggles of the extension's `lib/entities.js`, with English
 * labels. One toggle may map to several server types (IBAN -> IBAN, IBAN_CODE).
 *
 * Filter semantics (mirrors the extension): selecting all or none means "all types", which omits
 * the `entities` field so the server default stays authoritative (fail open to full protection).
 */
import type { INodePropertyOptions } from 'n8n-workflow';

export type EntityCatalogRow = {
	/** Stable toggle id, used as the multiOptions value. */
	id: string;
	/** English label shown in the node UI. */
	label: string;
	/** Short English description for the UI; ends with the server types it maps to. */
	description: string;
	/** Server entity types sent in the `entities` filter, in order. */
	types: string[];
};

function row(id: string, label: string, what: string, types: string[]): EntityCatalogRow {
	const plural = types.length > 1 ? 'types' : 'type';
	return { id, label, description: `${what} Server ${plural}: ${types.join(', ')}.`, types };
}

/** Catalog in the extension's order. */
export const ENTITY_CATALOG: readonly EntityCatalogRow[] = [
	row('PERSON', 'Person Names', 'Names of people; also creates _NAME and _SURNAME placeholders.', [
		'PERSON',
	]),
	row('EMAIL_ADDRESS', 'Email Addresses', 'Email addresses.', ['EMAIL_ADDRESS']),
	row('PHONE_NUMBER', 'Phone Numbers', 'Phone numbers.', ['PHONE_NUMBER']),
	row('CREDIT_CARD', 'Credit Card Numbers', 'Payment card numbers.', ['CREDIT_CARD']),
	row('IBAN', 'Bank Accounts (IBAN)', 'International bank account numbers.', ['IBAN', 'IBAN_CODE']),
	row('US_SSN', 'US Social Security Numbers', 'US Social Security numbers.', ['US_SSN']),
	row('API_KEY', 'API Keys', 'API keys and similar access strings.', ['API_KEY']),
	row('URL', 'URLs', 'Web addresses.', ['URL']),
	row('EMSO', 'Slovenian Personal ID (EMSO)', 'Slovenian unique master citizen number (EMŠO).', [
		'EMSO',
	]),
	row('SI_TAX_ID', 'Slovenian Tax Number', 'Slovenian tax number (davčna številka).', [
		'SI_TAX_ID',
	]),
	row('OIB', 'Croatian Personal ID (OIB)', 'Croatian personal identification number.', ['OIB']),
	row('AT_SVN', 'Austrian Social Insurance Number', 'Austrian social insurance number (SVNr).', [
		'AT_SVN',
	]),
	row(
		'ZZZS',
		'Slovenian Health Insurance Number (ZZZS)',
		'Slovenian health insurance card number.',
		['ZZZS'],
	),
	row('BIRTH_DATE', 'Birth Dates', 'Dates of birth.', ['BIRTH_DATE']),
	row('LOCATION', 'Locations', 'Places, addresses and other locations.', ['LOCATION']),
	row('IP_ADDRESS', 'IP Addresses', 'IPv4 and IPv6 addresses.', ['IP_ADDRESS']),
];

/** The catalog as node options, sorted alphabetically by label (n8n lint convention). */
export const ENTITY_OPTIONS: INodePropertyOptions[] = ENTITY_CATALOG.map((r) => ({
	name: r.label,
	value: r.id,
	description: r.description,
})).sort((a, b) => a.name.localeCompare(b.name, 'en'));

/**
 * Maps selected catalog ids to the server types to send, in catalog order. Returns undefined
 * (= omit the field, detect everything) when nothing or every catalog row is selected. Unknown ids
 * are ignored.
 */
export function selectionToEntityTypes(ids: readonly string[] | undefined): string[] | undefined {
	const selected = new Set(ids ?? []);
	const enabled = ENTITY_CATALOG.filter((r) => selected.has(r.id));
	if (enabled.length === 0 || enabled.length === ENTITY_CATALOG.length) return undefined;
	const types: string[] = [];
	for (const r of enabled) types.push(...r.types);
	return types;
}
