// Entity catalog, merge and filter (port of the extension's lib/entities.js). Never shipped.
// The differential cases run the extension's real lib/entities.js with node:vm and skip when its
// checkout is missing (ANON_EXT_DIR, else the default paths in helpers/pgw.mjs).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

import { EXT_DIR } from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const {
	ENTITY_CATALOG,
	ENTITY_GROUPS,
	ENTITY_OPTIONS,
	entityFilter,
	entityOptions,
	mergeCatalog,
	selectionToEntityTypes,
} = require('../dist/nodes/Anonymizator/shared/entities.js');

const hasExt = Boolean(EXT_DIR) && existsSync(join(EXT_DIR, 'lib/entities.js'));
const EXT_SKIP = !hasExt && 'extension checkout not found';

const ALL_IDS = ENTITY_CATALOG.map((r) => r.id);

/** A verified-capabilities shape as gateway.fetchCapabilities returns it. */
function caps({ entities = [], groups = [], possible = [], labels = [] } = {}) {
	const map = new Map();
	for (const [ref, lang, text] of labels) {
		if (!map.has(ref)) map.set(ref, new Map());
		map.get(ref).set(lang, text);
	}
	return { entities, groups, possible, labels: map };
}

const SERVER_DOC = caps({
	groups: [
		{ id: 'general', kind: 'category' },
		{ id: 'it', kind: 'country' },
	],
	entities: [
		{ type: 'PERSON', default: 'on', groups: ['general', 'it'] },
		{ type: 'IBAN_CODE', default: 'on', groups: ['finance'] },
		{ type: 'IT_FISCAL_CODE', default: 'on', groups: ['it'] },
		{ type: 'SOCIAL_HANDLE', default: 'opt_in', groups: ['general'] },
		{ type: 'bad type', default: 'on', groups: [] },
	],
	possible: [{ type: 'ORGANIZATION', groups: ['general'] }],
	labels: [
		['type:IT_FISCAL_CODE', 'en', 'Italian fiscal code'],
		['type:PERSON', 'en', 'Server name for persons'],
		['group:it', 'en', 'Italy'],
	],
});

describe('bundled catalog', () => {
	test('16 rows with the extension labels and groups, 7 groups', () => {
		assert.equal(ENTITY_CATALOG.length, 16);
		assert.equal(new Set(ALL_IDS).size, 16);
		assert.equal(ENTITY_GROUPS.length, 7);
		const groups = new Set(ENTITY_GROUPS.map((g) => g.id));
		for (const r of ENTITY_CATALOG) {
			assert.ok(r.types.length >= 1, r.id);
			assert.ok(
				r.groups.every((g) => groups.has(g)),
				r.id,
			);
		}
		assert.equal(ENTITY_CATALOG.find((r) => r.id === 'PERSON').label, 'Names');
		assert.deepEqual(ENTITY_CATALOG.find((r) => r.id === 'IBAN').types, ['IBAN', 'IBAN_CODE']);
	});

	test('ENTITY_OPTIONS: one per row, sorted by name, group and types in the description', () => {
		assert.equal(ENTITY_OPTIONS.length, 16);
		const names = ENTITY_OPTIONS.map((o) => o.name);
		assert.deepEqual(
			names,
			[...names].sort((a, b) => a.localeCompare(b, 'en')),
		);
		assert.deepEqual(new Set(ENTITY_OPTIONS.map((o) => o.value)), new Set(ALL_IDS));
		const iban = ENTITY_OPTIONS.find((o) => o.value === 'IBAN');
		assert.equal(iban.name, 'Bank accounts (IBAN)');
		assert.equal(iban.description, 'Finance. Server types: IBAN, IBAN_CODE.');
		for (const o of ENTITY_OPTIONS) assert.doesNotMatch(o.name, /\p{Extended_Pictographic}/u);
	});
});

describe('mergeCatalog', () => {
	test('null keeps the bundled catalog', () => {
		const merged = mergeCatalog(null);
		assert.equal(merged.source, 'bundled');
		assert.deepEqual(
			merged.rows.map((r) => r.id),
			ALL_IDS,
		);
	});

	test('the document only adds: rows, groups, labels; possible types never become rows', () => {
		const merged = mergeCatalog(SERVER_DOC);
		assert.equal(merged.source, 'server');
		assert.deepEqual(
			merged.rows.map((r) => r.id),
			[...ALL_IDS, 'SOCIAL_HANDLE', 'IT_FISCAL_CODE'],
		);
		const person = merged.rows.find((r) => r.id === 'PERSON');
		assert.deepEqual(person.groups, ['general', 'it']);
		assert.equal(person.labels.get('en'), 'Names', 'bundled labels win');
		assert.deepEqual(merged.rows.find((r) => r.id === 'IBAN').types, ['IBAN', 'IBAN_CODE']);
		const options = entityOptions(merged);
		const fiscal = options.find((o) => o.value === 'IT_FISCAL_CODE');
		assert.equal(fiscal.name, 'Italian fiscal code');
		assert.equal(fiscal.description, 'Italy. Server type: IT_FISCAL_CODE.');
		assert.equal(options.find((o) => o.value === 'SOCIAL_HANDLE').name, 'SOCIAL_HANDLE');
	});
});

describe('entityFilter', () => {
	test('bundled: sorted unique types; all, none and junk omit the field', () => {
		assert.deepEqual(selectionToEntityTypes(['PERSON', 'IBAN']), ['IBAN', 'IBAN_CODE', 'PERSON']);
		assert.equal(selectionToEntityTypes([]), undefined);
		assert.equal(selectionToEntityTypes(undefined), undefined);
		assert.equal(selectionToEntityTypes(['bad id', 5]), undefined);
		assert.equal(selectionToEntityTypes(ALL_IDS), undefined);
		assert.equal(selectionToEntityTypes(ALL_IDS.slice(1)).includes('PERSON'), false);
	});

	test('unknown TYPE-shaped ids are sent; a type covered by a row is not', () => {
		assert.deepEqual(selectionToEntityTypes(['EMAIL_ADDRESS', 'NEW_TYPE']), [
			'EMAIL_ADDRESS',
			'NEW_TYPE',
		]);
		assert.deepEqual(selectionToEntityTypes(['NEW_TYPE']), ['NEW_TYPE']);
		assert.equal(selectionToEntityTypes(['IBAN_CODE']), undefined);
		// Every bundled row plus an unknown id: everything selected, so the field is omitted.
		assert.equal(selectionToEntityTypes([...ALL_IDS, 'NEW_TYPE']), undefined);
	});

	test('with a document, every bundled row selected omits the field (findings 0 and 7)', () => {
		// A workflow saved with every built-in type ticked meant "All Types". Server-only rows the
		// document adds (ticked or not) must not turn that into a narrowing filter.
		const merged = mergeCatalog(SERVER_DOC);
		assert.equal(entityFilter(merged, ALL_IDS), undefined);
		assert.equal(entityFilter(merged, [...ALL_IDS, 'IT_FISCAL_CODE']), undefined);
		assert.equal(entityFilter(merged, [...ALL_IDS, 'NEW_TYPE']), undefined);
		assert.equal(
			entityFilter(
				merged,
				merged.rows.map((r) => r.id),
			),
			undefined,
		);
		// Same answer as without a document, so a failed capabilities fetch changes nothing.
		assert.equal(entityFilter(mergeCatalog(null), ALL_IDS), undefined);
	});

	test('with a document, a partial selection sends exactly what is selected', () => {
		const merged = mergeCatalog(SERVER_DOC);
		const rest = ALL_IDS.filter((id) => id !== 'URL');
		const restTypes = [
			...new Set(ENTITY_CATALOG.filter((r) => r.id !== 'URL').flatMap((r) => r.types)),
		].sort();
		assert.deepEqual(entityFilter(merged, rest), restTypes);
		assert.deepEqual(
			entityFilter(merged, [...rest, 'IT_FISCAL_CODE']),
			[...restTypes, 'IT_FISCAL_CODE'].sort(),
		);
		assert.deepEqual(entityFilter(merged, ['IT_FISCAL_CODE']), ['IT_FISCAL_CODE']);
		assert.deepEqual(entityFilter(merged, ['PERSON', 'SOCIAL_HANDLE']), [
			'PERSON',
			'SOCIAL_HANDLE',
		]);
		assert.equal(entityFilter(merged, []), undefined);
	});
});

describe('against the extension lib/entities.js', () => {
	function loadExt() {
		const ctx = vm.createContext({});
		ctx.self = ctx;
		vm.runInContext(readFileSync(join(EXT_DIR, 'lib/entities.js'), 'utf8'), ctx);
		const api = ctx.anonEntities;
		// The extension checks `instanceof Map`, so its labels must be Maps of its own realm.
		const VmMap = vm.runInContext('Map', ctx);
		api.realm = (doc) =>
			doc && {
				...doc,
				labels: new VmMap([...doc.labels].map(([ref, langs]) => [ref, new VmMap(langs)])),
			};
		return api;
	}
	const plain = (value) => JSON.parse(JSON.stringify(value));
	const rowView = (r) => [r.id, r.types, r.groups, r.serverOnly, r.labels.get('en') ?? null];
	const groupView = (g) => [g.id, g.kind, g.labels.get('en') ?? null];

	test('catalog and groups match row for row', { skip: EXT_SKIP }, () => {
		const ext = loadExt();
		assert.deepEqual(plain(ENTITY_CATALOG), plain(ext.CATALOG));
		assert.deepEqual(plain(ENTITY_GROUPS), plain(ext.GROUPS));
	});

	test('merge: same rows, types, groups and English labels', { skip: EXT_SKIP }, () => {
		const ext = loadExt();
		for (const doc of [null, SERVER_DOC]) {
			const ours = mergeCatalog(doc);
			// The extension's seen-on set and opt_in default are UI state; compare the rest.
			const theirs = ext.mergeCatalog(ext.realm(doc), []);
			assert.equal(ours.source, theirs.source);
			assert.deepEqual(ours.rows.map(rowView), plain(theirs.rows.map(rowView)));
			assert.deepEqual(ours.groups.map(groupView), plain(theirs.groups.map(groupView)));
		}
	});

	test(
		'filter: the same field as anonEntityFilter for the same enabled set',
		{ skip: EXT_SKIP },
		() => {
			const ext = loadExt();
			const selections = [
				[],
				['PERSON'],
				['PERSON', 'IBAN', 'ZZZS'],
				ALL_IDS,
				ALL_IDS.slice(3),
				['IT_FISCAL_CODE'],
				['EMAIL_ADDRESS', 'SOCIAL_HANDLE'],
			];
			for (const doc of [null, SERVER_DOC]) {
				const merged = mergeCatalog(doc);
				const extMerged = ext.mergeCatalog(ext.realm(doc), []);
				const allIds = merged.rows.map((r) => r.id);
				for (const selection of [...selections, allIds]) {
					// The extension stores deviations from its defaults: here every row explicitly on or
					// off, plus the selected ids it does not list.
					const stored = Object.fromEntries(allIds.map((id) => [id, selection.includes(id)]));
					for (const id of selection) stored[id] = true;
					// Deliberate deviation: n8n stores no explicit off for server-only rows, so every
					// bundled row selected means All Types (field omitted) whatever the server adds.
					const allBundled = ALL_IDS.every((id) => selection.includes(id));
					const expected = allBundled ? undefined : ext.entityFilter(extMerged, stored);
					assert.deepEqual(
						entityFilter(merged, selection),
						expected === undefined ? undefined : plain(expected),
						`${doc ? 'server' : 'bundled'}: ${selection.join(',')}`,
					);
				}
			}
		},
	);
});
