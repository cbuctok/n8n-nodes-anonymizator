// Entity catalog and filter semantics (port of the extension's lib/entities.js behaviour). Never shipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const {
	ENTITY_CATALOG,
	ENTITY_OPTIONS,
	selectionToEntityTypes,
} = require('../dist/nodes/Anonymizator/shared/entities.js');

const EXT_DIR =
	process.env.ANON_EXT_DIR ??
	'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext';
const hasExt = existsSync(join(EXT_DIR, 'lib/entities.js'));

test('16 rows, unique ids, English labels, descriptions list the server types', () => {
	assert.equal(ENTITY_CATALOG.length, 16);
	assert.equal(new Set(ENTITY_CATALOG.map((r) => r.id)).size, 16);
	assert.equal(new Set(ENTITY_CATALOG.map((r) => r.label)).size, 16);
	for (const r of ENTITY_CATALOG) {
		assert.ok(r.types.length >= 1, r.id);
		assert.ok(r.description.endsWith(`: ${r.types.join(', ')}.`), r.description);
	}
	assert.equal(ENTITY_CATALOG.find((r) => r.id === 'SI_TAX_ID').label, 'Slovenian Tax Number');
	assert.deepEqual(ENTITY_CATALOG.find((r) => r.id === 'IBAN').types, ['IBAN', 'IBAN_CODE']);
});

test('ENTITY_OPTIONS: one per row, sorted by name, no emoji', () => {
	assert.equal(ENTITY_OPTIONS.length, 16);
	const names = ENTITY_OPTIONS.map((o) => o.name);
	assert.deepEqual(
		names,
		[...names].sort((a, b) => a.localeCompare(b, 'en')),
	);
	assert.deepEqual(
		new Set(ENTITY_OPTIONS.map((o) => o.value)),
		new Set(ENTITY_CATALOG.map((r) => r.id)),
	);
	for (const o of ENTITY_OPTIONS) assert.doesNotMatch(o.name, /\p{Extended_Pictographic}/u);
});

test('selectionToEntityTypes: catalog order, IBAN expands, all/none/unknown omit', () => {
	assert.deepEqual(selectionToEntityTypes(['IBAN', 'PERSON']), ['PERSON', 'IBAN', 'IBAN_CODE']);
	assert.deepEqual(selectionToEntityTypes(['EMAIL_ADDRESS', 'NOPE']), ['EMAIL_ADDRESS']);
	assert.equal(selectionToEntityTypes([]), undefined);
	assert.equal(selectionToEntityTypes(undefined), undefined);
	assert.equal(selectionToEntityTypes(['NOPE']), undefined);
	assert.equal(selectionToEntityTypes(ENTITY_CATALOG.map((r) => r.id)), undefined);
	const allButOne = ENTITY_CATALOG.slice(1).map((r) => r.id);
	assert.equal(selectionToEntityTypes(allButOne).includes('PERSON'), false);
});

test(
	'ids, order and server types match the extension catalog',
	{ skip: !hasExt && 'extension checkout not found' },
	() => {
		const ctx = vm.createContext({});
		ctx.self = ctx;
		vm.runInContext(readFileSync(join(EXT_DIR, 'lib/entities.js'), 'utf8'), ctx);
		const ext = JSON.parse(JSON.stringify(ctx.anonEntities.CATALOG));
		assert.deepEqual(
			ENTITY_CATALOG.map((r) => [r.id, r.types]),
			ext.map((r) => [r.id, r.types]),
		);
		// Same filter result for a sample selection.
		const selection = Object.fromEntries(
			ext.map((r) => [r.id, ['PERSON', 'IBAN', 'ZZZS'].includes(r.id)]),
		);
		assert.deepEqual(
			selectionToEntityTypes(['PERSON', 'IBAN', 'ZZZS']),
			JSON.parse(JSON.stringify(ctx.anonEntities.selectionToEntityTypes(selection))),
		);
	},
);
