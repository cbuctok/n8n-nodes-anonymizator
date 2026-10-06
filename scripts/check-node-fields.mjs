/**
 * Checks that every fixedCollection in a node is internally consistent.
 *
 * The hard rule, learned from a bug that only reproduced inside a running n8n: a collection's
 * `default` must carry a row keyed by the collection's own container name, listing exactly the
 * leaves the collection declares. n8n builds the value it hands the node from `default`, so a leaf
 * absent there is silently dropped even when a saved workflow contains it.
 *
 * `displayOptions` on a sub-field is reported as a warning only. n8n's own nodes use it freely (the
 * Slack node has dozens), so it is not a rule on its own; it is worth a second look because a
 * condition that cannot resolve at that point is one way a field goes missing.
 *
 *   node scripts/check-node-fields.mjs                       # this package's Anonymizator node
 *   node scripts/check-node-fields.mjs <path-to-node.js>     # any compiled node
 */
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);

const here = dirname(fileURLToPath(import.meta.url));

function loadNodeClass(modulePath) {
	const mod = require(modulePath);
	const name = Object.keys(mod).find((k) => /^[A-Z]/.test(k));
	if (!name) throw new Error(`no exported node class in ${modulePath}`);
	return mod[name];
}

const problems = [];
const warnings = [];

function checkCollection(collection, path) {
	if (!Array.isArray(collection.options)) return;

	const defaults = collection.default ?? {};

	for (const option of collection.options) {
		const container = option.name;
		const where = `${path} -> ${collection.name}.${container}`;

		if (!Array.isArray(option.values)) continue;

		// Advisory: a condition here is one way a field goes missing, but n8n's own nodes use it.
		for (const leaf of option.values) {
			if (leaf.displayOptions) {
				warnings.push(`${where}.${leaf.name} carries displayOptions`);
			}
		}

		// The default must supply a row under the container name, with every leaf present.
		const rows = defaults[container];
		if (!Array.isArray(rows) || rows.length === 0) {
			problems.push(`${where} has no default row under "${container}"`);
			continue;
		}

		const declared = option.values.map((v) => v.name);
		const supplied = Object.keys(rows[0]);
		const missing = declared.filter((d) => !supplied.includes(d));
		if (missing.length) {
			problems.push(`${where} default row is missing: ${missing.join(', ')}`);
		}

		// Recurse into nested collections.
		for (const leaf of option.values) {
			if (leaf.type === 'fixedCollection') checkCollection(leaf, `${where}.${leaf.name}`);
		}
	}
}

function checkNode(nodeClass, label) {
	const instance = new nodeClass();
	const properties = instance.description?.properties ?? [];

	for (const property of properties) {
		if (property.type === 'fixedCollection') checkCollection(property, `${label}.${property.name}`);
	}
}

const target = process.argv[2];
if (target) {
	const modulePath = resolve(process.cwd(), target);
	const cls = loadNodeClass(modulePath);
	checkNode(cls, target);
	console.log(`checked ${target}`);
} else {
	const modulePath = resolve(here, '../dist/nodes/Anonymizator/Anonymizator.node.js');
	const cls = loadNodeClass(modulePath);
	checkNode(cls, 'Anonymizator');
	console.log('checked Anonymizator');
}

if (warnings.length) {
	console.log(`\n${warnings.length} warning(s):`);
	for (const w of warnings) console.log('  ' + w);
}

if (problems.length) {
	console.error(`\n${problems.length} problem(s):`);
	for (const p of problems) console.error('  ' + p);
	process.exit(1);
}

console.log('all collections are internally consistent');
