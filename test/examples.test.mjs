// Structural checks on the importable example workflows under examples/. Never shipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');
const EXAMPLES = new URL('../examples/', import.meta.url);
const NODE_TYPE = 'n8n-nodes-anonymizator.anonymizator';

const dirs = readdirSync(EXAMPLES, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => entry.name);

test('there is at least one example, and examples are not shipped', () => {
	assert.ok(dirs.includes('protect-llm-reveal'));
	assert.ok(!pkg.files.some((f) => f.startsWith('examples')));
});

for (const dir of dirs) {
	const workflow = JSON.parse(readFileSync(new URL(`${dir}/workflow.json`, EXAMPLES), 'utf8'));
	const readme = readFileSync(new URL(`${dir}/README.md`, EXAMPLES), 'utf8');
	const names = workflow.nodes.map((n) => n.name);

	test(`${dir}: only importable keys, no export metadata`, () => {
		assert.deepEqual(Object.keys(workflow).sort(), [
			'connections',
			'name',
			'nodes',
			'pinData',
			'settings',
		]);
		assert.equal(new Set(names).size, names.length, 'node names are unique');
		assert.equal(readme.split('\n')[0], `# ${workflow.name}`);
	});

	test(`${dir}: our nodes use the installed package type, never CUSTOM.`, () => {
		const ours = workflow.nodes.filter((n) => n.type.includes('anonymizator'));
		assert.ok(ours.length > 0);
		for (const node of ours) {
			assert.equal(node.type, NODE_TYPE, node.name);
			assert.equal(node.typeVersion, 1, node.name);
		}
		assert.ok(!JSON.stringify(workflow).includes('CUSTOM.'));
	});

	test(`${dir}: every connection references an existing node`, () => {
		for (const [source, outputs] of Object.entries(workflow.connections)) {
			assert.ok(names.includes(source), `source ${source}`);
			for (const [type, branches] of Object.entries(outputs)) {
				for (const branch of branches) {
					for (const target of branch) {
						assert.ok(names.includes(target.node), `target ${target.node}`);
						assert.equal(target.type, type);
					}
				}
			}
		}
	});

	test(`${dir}: no credential ids or secrets are embedded`, () => {
		for (const node of workflow.nodes) {
			for (const credential of Object.values(node.credentials ?? {})) {
				assert.equal(credential.id, '', `${node.name} must not carry a real credential id`);
			}
		}
		assert.ok(!/sk-[A-Za-z0-9]{16,}|Bearer\s+\S{20,}/.test(JSON.stringify(workflow)));
	});

	test(`${dir}: node references in expressions resolve`, () => {
		const serialised = JSON.stringify(workflow.nodes.map((n) => n.parameters));
		for (const match of serialised.matchAll(/\$\('([^']+)'\)/g)) {
			assert.ok(names.includes(match[1]), `$('${match[1]}') names a node in the workflow`);
		}
	});
}

test('protect-llm-reveal: Protect feeds the chain, Reveal reads the chain output and the map', () => {
	const workflow = JSON.parse(
		readFileSync(new URL('protect-llm-reveal/workflow.json', EXAMPLES), 'utf8'),
	);
	const byName = Object.fromEntries(workflow.nodes.map((n) => [n.name, n]));
	assert.equal(byName.Protect.parameters.operation, undefined, 'Protect is the default operation');
	assert.ok(byName.Protect.credentials.anonymizatorApi);
	assert.equal(byName['Draft Reply'].type, '@n8n/n8n-nodes-langchain.chainLlm');
	assert.match(byName['Draft Reply'].parameters.text, /\{\{ \$json\.protectedText \}\}/);
	assert.match(byName['Draft Reply'].parameters.text, /placeholder/i);
	assert.equal(
		workflow.connections['OpenAI Chat Model'].ai_languageModel[0][0].node,
		'Draft Reply',
	);
	const reveal = byName.Reveal.parameters;
	assert.equal(reveal.operation, 'reveal');
	assert.equal(reveal.text, '={{ $json.text }}');
	assert.equal(reveal.placeholderMap, "={{ $('Protect').item.json.placeholderMap }}");
	assert.equal(byName['OpenAI Chat Model'].credentials, undefined);
});
