// Structural checks on the built package (run after `npm run build`). Never shipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

test('package.json n8n entries point at built files', () => {
	for (const path of [...pkg.n8n.nodes, ...pkg.n8n.credentials]) {
		assert.doesNotThrow(() => require(`../${path}`), path);
	}
	// NOTICE carries the attribution for the code ported from the Anonymizator extension.
	assert.deepEqual(pkg.files, ['dist', 'NOTICE']);
	assert.equal(pkg.dependencies, undefined);
});

test('node description: names, credential gated on Protect, tool usage', () => {
	const { Anonymizator } = require('../dist/nodes/Anonymizator/Anonymizator.node.js');
	const d = new Anonymizator().description;
	assert.equal(d.name, 'anonymizator');
	assert.equal(d.displayName, 'Anonymizator');
	assert.equal(d.usableAsTool, true);
	assert.deepEqual(d.credentials, [
		{
			name: 'anonymizatorApi',
			required: true,
			displayOptions: { show: { operation: ['protect'] } },
		},
	]);
	const op = d.properties.find((p) => p.name === 'operation');
	assert.equal(op.default, 'protect');
	assert.deepEqual(
		op.options.map((o) => o.value),
		['protect', 'reveal'],
	);
});

test('credential: bearer auth and redirect-safe test', () => {
	const { AnonymizatorApi } = require('../dist/credentials/AnonymizatorApi.credentials.js');
	const c = new AnonymizatorApi();
	assert.equal(c.name, 'anonymizatorApi');
	assert.equal(c.displayName, 'Anonymizator API');
	assert.equal(c.test.request.baseURL, 'https://anon.prosecco37.com');
	assert.equal(c.test.request.url, '/v1/keyconfig');
	assert.equal(c.test.request.disableFollowRedirect, true);
	assert.deepEqual(
		c.test.rules.map((r) => r.properties.value),
		[302, 401, 403],
	);
	assert.match(c.documentationUrl, /^https:\/\//);
});

test('codex categories are valid community categories', () => {
	const codex = require('../dist/nodes/Anonymizator/Anonymizator.node.json');
	assert.equal(codex.node, 'n8n-nodes-anonymizator.anonymizator');
	assert.deepEqual(codex.categories, ['Utility', 'Development']);
});
