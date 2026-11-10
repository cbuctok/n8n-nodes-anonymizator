// Structural checks on the built package (run after `npm run build`). Never shipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

test('package.json n8n entries point at built files', () => {
	for (const path of [...pkg.n8n.nodes, ...pkg.n8n.credentials]) {
		assert.doesNotThrow(() => require(`../${path}`), path);
	}
	// NOTICE carries the attribution for the code ported from the Anonymizator extension.
	assert.deepEqual(pkg.files, [
		'dist',
		'!dist/**/*.map',
		'!dist/**/*.d.ts',
		'!dist/**/*.tsbuildinfo',
		'NOTICE',
	]);
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
			displayOptions: { show: { operation: ['protect', 'detect'] } },
		},
	]);
	const op = d.properties.find((p) => p.name === 'operation');
	assert.equal(op.default, 'protect');
	assert.deepEqual(
		op.options.map((o) => o.value),
		['detect', 'protect', 'reveal'],
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

test('codex alias lists search terms for the nodes panel', () => {
	const codex = require('../dist/nodes/Anonymizator/Anonymizator.node.json');
	assert.ok(Array.isArray(codex.alias));
	for (const term of ['PII', 'anonymize', 'pseudonymize', 'redact', 'GDPR', 'personal data']) {
		assert.ok(codex.alias.includes(term), term);
	}
	for (const term of codex.alias) assert.equal(typeof term, 'string');
	assert.equal(new Set(codex.alias).size, codex.alias.length, 'no duplicates');
});

test('package.json points bug reports at GitHub issues', () => {
	assert.equal(pkg.bugs.url, 'https://github.com/cbuctok/n8n-nodes-anonymizator/issues');
});

// 2026-11-10 (WEB2-7): maps, declarations and build info stay out of the tarball; every runtime
// file the n8n entries need stays in.
test('npm pack file list: no maps, declarations or build info; entries and NOTICE present', () => {
	const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
		cwd: new URL('..', import.meta.url),
		encoding: 'utf8',
	});
	const paths = JSON.parse(out)[0].files.map((f) => f.path);
	assert.deepEqual(
		paths.filter((p) => /\.(map|d\.ts|tsbuildinfo)$/.test(p)),
		[],
	);
	for (const need of [...pkg.n8n.nodes, ...pkg.n8n.credentials, 'NOTICE', 'package.json']) {
		assert.ok(paths.includes(need), `${need} must still ship`);
	}
	assert.ok(paths.some((p) => /nodes\/Anonymizator\/.*\.js$/.test(p)));
});

// 2026-11-10 (WEB2-4): every action in the workflows is pinned to a full commit SHA.
test('workflow actions are pinned to commit SHAs', () => {
	const dir = new URL('../.github/workflows/', import.meta.url);
	for (const f of readdirSync(dir)) {
		for (const m of readFileSync(new URL(f, dir), 'utf8').matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)) {
			assert.match(m[1], /@[0-9a-f]{40}$/, `${f}: ${m[1]}`);
		}
	}
});
