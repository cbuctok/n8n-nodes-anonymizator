// The vendored @noble subset (nodes/Anonymizator/shared/vendor/, EXPERIMENTAL protocol v3):
// provenance against vendor-noble.lock.json, the scanner's restricted globals and dangerous calls,
// no runtime dependency in dist/, the copied vector fixtures, and a differential run against the
// extension's esbuild bundle of the same pinned tarballs (unmodified upstream) when present.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import { EXT_BUNDLE_SKIP, loadExtNoblePq } from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const ROOT = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const LOCK = JSON.parse(read('vendor-noble.lock.json').toString('utf8'));
const VENDOR = 'nodes/Anonymizator/shared/vendor';

describe('vendor-noble.lock.json', () => {
	it('pins the tarballs of docs/HPKE-V3-EXPERIMENTAL.md section 13.1', () => {
		const pins = Object.fromEntries(LOCK.packages.map((p) => [p.name, p]));
		assert.deepEqual(Object.keys(pins).sort(), [
			'@noble/curves',
			'@noble/hashes',
			'@noble/post-quantum',
		]);
		assert.equal(pins['@noble/post-quantum'].version, '0.7.1');
		assert.equal(
			pins['@noble/post-quantum'].tarball_sha256,
			'e98947485ff33c322ce75f8ae32cf7041a510dca9b8135f10475c8c10c956bab',
		);
		assert.equal(
			pins['@noble/post-quantum'].integrity,
			'sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==',
		);
		assert.equal(pins['@noble/hashes'].version, '2.4.0');
		assert.equal(
			pins['@noble/hashes'].tarball_sha256,
			'e1946149b780017b2564fcc092cb01c04e1d7f20627d0296c17da8868f4436dc',
		);
		assert.equal(
			pins['@noble/hashes'].integrity,
			'sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==',
		);
		assert.equal(pins['@noble/curves'].version, '2.4.0');
		assert.equal(
			pins['@noble/curves'].tarball_sha256,
			'55279c71b0201d6c0e58d0206d15825359e02a3932f326ba7b7909ac2d334aa9',
		);
		assert.equal(
			pins['@noble/curves'].integrity,
			'sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==',
		);
		for (const p of LOCK.packages) {
			assert.equal(p.license, 'MIT');
			assert.equal(
				p.tarball_url,
				`https://registry.npmjs.org/${p.name}/-/${p.name.split('/')[1]}-${p.version}.tgz`,
			);
			for (const f of p.source_files) assert.match(f.sha256, /^[0-9a-f]{64}$/);
		}
	});

	it('every output file matches its SHA-256, and the vendor directory holds nothing else', () => {
		const listed = LOCK.outputs.map((o) => o.path).sort();
		const present = [
			...readdirSync(new URL(`${VENDOR}/`, ROOT))
				.filter((f) => f.endsWith('.ts'))
				.map((f) => `${VENDOR}/${f}`),
			...readdirSync(new URL(`${VENDOR}/noble/`, ROOT)).map((f) => `${VENDOR}/noble/${f}`),
		].sort();
		assert.deepEqual(present, listed);
		for (const o of LOCK.outputs) {
			const bytes = read(o.path);
			assert.equal(bytes.length, o.bytes, o.path);
			assert.equal(sha256(bytes), o.sha256, o.path);
		}
	});

	it('records every patch with its reason, and the type-only `any` rewrite', () => {
		assert.equal(LOCK.generator.script, 'scripts/vendor-noble-pq.mjs');
		assert.ok(LOCK.generator.patches.length >= 1);
		for (const p of LOCK.generator.patches) {
			assert.ok(
				p.reason.length > 20 && typeof p.find === 'string' && typeof p.replace === 'string',
				p.module,
			);
		}
		assert.match(LOCK.generator.type_rewrite, /NobleAny/);
		assert.deepEqual(LOCK.generator.roots, [
			'@noble/post-quantum:ml-kem#ml_kem768',
			'@noble/hashes:sha3#sha3_256',
			'@noble/hashes:sha3#shake256',
		]);
	});
});

describe('the vendored code is clean for the scanner and has no runtime dependency', () => {
	const sources = LOCK.outputs.map((o) => [o.path, read(o.path).toString('utf8')]);
	const dist = LOCK.outputs.map((o) => {
		const path = o.path.replace(/^nodes\//, 'dist/nodes/').replace(/\.ts$/, '.js');
		return [path, read(path).toString('utf8')];
	});
	// Comments may name things (upstream JSDoc mentions crypto.getRandomValues); code may not.
	const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');

	it('no restricted globals or dangerous calls, in the source and in dist/', () => {
		for (const [path, text] of [...sources, ...dist]) {
			const c = code(text);
			for (const re of [
				/\bglobalThis\b/,
				/\bprocess\b/,
				/\bsetTimeout\b/,
				/\bconsole\b/,
				/\beval\s*\(/,
				/\bnew\s+Function\b/,
				/\bimport\s*\(/,
				/\bfetch\s*\(/,
				/\bXMLHttpRequest\b/,
				/@ts-nocheck|@ts-ignore|eslint-disable/,
			]) {
				assert.doesNotMatch(c, re, `${path}: ${re}`);
			}
		}
	});

	it('the source imports only sibling files; dist/ requires only relative paths', () => {
		for (const [path, text] of sources) {
			assert.doesNotMatch(text, /\brequire\s*\(/, path);
			// Statements only (the upstream JSDoc examples name the npm packages).
			for (const m of text.matchAll(/^(?:import|export)\b[^;]*?from '([^']+)';/gm)) {
				assert.match(m[1], /^\.\//, `${path}: ${m[1]}`);
			}
		}
		for (const [path, text] of dist) {
			for (const m of text.matchAll(/require\("([^"]+)"\)/g))
				assert.match(m[1], /^\.\.?\//, `${path}: ${m[1]}`);
		}
		for (const file of ['hpkeV3', 'keyconfigV3']) {
			const text = read(`dist/nodes/Anonymizator/shared/${file}.js`).toString('utf8');
			for (const m of text.matchAll(/require\("([^"]+)"\)/g)) {
				assert.ok(m[1] === 'node:crypto' || m[1].startsWith('./'), `${file}: ${m[1]}`);
			}
		}
	});

	it('package.json still has no runtime dependencies', () => {
		const pkg = JSON.parse(read('package.json').toString('utf8'));
		assert.equal(pkg.dependencies, undefined);
		assert.deepEqual(pkg.peerDependencies, { 'n8n-workflow': '*' });
		assert.deepEqual(pkg.files, ['dist', 'NOTICE']);
		// The generator parses with the project's own TypeScript; the lock records its version.
		assert.equal(LOCK.generator.typescript, require('typescript').version);
	});

	it('the vendored random source is a stub that throws (callers pass randomness)', () => {
		const utils = require('../dist/nodes/Anonymizator/shared/vendor/noble/hashesUtils.js');
		assert.throws(
			() => utils.randomBytes(32),
			/randomBytes is not available in the vendored subset/,
		);
	});
});

describe('test fixtures copied from the gateway (branch experimental-pq-v3, bd97c6f)', () => {
	it('pgw-v3.json and xwing-official.json are byte-identical to the gateway files', () => {
		assert.equal(
			sha256(read('test/fixtures/pgw-v3.json')),
			'47fcca7969874db0f345f038c477997224659833c4b7f0dc4dc5f2ef40c40853',
		);
		assert.equal(
			sha256(read('test/fixtures/xwing-official.json')),
			'ab1c84c4d9009742fa9707a03ef75e3af5305b1671487c5f2fed70fd008780ea',
		);
	});
});

describe('differential: the vendored subset against the extension bundle of unmodified upstream', () => {
	it(
		'sha3_256, shake256, keygen, encapsulate and decapsulate agree on random inputs',
		{ skip: EXT_BUNDLE_SKIP },
		() => {
			const ours = require('../dist/nodes/Anonymizator/shared/vendor/noblePq.js');
			const theirs = loadExtNoblePq();
			const h = (u) => Buffer.from(u).toString('hex');
			for (let i = 0; i < 40; i++) {
				const m = Uint8Array.from(randomBytes((i * 37) % 600));
				assert.equal(h(ours.sha3_256(m)), h(theirs.sha3_256(m)));
				assert.equal(h(ours.sha3_256(m)), createHash('sha3-256').update(m).digest('hex'));
				assert.equal(
					h(ours.shake256(m, { dkLen: 1 + i * 3 })),
					h(theirs.shake256(m, { dkLen: 1 + i * 3 })),
				);
				const seed = Uint8Array.from(randomBytes(64));
				const a = ours.ml_kem768.keygen(seed);
				const b = theirs.ml_kem768.keygen(seed);
				assert.equal(h(a.publicKey), h(b.publicKey));
				assert.equal(h(a.secretKey), h(b.secretKey));
				const msg = Uint8Array.from(randomBytes(32));
				const ea = ours.ml_kem768.encapsulate(a.publicKey, msg);
				const eb = theirs.ml_kem768.encapsulate(b.publicKey, msg);
				assert.equal(h(ea.cipherText), h(eb.cipherText));
				assert.equal(h(ea.sharedSecret), h(eb.sharedSecret));
				const ct = Uint8Array.from(ea.cipherText);
				if (i % 2) ct[i * 7] ^= 1; // implicit rejection must agree too
				assert.equal(
					h(ours.ml_kem768.decapsulate(ct, a.secretKey)),
					h(theirs.ml_kem768.decapsulate(ct, b.secretKey)),
				);
			}
		},
	);
});
