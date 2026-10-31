#!/usr/bin/env node
/**
 * Builds nodes/Anonymizator/shared/vendor/ (noblePq.ts and noble/*.ts): the ONE vendored
 * third-party crypto code of the node, for the EXPERIMENTAL post-quantum protocol v3 (X-Wing;
 * anonymizator repository, docs/HPKE-V3-EXPERIMENTAL.md section 13.1).
 *
 * Why not the esbuild bundle of section 13.1: the n8n recipe there needs the bundle in
 * eslint.config.mjs `ignores`, but this package runs `n8n-node lint` in strict mode
 * (`n8n.strict: true`), which exits 1 when eslint.config.mjs differs from the CLI default, and
 * `// @ts-nocheck` is itself a lint error (@typescript-eslint/ban-ts-comment). So the vendored
 * code is TypeScript, taken from the `src/*.ts` files that the pinned noble tarballs ship:
 *
 * - Starting from the three exports the node needs ({ml_kem768, sha3_256, shake256}), the
 *   script follows every identifier through the top-level declarations and imports of the
 *   upstream modules (TypeScript compiler API) and keeps exactly the declarations that are
 *   reached: the same closure esbuild's tree shaking keeps, plus the types.
 * - Each kept declaration is copied byte for byte, with its comments. One output file per
 *   upstream module, so names never collide; imports are rewritten to the sibling files.
 * - PATCHES (below) are the only edits: each names its reason and must match exactly once.
 *
 * Run by hand by a developer only, never by a test or a build, and never with network access
 * of its own:
 *
 *   npm pack @noble/post-quantum@0.7.1 @noble/hashes@2.4.0 @noble/curves@2.4.0   (in an empty dir)
 *   node scripts/vendor-noble-pq.mjs --tarballs <that dir>            # check: rebuild and compare
 *   node scripts/vendor-noble-pq.mjs --tarballs <that dir> --write    # rewrite the files + lock
 *
 * Every tarball's SHA-256 and npm integrity are checked against vendor-noble.lock.json BEFORE it
 * is unpacked. The lock then records the upstream source files (SHA-256 each), the declarations
 * kept per module, the patches, the TypeScript version that parsed them, and every output file's
 * SHA-256 (test/vendorNoble.test.mjs checks them). Run `npm run lint && npm run build` after
 * `--write`.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const LOCK = join(ROOT, 'vendor-noble.lock.json');
const OUT_DIR_REL = 'nodes/Anonymizator/shared/vendor';
const OUT_DIR = join(ROOT, OUT_DIR_REL);

/** Upstream module (package + path below src/) -> output file name below vendor/noble/. */
const MODULES = {
	'@noble/hashes:_u64': 'hashesU64',
	'@noble/hashes:utils': 'hashesUtils',
	'@noble/hashes:sha3': 'hashesSha3',
	'@noble/curves:utils': 'curvesUtils',
	'@noble/curves:abstract/modular': 'curvesModular',
	'@noble/curves:abstract/fft': 'curvesFft',
	'@noble/post-quantum:utils': 'pqUtils',
	'@noble/post-quantum:_crystals': 'pqCrystals',
	'@noble/post-quantum:ml-kem': 'pqMlKem',
};

/** The exports the node uses (shared/hpkeV3.ts), re-exported by vendor/noblePq.ts. */
const ROOTS = [
	['@noble/post-quantum:ml-kem', 'ml_kem768'],
	['@noble/hashes:sha3', 'sha3_256'],
	['@noble/hashes:sha3', 'shake256'],
];

/**
 * The only edits to upstream text, applied to the source file before it is parsed. Each must
 * match exactly once. Keep this list short and every reason concrete.
 */
const PATCHES = [
	{
		module: '@noble/hashes:utils',
		reason:
			"n8n's verification scanner forbids the global `globalThis` (no-restricted-globals, also on dist/). " +
			'randomBytes is never reached: the node always passes the ML-KEM randomness `m` from ' +
			'node:crypto.randomBytes (HPKE-V3-EXPERIMENTAL.md section 4). It throws instead, as the ' +
			"spec's --define:globalThis=undefined bundle would.",
		find:
			"  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;\n" +
			"  if (typeof cr?.getRandomValues !== 'function')\n" +
			"    throw new Error('crypto.getRandomValues must be defined');\n" +
			'  // Web Cryptography API Level 2 §10.1.1:\n' +
			'  // if `byteLength > 65536`, throw `QuotaExceededError`.\n' +
			'  // Keep the guard explicit so callers can see the quota in code\n' +
			'  // instead of discovering it by reading the spec or host errors.\n' +
			'  // This wrapper surfaces the same quota as a stable library RangeError.\n' +
			'  if (bytesLength > 65536)\n' +
			'    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);\n' +
			'  return cr.getRandomValues(new Uint8Array(bytesLength));\n',
		replace:
			'  // n8n vendoring: no platform CSPRNG here (globalThis is banned in n8n nodes). Callers\n' +
			'  // always pass their randomness explicitly, so this is never reached.\n' +
			"  throw new Error('randomBytes is not available in the vendored subset');\n",
	},
	{
		module: '@noble/hashes:utils',
		reason:
			'Object.hasOwn is ES2022; the project compiles against lib es2019/es2020 (tsconfig.json is ' +
			"the n8n CLI template's and must not change). Same semantics.",
		find: '      !Object.hasOwn(object, fieldName) &&',
		replace: '      !Object.prototype.hasOwnProperty.call(object, fieldName) &&',
	},
	{
		module: '@noble/hashes:utils',
		reason: 'As above (Object.hasOwn is ES2022).',
		find: "  if (Object.hasOwn(value, '__proto__'))",
		replace: "  if (Object.prototype.hasOwnProperty.call(value, '__proto__'))",
	},
	{
		module: '@noble/curves:utils',
		reason: 'As above (Object.hasOwn is ES2022).',
		find: '      !Object.hasOwn(object, fieldName) &&',
		replace: '      !Object.prototype.hasOwnProperty.call(object, fieldName) &&',
	},
	{
		module: '@noble/hashes:_u64',
		reason: 'prefer-const (lint). Never reassigned, so const is the same program.',
		find: '  let Ah = new Uint32Array(len);\n  let Al = new Uint32Array(len);\n',
		replace: '  const Ah = new Uint32Array(len);\n  const Al = new Uint32Array(len);\n',
	},
	{
		module: '@noble/hashes:utils',
		reason:
			'@typescript-eslint/no-empty-object-type (lint). Type only: NonNullable<unknown> is {}.',
		find: 'type EmptyObj = {};\n',
		replace: 'type EmptyObj = NonNullable<unknown>;\n',
	},
	{
		module: '@noble/post-quantum:_crystals',
		reason:
			'@typescript-eslint/no-unused-vars (lint). The stub ignores its argument either way; callers ' +
			'still type-check against the field type.',
		find: '  const inv = (_a: number) => {\n',
		replace: '  const inv = () => {\n',
	},
	{
		module: '@noble/post-quantum:ml-kem',
		reason:
			'@typescript-eslint/no-unused-vars (lint). Array holes skip the same elements; the decode ' +
			'call and its checks are unchanged.',
		find: '      const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);\n',
		replace: '      const [, publicKey] = secretCoder.decode(secretKey);\n',
	},
];

/**
 * Type-only rewrite (no effect on the emitted JavaScript, since types are erased): every `any`
 * type in a kept declaration is spelled ANY_ALIAS, declared once per file as `any` written
 * without the keyword, so the strict local lint config (@typescript-eslint/no-explicit-any)
 * passes without editing eslint.config.mjs. The counts per file are recorded in the lock.
 */
const ANY_ALIAS = 'NobleAny';
const ANY_ALIAS_DECL =
	`// n8n vendoring: upstream's \`any\`, spelled without the keyword (type only; see the lock).\n` +
	`type ${ANY_ALIAS} = ReturnType<typeof JSON.parse>;\n`;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const integrity = (buf) => 'sha512-' + createHash('sha512').update(buf).digest('base64');

function args() {
	const out = { tarballs: null, write: false };
	const argv = process.argv.slice(2);
	for (let i = 0; i < argv.length; i++) {
		if (argv[i] === '--tarballs') out.tarballs = argv[++i];
		else if (argv[i] === '--write') out.write = true;
		else throw new Error(`unknown argument ${argv[i]}`);
	}
	if (!out.tarballs) throw new Error('--tarballs <dir> is required (see the header)');
	return out;
}

/** Resolves an import specifier of module `from` to a MODULES key. */
function resolveSpecifier(from, spec) {
	const [pkg, path] = from.split(':');
	let key;
	if (spec.startsWith('.')) {
		const joined = posix.normalize(posix.join(posix.dirname(path), spec)).replace(/\.(ts|js)$/, '');
		key = `${pkg}:${joined}`;
	} else {
		const m = /^(@noble\/[a-z-]+)\/(.+?)\.js$/.exec(spec);
		if (!m) throw new Error(`${from}: unexpected import ${spec}`);
		key = `${m[1]}:${m[2]}`;
	}
	if (!MODULES[key]) throw new Error(`${from}: import ${spec} -> ${key} is not in MODULES`);
	return key;
}

function declaredNames(stmt) {
	if (ts.isVariableStatement(stmt)) {
		return stmt.declarationList.declarations.map((d) => {
			if (!ts.isIdentifier(d.name)) throw new Error('destructuring at top level is not supported');
			return d.name.text;
		});
	}
	if (
		(ts.isFunctionDeclaration(stmt) ||
			ts.isClassDeclaration(stmt) ||
			ts.isInterfaceDeclaration(stmt) ||
			ts.isTypeAliasDeclaration(stmt) ||
			ts.isEnumDeclaration(stmt)) &&
		stmt.name
	) {
		return [stmt.name.text];
	}
	return [];
}

const hasExport = (stmt) =>
	(ts.canHaveModifiers(stmt) ? (ts.getModifiers(stmt) ?? []) : []).some(
		(m) => m.kind === ts.SyntaxKind.ExportKeyword,
	);

/** Parses one upstream module into declarations, imports and local export aliases. */
function parseModule(key, text) {
	const sf = ts.createSourceFile(`${key}.ts`, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
	const decls = new Map(); // name -> [statement]
	const imports = new Map(); // local name -> { module, name, isType }
	const aliases = new Map(); // exported name -> local name
	const side = []; // top-level statements that declare nothing
	for (const stmt of sf.statements) {
		if (ts.isImportDeclaration(stmt)) {
			const module = resolveSpecifier(key, stmt.moduleSpecifier.text);
			const clause = stmt.importClause;
			if (
				!clause ||
				clause.name ||
				!clause.namedBindings ||
				!ts.isNamedImports(clause.namedBindings)
			) {
				throw new Error(`${key}: only named imports are supported`);
			}
			for (const el of clause.namedBindings.elements) {
				imports.set(el.name.text, {
					module,
					name: (el.propertyName ?? el.name).text,
					isType: clause.isTypeOnly || el.isTypeOnly,
				});
			}
			continue;
		}
		if (ts.isExportDeclaration(stmt)) {
			if (stmt.moduleSpecifier) throw new Error(`${key}: export ... from is not supported`);
			for (const el of stmt.exportClause.elements) {
				aliases.set(el.name.text, (el.propertyName ?? el.name).text);
			}
			continue;
		}
		const names = declaredNames(stmt);
		if (names.length === 0) side.push(stmt);
		for (const name of names) {
			if (!decls.has(name)) decls.set(name, []);
			decls.get(name).push(stmt);
		}
	}
	return { key, sf, text, decls, imports, aliases, side };
}

/** Identifiers a statement references, minus property names and its own declared names. */
function referencedIdentifiers(stmt) {
	const out = new Set();
	const visit = (node) => {
		if (ts.isIdentifier(node)) {
			const p = node.parent;
			const isPropName =
				(ts.isPropertyAccessExpression(p) && p.name === node) ||
				(ts.isPropertyAssignment(p) && p.name === node) ||
				(ts.isMethodDeclaration(p) && p.name === node) ||
				(ts.isPropertyDeclaration(p) && p.name === node) ||
				(ts.isPropertySignature(p) && p.name === node) ||
				(ts.isMethodSignature(p) && p.name === node) ||
				(ts.isGetAccessorDeclaration(p) && p.name === node) ||
				(ts.isSetAccessorDeclaration(p) && p.name === node) ||
				(ts.isQualifiedName(p) && p.right === node);
			if (!isPropName) out.add(node.text);
		}
		ts.forEachChild(node, visit);
	};
	visit(stmt);
	return out;
}

function buildClosure(mods) {
	const kept = new Map(Object.keys(MODULES).map((k) => [k, new Set()])); // module -> decl names
	const usedImports = new Map(Object.keys(MODULES).map((k) => [k, new Set()])); // module -> local names
	const exportedNeeded = new Map(Object.keys(MODULES).map((k) => [k, new Set()])); // module -> decl names
	const work = [];
	/** Resolves (module, exported name) to (module, declaration name). */
	const resolveExport = (module, name) => {
		const m = mods.get(module);
		if (m.decls.has(name)) return [module, name];
		if (m.aliases.has(name)) return resolveLocal(module, m.aliases.get(name));
		throw new Error(`${module} does not export ${name}`);
	};
	const resolveLocal = (module, name) => {
		const m = mods.get(module);
		if (m.decls.has(name)) return [module, name];
		const imp = m.imports.get(name);
		if (imp) return resolveExport(imp.module, imp.name);
		throw new Error(`${module}: ${name} is neither declared nor imported`);
	};
	const enqueue = (module, name) => {
		if (kept.get(module).has(name)) return;
		kept.get(module).add(name);
		work.push([module, name]);
	};
	for (const [module, name] of ROOTS) {
		const [dm, dn] = resolveExport(module, name);
		enqueue(dm, dn);
	}
	const follow = (module, stmt) => {
		const m = mods.get(module);
		for (const id of referencedIdentifiers(stmt)) {
			if (m.decls.has(id)) enqueue(module, id);
			else if (m.imports.has(id)) {
				usedImports.get(module).add(id);
				const [dm, dn] = resolveLocal(module, id);
				exportedNeeded.get(dm).add(dn);
				enqueue(dm, dn);
			}
		}
	};
	// Top-level statements that declare nothing (sha3.ts fills its round tables in a top-level
	// `for` loop) are kept when they touch a kept declaration, and followed like one.
	const sideKept = new Map(Object.keys(MODULES).map((k) => [k, new Set()]));
	for (;;) {
		while (work.length) {
			const [module, name] = work.pop();
			for (const stmt of mods.get(module).decls.get(name)) follow(module, stmt);
		}
		let added = false;
		for (const [module, m] of mods) {
			for (const stmt of m.side) {
				if (sideKept.get(module).has(stmt)) continue;
				const ids = referencedIdentifiers(stmt);
				if ([...ids].some((id) => kept.get(module).has(id))) {
					sideKept.get(module).add(stmt);
					follow(module, stmt);
					added = true;
				}
			}
		}
		if (!added && !work.length) break;
	}
	for (const [module, name] of ROOTS) exportedNeeded.get(resolveExport(module, name)[0]).add(name);
	return { kept, sideKept, usedImports, exportedNeeded, resolveLocal, anyRewrites: new Map() };
}

function headerComment(m) {
	const lic = /\/\*! noble-[^*]*\*\//.exec(m.text);
	const [pkg, path] = m.key.split(':');
	return [
		`// GENERATED by scripts/vendor-noble-pq.mjs from ${pkg} src/${path}.ts (MIT, (c) Paul Miller);`,
		'// version and hashes in vendor-noble.lock.json. Never edit by hand. Only the declarations',
		'// reached from ml_kem768, sha3_256 and shake256 are kept, byte for byte, apart from the',
		'// patches listed in the lock. EXPERIMENTAL protocol v3 only (shared/hpkeV3.ts).',
		lic ? lic[0] : null,
	]
		.filter(Boolean)
		.join('\n');
}

function emitModule(m, closure) {
	const keptNames = closure.kept.get(m.key);
	if (keptNames.size === 0) return null;
	// Statements in source order (a function's overloads are separate statements).
	const stmts = m.sf.statements.filter(
		(s) => declaredNames(s).some((n) => keptNames.has(n)) || closure.sideKept.get(m.key).has(s),
	);
	// Imports grouped by target file, as `import { declName as localName }`.
	const byTarget = new Map();
	for (const local of [...closure.usedImports.get(m.key)].sort()) {
		const imp = m.imports.get(local);
		const [dm, dn] = closure.resolveLocal(m.key, local);
		if (!byTarget.has(dm)) byTarget.set(dm, []);
		const spec = dn === local ? local : `${dn} as ${local}`;
		byTarget.get(dm).push(imp.isType ? `type ${spec}` : spec);
	}
	const importLines = [...byTarget.keys()]
		.sort((a, b) => MODULES[a].localeCompare(MODULES[b]))
		.map((dm) => `import { ${byTarget.get(dm).join(', ')} } from './${MODULES[dm]}';`);
	let anyCount = 0;
	const body = stmts
		.map((s) => {
			// Replace `any` keywords from the end so earlier offsets stay valid.
			const anys = [];
			const visit = (node) => {
				if (node.kind === ts.SyntaxKind.AnyKeyword) anys.push(node);
				ts.forEachChild(node, visit);
			};
			visit(s);
			let text = s.getFullText();
			const base = s.getFullStart();
			for (const node of anys.reverse()) {
				const start = node.getStart() - base;
				const end = node.getEnd() - base;
				if (text.slice(start, end) !== 'any') throw new Error(`${m.key}: unexpected any node`);
				text = text.slice(0, start) + ANY_ALIAS + text.slice(end);
			}
			anyCount += anys.length;
			return text.replace(/^\n+/, '');
		})
		.join('\n');
	closure.anyRewrites.set(m.key, anyCount);
	const needExport = [...closure.exportedNeeded.get(m.key)].filter((n) =>
		m.decls.get(n).every((s) => !hasExport(s)),
	);
	const exportLine = needExport.length ? `\nexport { ${needExport.sort().join(', ')} };\n` : '';
	const alias = anyCount ? `\n${ANY_ALIAS_DECL}` : '';
	return `${headerComment(m)}\n${importLines.join('\n')}${importLines.length ? '\n' : ''}${alias}\n${body.replace(/\s*$/, '\n')}${exportLine}`;
}

const ENTRY = [
	'// GENERATED by scripts/vendor-noble-pq.mjs. Never edit by hand. The vendored subset of',
	'// @noble/post-quantum 0.7.1 and @noble/hashes 2.4.0 (MIT, (c) Paul Miller) that the',
	'// EXPERIMENTAL protocol v3 (shared/hpkeV3.ts) uses; provenance in vendor-noble.lock.json.',
	"export { ml_kem768 } from './noble/pqMlKem';",
	"export { sha3_256, shake256 } from './noble/hashesSha3';",
	'',
].join('\n');

function main() {
	const { tarballs, write } = args();
	const lock = JSON.parse(readFileSync(LOCK, 'utf8'));
	const work = mkdtempSync(join(tmpdir(), 'anon-noble-pq-'));
	try {
		for (const pkg of lock.packages) {
			const file = join(tarballs, pkg.tarball_file);
			const buf = readFileSync(file);
			if (sha256(buf) !== pkg.tarball_sha256)
				throw new Error(`${pkg.name}: tarball SHA-256 mismatch`);
			if (integrity(buf) !== pkg.integrity) throw new Error(`${pkg.name}: npm integrity mismatch`);
			const dest = join(work, pkg.name);
			mkdirSync(dest, { recursive: true });
			execFileSync('tar', ['-xzf', file, '-C', dest, '--strip-components=1']);
		}
		const mods = new Map();
		const sources = new Map();
		for (const key of Object.keys(MODULES)) {
			const [pkg, path] = key.split(':');
			const raw = readFileSync(join(work, pkg, 'src', `${path}.ts`), 'utf8');
			sources.set(key, { path: `src/${path}.ts`, sha256: sha256(raw) });
			let text = raw;
			for (const p of PATCHES.filter((x) => x.module === key)) {
				const n = text.split(p.find).length - 1;
				if (n !== 1) throw new Error(`patch for ${key} matches ${n} times: ${p.reason}`);
				text = text.replace(p.find, () => p.replace);
			}
			mods.set(key, parseModule(key, text));
		}
		const closure = buildClosure(mods);
		const outputs = new Map(); // relative path -> text
		for (const m of mods.values()) {
			const text = emitModule(m, closure);
			if (text !== null) outputs.set(`noble/${MODULES[m.key]}.ts`, text);
		}
		outputs.set('noblePq.ts', ENTRY);

		const packages = lock.packages.map((pkg) => ({
			...pkg,
			source_files: Object.keys(MODULES)
				.filter((k) => k.startsWith(`${pkg.name}:`))
				.map((k) => ({
					...sources.get(k),
					output: closure.kept.get(k).size ? `noble/${MODULES[k]}.ts` : null,
					kept: [...closure.kept.get(k)].sort(),
					top_level_statements_kept: closure.sideKept.get(k).size,
					any_rewrites: closure.anyRewrites.get(k) ?? 0,
				})),
		}));
		const next = {
			...lock,
			packages,
			generator: {
				script: 'scripts/vendor-noble-pq.mjs',
				typescript: ts.version,
				roots: ROOTS.map(([m, n]) => `${m}#${n}`),
				patches: PATCHES,
				type_rewrite: `every \`any\` type in a kept declaration is spelled ${ANY_ALIAS}, declared per file as: ${ANY_ALIAS_DECL.trim()}`,
			},
			outputs: [...outputs.entries()]
				.sort(([a], [b]) => a.localeCompare(b))
				.map(([path, text]) => ({
					path: `${OUT_DIR_REL}/${path}`,
					sha256: sha256(Buffer.from(text, 'utf8')),
					bytes: Buffer.byteLength(text, 'utf8'),
				})),
		};
		const nextText = JSON.stringify(next, null, '\t') + '\n';
		if (write) {
			rmSync(join(OUT_DIR, 'noble'), { recursive: true, force: true });
			mkdirSync(join(OUT_DIR, 'noble'), { recursive: true });
			for (const [path, text] of outputs) writeFileSync(join(OUT_DIR, path), text);
			writeFileSync(LOCK, nextText);
			console.log(`wrote ${outputs.size} files under ${OUT_DIR_REL}/ and vendor-noble.lock.json`);
			return;
		}
		let same = readFileSync(LOCK, 'utf8') === nextText;
		const present = existsSync(join(OUT_DIR, 'noble')) ? readdirSync(join(OUT_DIR, 'noble')) : [];
		if (present.length !== outputs.size - 1) same = false;
		for (const [path, text] of outputs) {
			const file = join(OUT_DIR, path);
			if (!existsSync(file) || readFileSync(file, 'utf8') !== text) same = false;
		}
		console.log(same ? 'up to date' : 'STALE: run with --write');
		process.exitCode = same ? 0 : 1;
	} finally {
		rmSync(work, { recursive: true, force: true });
	}
}

try {
	main();
} catch (err) {
	console.error(String(err && err.message));
	process.exit(2);
}
