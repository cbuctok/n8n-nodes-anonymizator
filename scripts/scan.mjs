/**
 * Runs n8n's verification scanner (@n8n/scan-community-package) the way the verification pipeline
 * does, without publishing first:
 *
 * 1. on the source (`package.json` + `{nodes,credentials}/**`), and
 * 2. on the files `npm pack` would publish (the dist tarball, `**\/*.js` + `package.json`).
 *
 * The scanner is not a devDependency (it pins its own eslint and TypeScript). It is installed once
 * into node_modules/.cache/scan-community-package, or taken from SCAN_PACKAGE_DIR when set (a
 * directory containing the scanner's package.json).
 *
 * Usage: npm run build && npm run scan
 *        SCAN_VERSION=0.38.0 npm run scan
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_VERSION = process.env.SCAN_VERSION ?? '0.38.0';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function scannerDir() {
	if (process.env.SCAN_PACKAGE_DIR) return resolve(process.env.SCAN_PACKAGE_DIR);
	const cache = join(root, 'node_modules', '.cache', `scan-community-package-${SCAN_VERSION}`);
	const dir = join(cache, 'node_modules', '@n8n', 'scan-community-package');
	if (!existsSync(join(dir, 'scanner', 'scanner.mjs'))) {
		console.log(`Installing @n8n/scan-community-package@${SCAN_VERSION} into ${cache}`);
		mkdirSync(cache, { recursive: true });
		execFileSync(
			npm,
			[
				'install',
				'--prefix',
				cache,
				'--no-audit',
				'--no-fund',
				'--ignore-scripts',
				'--force',
				`@n8n/scan-community-package@${SCAN_VERSION}`,
			],
			{ stdio: 'inherit' },
		);
	}
	return dir;
}

function report(label, result) {
	const status = result.passed ? 'PASS' : 'FAIL';
	console.log(`\n[${status}] ${label}`);
	if (!result.passed) console.log(JSON.stringify(result, null, 2));
	else if (result.message) console.log(`  ${result.message}`);
}

if (!existsSync(join(root, 'dist', 'nodes', 'Anonymizator', 'Anonymizator.node.js'))) {
	console.error('dist/ is missing: run `npm run build` first');
	process.exit(1);
}

const { analyzePackage, SOURCE_FILE_PATTERNS } = await import(
	pathToFileURL(join(scannerDir(), 'scanner', 'scanner.mjs')).href
);

const work = mkdtempSync(join(tmpdir(), 'anonymizator-scan-'));
let passed = false;
try {
	const source = await analyzePackage(root, SOURCE_FILE_PATTERNS);
	report('source (package.json, nodes/, credentials/)', source);

	const packed = JSON.parse(
		execFileSync(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', work], {
			cwd: root,
			encoding: 'utf8',
		}),
	);
	const tarball = join(work, packed[0].filename);
	execFileSync('tar', ['-xzf', tarball, '-C', work]);
	const files = packed[0].files.map((file) => file.path);
	console.log(`\nPacked ${packed[0].filename}: ${files.length} files`);
	for (const file of files) console.log(`  ${file}`);
	const unexpected = files.filter(
		(file) =>
			!file.startsWith('dist/') && !/^(package\.json|README\.md|LICENSE\.md|NOTICE)$/.test(file),
	);
	if (unexpected.length > 0)
		console.log(`Unexpected files in the tarball: ${unexpected.join(', ')}`);

	const dist = await analyzePackage(join(work, 'package'), ['**/*.js', 'package.json']);
	report('packed tarball (dist)', dist);

	passed = source.passed && dist.passed && unexpected.length === 0;
} finally {
	rmSync(work, { recursive: true, force: true });
}

console.log(passed ? '\nScan passed' : '\nScan FAILED');
process.exit(passed ? 0 : 1);
