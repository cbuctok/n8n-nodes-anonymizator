/**
 * Cuts a release: checks, bump, changelog notes, commit, tag, push.
 *
 *   npm run release
 *
 * The tag push is the whole point. `publish.yml` notices it, re-runs the checks, stages the package
 * on npm with a provenance attestation, and stops; nothing becomes installable until a staged
 * version is approved on npmjs.com. This script deliberately does not publish.
 *
 * Why not `n8n-node release`: it passes `-n` to release-it, and no release-it major has ever
 * accepted that flag, so the command fails before the first prompt. It also passes config keys such
 * as `--git.requireBranch` on the command line, which release-it expects in a config file. The steps
 * that actually matter are short enough to do directly.
 *
 * Before anything is written, it runs lint, the unit tests (which build) and n8n's verification
 * scanner. The scanner is stricter than local lint, and a tag that CI would refuse to stage is a
 * wasted version number. Live checks (`npm run smoke`, `npm run e2e`) need the API key and Docker,
 * so they are left to the person releasing; see AGENTS.md.
 *
 * Requires a clean tree and no upstream drift, because a tag is a promise about a commit. Refusing
 * early is cheaper than a tag pointing at something nobody reviewed.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const BUMPS = ['patch', 'minor', 'major'];

/** The gates CI runs, in the same order. Each must exit 0. */
const CHECKS = [['run', 'lint'], ['test'], ['run', 'check:fields'], ['run', 'scan']];

function run(command, args) {
	return execFileSync(command, args, { cwd: root, encoding: 'utf8' }).trim();
}

function git(...args) {
	return run('git', args);
}

function fail(message) {
	console.error(`\n  ${message}\n`);
	process.exit(1);
}

function readPackage() {
	return JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
}

/** `1.2.3` -> `[1, 2, 3]`. Prerelease suffixes are not supported by this script. */
function parseVersion(version) {
	const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
	if (!match) fail(`package.json version "${version}" is not a plain major.minor.patch`);
	return match.slice(1).map(Number);
}

function bumpVersion(version, bump) {
	const [major, minor, patch] = parseVersion(version);
	if (bump === 'major') return `${major + 1}.0.0`;
	if (bump === 'minor') return `${major}.${minor + 1}.0`;
	return `${major}.${minor}.${patch + 1}`;
}

/** Local date as YYYY-MM-DD, the format of the changelog headings. */
function today() {
	const now = new Date();
	const pad = (n) => String(n).padStart(2, '0');
	return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

/**
 * Replaces the version in package.json without reformatting the rest of the file, and the two
 * version fields of package-lock.json (top level and `packages[""]`), as `npm version` would.
 * Without the lockfile bump the first `npm install` after a release rewrites it, and the next
 * release refuses the dirty tree.
 */
function writeVersion(version) {
	const path = resolve(root, 'package.json');
	const before = readFileSync(path, 'utf8');
	const after = before.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`);
	if (after === before) fail('could not find a version field in package.json');
	writeFileSync(path, after);

	const lockPath = resolve(root, 'package-lock.json');
	if (!existsSync(lockPath)) return;
	const lockText = readFileSync(lockPath, 'utf8');
	const lock = JSON.parse(lockText);
	lock.version = version;
	if (lock.packages && lock.packages['']) lock.packages[''].version = version;
	const indent = /^\{\n([ \t]+)"/.exec(lockText)?.[1] ?? '\t';
	writeFileSync(lockPath, `${JSON.stringify(lock, null, indent)}\n`);
}

/**
 * Inserts a new `## x.y.z - YYYY-MM-DD` section under the `# Changelog` heading. The body is left as
 * an empty bullet on purpose: the notes are the one part of a release that cannot be derived, so the
 * script stops and waits for a person to write them (`waitForNotes`).
 */
function writeChangelog(version) {
	const path = resolve(root, 'CHANGELOG.md');
	const text = readFileSync(path, 'utf8');
	const heading = '## ';
	const section = `## ${version} - ${today()}\n\n- \n\n`;

	const escaped = version.replace(/\./g, '\\.');
	if (new RegExp(`\\n## ${escaped}(?: |\\n)`).test(text)) {
		fail(`CHANGELOG.md already has a ${version} section`);
	}

	const firstEntry = text.indexOf(`\n${heading}`);
	if (firstEntry === -1) fail('CHANGELOG.md has no previous release section to insert before');

	writeFileSync(path, text.slice(0, firstEntry + 1) + section + text.slice(firstEntry + 1));
}

function ensureReleasable() {
	const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
	const dirty = git('status', '--porcelain');
	if (dirty) fail('working tree is dirty; commit or stash first');
	if (!['dev', 'master'].includes(branch)) {
		fail(`refusing to release from "${branch}"; releases come from dev or master`);
	}

	try {
		git('fetch', '--quiet', 'origin');
	} catch {
		fail('could not reach origin; a release must not be cut offline');
	}

	const drift = git('rev-list', '--count', `origin/${branch}..HEAD`);
	const behind = git('rev-list', '--count', `HEAD..origin/${branch}`);
	if (drift !== '0') fail(`${drift} unpushed commit(s) on ${branch}; push first`);
	if (behind !== '0') fail(`local ${branch} is ${behind} commit(s) behind origin; pull first`);

	return { branch, version: readPackage().version };
}

/** Runs the CI gates with their output visible. Stops at the first failure. */
function runChecks() {
	for (const args of CHECKS) {
		console.log(`\n  > npm ${args.join(' ')}\n`);
		try {
			execFileSync(npm, args, { cwd: root, stdio: 'inherit' });
		} catch {
			fail(`npm ${args.join(' ')} failed; nothing was changed`);
		}
	}
	// The checks only write gitignored files (dist/, the scanner cache). Anything else is a surprise.
	if (git('status', '--porcelain')) fail('the checks modified tracked files; inspect git status');
}

/**
 * Asks one question on the terminal. Resolves on both the answer and `close`: a pseudoterminal can
 * deliver the input without ever signalling close, and a promise that only listens for one of them
 * hangs the whole script.
 */
function ask(question) {
	const readline = createInterface({ input: process.stdin, output: process.stdout });
	return new Promise((done) => {
		readline.question(question, (reply) => {
			readline.close();
			done(reply);
		});
		readline.on('close', () => done(''));
	});
}

async function chooseBump(current) {
	if (!process.stdin.isTTY) {
		fail('no terminal available for the version prompt; run this locally');
	}

	const options = BUMPS.map((bump) => `${bump}  ->  ${bumpVersion(current, bump)}`);
	console.log(`\n  current version: ${current}\n`);
	options.forEach((option, index) => console.log(`  ${index + 1}) ${option}`));
	console.log();

	const trimmed = (await ask('  Choose a bump [1]: ')).trim();
	if (trimmed === '') return BUMPS[0];

	const index = Number(trimmed);
	if (!Number.isInteger(index) || index < 1 || index > BUMPS.length) fail('unrecognised choice');
	return BUMPS[index - 1];
}

/**
 * Waits while the release notes are written into the new changelog section, then refuses to commit
 * an empty one. Nothing is committed yet at this point, so a refusal leaves only two edited files.
 */
async function waitForNotes(version) {
	console.log(`  Write the release notes under "## ${version}" in CHANGELOG.md.`);
	await ask('  Press Enter when they are saved: ');

	const text = readFileSync(resolve(root, 'CHANGELOG.md'), 'utf8');
	const start = text.indexOf(`\n## ${version} `);
	const end = text.indexOf('\n## ', start + 1);
	const section = text.slice(start, end === -1 ? undefined : end);
	const bullets = section.split('\n').filter((line) => /^-\s+\S/.test(line));
	if (start === -1 || bullets.length === 0) {
		fail(
			`the ${version} section in CHANGELOG.md has no notes; nothing was committed.\n` +
				'  Undo with: git checkout -- package.json package-lock.json CHANGELOG.md',
		);
	}
}

async function main() {
	const { branch, version: current } = ensureReleasable();
	runChecks();
	const bump = await chooseBump(current);
	const next = bumpVersion(current, bump);

	// Checked against the version being released rather than the one in package.json, which is
	// always the previously released version. Testing the current one would refuse every release.
	// `git fetch` only follows tags that point into fetched history, so ask origin directly too.
	let remoteTag = '';
	try {
		remoteTag = git('ls-remote', '--tags', 'origin', `refs/tags/${next}`);
	} catch {
		fail('could not list the tags on origin; a release must not be cut offline');
	}
	if (git('tag', '-l', next) || remoteTag) fail(`tag ${next} already exists; pick a larger bump`);

	console.log(`\n  ${branch}: ${current} -> ${next}\n`);

	writeVersion(next);
	writeChangelog(next);
	await waitForNotes(next);

	// `git add` aborts on a path that does not exist, and package-lock.json is not guaranteed to be
	// tracked. Adding the version and changelog explicitly, then staging whatever else a dependency
	// bump touched, keeps a missing lockfile from failing the release after the version is written.
	git('add', 'package.json', 'CHANGELOG.md');
	try {
		git('add', 'package-lock.json');
	} catch {
		// No lockfile in this repository; nothing to stage.
	}

	git('commit', '-m', `Release ${next}`);
	git('tag', next);

	// One atomic push: the branch and the tag land together or not at all, so a refused tag never
	// leaves the release commit on origin without its tag (and the undo below stays safe).
	try {
		git('push', '--atomic', 'origin', branch, next);
	} catch {
		fail(
			`release ${next} is committed and tagged locally but not pushed.\n` +
				`  Push it by hand once the reason is clear:\n` +
				`    git push --atomic origin ${branch} ${next}\n` +
				`  Or undo it entirely:\n` +
				`    git tag -d ${next} && git reset --hard HEAD~1`,
		);
	}

	console.log(`\n  Pushed ${next}. CI is staging it on npm; approve it at`);
	console.log('  npmjs.com -> the package -> Staged versions -> Approve\n');
}

await main();
