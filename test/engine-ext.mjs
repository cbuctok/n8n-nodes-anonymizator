// Loads the extension's real Protect pipeline files (lib/*.js) into a node:vm context, for the
// engine's differential tests. Never shipped. The checkout is found through ANON_EXT_DIR (the
// anonymizator-chrome-ext subdirectory), else the default locations below; tests SKIP when absent.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

const CANDIDATES = [
	'/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
	'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
];

export const EXT_DIR =
	process.env.ANON_EXT_DIR ??
	CANDIDATES.find((dir) => existsSync(join(dir, 'lib/anonymizer.js'))) ??
	CANDIDATES[0];

/** The worker files of the Protect pipeline, in the extension's importScripts order. */
export const PIPELINE_FILES = [
	'lib/anonymizer.js',
	'lib/id-model.js',
	'lib/id-rules.js',
	'lib/id-names.js',
	'lib/extra-detect.js',
	'lib/id-possible.js',
	'lib/id-edits.js',
];

export const hasExt = PIPELINE_FILES.every((file) => existsSync(join(EXT_DIR, file)));

export const SKIP_EXT = !hasExt && 'extension checkout not found';

/** A fresh vm context with `files` (default: the whole pipeline) loaded in order. */
export function loadExt(files = PIPELINE_FILES) {
	const ctx = vm.createContext({ crypto: webcrypto, console });
	ctx.self = ctx;
	ctx.globalThis = ctx;
	for (const file of files) {
		vm.runInContext(readFileSync(join(EXT_DIR, file), 'utf8'), ctx, { filename: file });
	}
	return ctx;
}

/** Plain JSON copy (drops prototypes from another realm). */
export const plain = (x) => JSON.parse(JSON.stringify(x));

/**
 * A deterministic PRNG (mulberry32) returning integers in [0, n). All arithmetic is 32-bit
 * (Math.imul, >>> 0), so no bits are lost to doubles, and the result comes from the high bits.
 * The earlier double-precision LCG lost its low bits after a few steps (`rnd(2)` stuck at 0),
 * which made the generated differential tests run only a handful of distinct cases.
 */
export function prng(seed) {
	let state = seed >>> 0;
	return (n) => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		const u = ((t ^ (t >>> 14)) >>> 0) / 4294967296;
		return Math.floor(u * n);
	};
}

/** Runs `fn` once; its value and the wall-clock milliseconds it took. */
export function timed(fn) {
	const started = performance.now();
	const value = fn();
	return { value, ms: Math.round(performance.now() - started) };
}
