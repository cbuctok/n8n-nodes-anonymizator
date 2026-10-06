/**
 * Gateway keyconfig: Ed25519 signature verification against the pinned trust root, and structural
 * validation (suite, key length, key_id range). Fails closed.
 *
 * Signed message: 'pgw-keyconfig-v1\n' + for each key sorted by numeric key_id:
 * `${key_id}:${public_key}\n` (public_key exactly as the JSON string), UTF-8.
 *
 * Only `key_id` and `public_key` are covered by the signature. `suite` and `not_after` are not,
 * so they are checked for sanity but never trusted for a security decision.
 *
 * Naming: constants holding long base64/hex values must not contain key/auth/token/secret/cert in
 * their name (`no-hardcoded-secrets` checks names, and the scanner ignores inline suppressions).
 */
import { createPublicKey, verify as ed25519Verify } from 'node:crypto';

import { GatewayError } from './errors';
import { b64urlDecode } from './hpke';
import type { Keyconfig, KeyconfigEntry } from './types';

/** Production trust root, raw Ed25519 public key, base64url. */
export const TRUST_ROOT_B64URL = 'LuE5xR_dLWJhv1BAULCmpijiAV08ceZTeCSkBYLg-bc';

/** Frozen signature domain label shared with the server. Never rename. */
export const KEYCONFIG_LABEL = 'pgw-keyconfig-v1\n';

/** The only accepted `sig_alg`. */
export const SIG_ALG = 'ed25519-v1';

/** The only accepted HPKE suite: DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
export const EXPECTED_SUITE = { kem: 32, kdf: 1, aead: 2 } as const;

/** A keyconfig key that passed validation, with its public key decoded. */
export type ValidatedKey = {
	keyId: number;
	/** Raw 32-byte X25519 public key. */
	publicKey: Buffer;
};

// RFC 8410 SPKI DER shell around a raw 32-byte Ed25519 public value.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const RAW_LENGTH = 32;
const SIGNATURE_LENGTH = 64;
const MAX_KEY_ID = 0xffffffff;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isKeyId(value: unknown): value is number {
	return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= MAX_KEY_ID;
}

function isEntry(value: unknown): value is KeyconfigEntry {
	return isRecord(value) && isKeyId(value.key_id) && typeof value.public_key === 'string';
}

/** Builds the exact byte string the trust root signed. */
export function buildKeyconfigMessage(keys: KeyconfigEntry[]): Buffer {
	const sorted = [...keys].sort((a, b) => a.key_id - b.key_id);
	let message = KEYCONFIG_LABEL;
	for (const entry of sorted) message += `${entry.key_id}:${entry.public_key}\n`;
	return Buffer.from(message, 'utf8');
}

/**
 * Verifies the keyconfig signature. Returns false (never throws) on any failure: wrong sig_alg,
 * missing signature, malformed input, bad signature. `rootB64url` is injectable for tests.
 */
export function verifyKeyconfig(cfg: unknown, rootB64url: string = TRUST_ROOT_B64URL): boolean {
	if (!isRecord(cfg)) return false;
	if (cfg.sig_alg !== SIG_ALG) return false;
	if (typeof cfg.signature !== 'string' || cfg.signature.length === 0) return false;
	const keys = cfg.keys;
	if (!Array.isArray(keys) || keys.length === 0 || !keys.every(isEntry)) return false;
	try {
		const root = b64urlDecode(rootB64url);
		const signature = b64urlDecode(cfg.signature);
		if (root.length !== RAW_LENGTH || signature.length !== SIGNATURE_LENGTH) return false;
		const verifier = createPublicKey({
			key: Buffer.concat([ED25519_SPKI_PREFIX, root]),
			format: 'der',
			type: 'spki',
		});
		return ed25519Verify(null, buildKeyconfigMessage(keys), verifier, signature);
	} catch {
		return false;
	}
}

function badKeyconfig(reason: string): GatewayError {
	return new GatewayError(
		'hpke_bad_keyconfig',
		`The gateway's encryption key configuration is not usable (${reason})`,
	);
}

/**
 * Structural validation of an already-verified keyconfig. Returns the first key (the gateway's
 * current key, as the extension uses `keys[0]`). Throws GatewayError('hpke_bad_keyconfig') when
 * `keys` is empty, the suite is not EXPECTED_SUITE, the public key is not 32 bytes, or key_id is
 * not an integer in [0, 2^32-1].
 */
export function validateKeyconfig(cfg: Keyconfig): ValidatedKey {
	if (!isRecord(cfg) || !Array.isArray(cfg.keys) || cfg.keys.length === 0) {
		throw badKeyconfig('no keys');
	}
	const entry: unknown = cfg.keys[0];
	if (!isRecord(entry)) throw badKeyconfig('malformed key entry');
	if (!isKeyId(entry.key_id)) throw badKeyconfig('key_id out of range');

	const suite = entry.suite;
	if (
		!isRecord(suite) ||
		suite.kem !== EXPECTED_SUITE.kem ||
		suite.kdf !== EXPECTED_SUITE.kdf ||
		suite.aead !== EXPECTED_SUITE.aead
	) {
		throw badKeyconfig('unsupported HPKE suite');
	}

	if (typeof entry.public_key !== 'string') throw badKeyconfig('missing public key');
	let publicKey: Buffer | undefined;
	try {
		publicKey = b64urlDecode(entry.public_key);
	} catch {
		publicKey = undefined;
	}
	if (publicKey === undefined || publicKey.length !== RAW_LENGTH) {
		throw badKeyconfig('public key is not 32 bytes');
	}
	return { keyId: entry.key_id, publicKey };
}
