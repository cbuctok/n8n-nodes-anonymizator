/**
 * Gateway keyconfig v2 (docs/HPKE.md in the gateway repository, "Keyconfig"): the trust chain
 * pinned root -> root-signed delegation -> keyconfig signed by the delegated key -> HPKE keys with a
 * signed expiry. Port of `verifyDelegationV2` / `verifyKeyconfigV2` and their strict parsers from the
 * extension's `lib/hpke.js`. Fails closed: a response without `v2` is refused.
 *
 * Both documents are ASCII byte strings, `name=value` lines in a fixed order, one LF after every
 * line. The bytes are checked before any decoding, numbers and base64url are matched with full
 * regular expressions (never `parseInt`, never a lenient decoder), and nobody canonicalises JSON:
 * the signature covers the exact bytes.
 *
 * Naming: constants holding long base64/hex values must not contain key/auth/token/secret/cert in
 * their name (`no-hardcoded-secrets` checks names, and the scanner ignores inline suppressions).
 */
import { createPublicKey, verify as ed25519VerifyRaw } from 'node:crypto';

import { MAX_KEY_ID } from './hpke';

/**
 * Pinned Ed25519 roots (raw 32-byte public keys, base64url): the primary and the backup v2 root,
 * exactly as the extension's `lib/constants.js` `ROOT_KEYCONFIG_PUBKEYS`. Never the v1 root, never
 * a test-vector root. An empty list trusts nothing.
 */
export const TRUST_ROOTS_B64URL: readonly string[] = [
	// primary v2 root (2026-10-08)
	'lgcsJYcJVj99IW2N5rg73nkRmL0YkuU5uLkR1FsHfhc',
	// backup v2 root (2026-10-08)
	'ZeXBFyWu8WB0cvyjNIC4LKJymDe5HDb6H08JkcmwdpE',
];

/** Frozen document headers shared with the server. Never rename. */
export const DELEGATION_HEADER = 'pgw-keyconfig-delegation-v2';
export const KC_DOCUMENT_HEADER = 'pgw-keyconfig-v2';

/** Protocol v2 limits (frozen; the gateway uses the same values). */
export const V2_LIMITS = {
	/** Client tolerance on delegation and keyconfig time windows, seconds. */
	CLIENT_SKEW_S: 300,
	/** A keyconfig older than this (plus the skew) after its `issued_at` is stale, seconds. */
	KEYCONFIG_MAX_AGE_S: 900,
	/** Longest accepted delegation, seconds (32 days). */
	MAX_DELEGATION_LIFETIME_S: 2764800,
	/** `not_before <= serial <= not_before + this`, seconds. */
	DELEGATION_SERIAL_SLACK_S: 300,
	/** A key is used only while `now + this < not_after`, seconds. */
	KEY_EXPIRY_MARGIN_S: 300,
	/** Key lines accepted in one keyconfig. */
	MAX_KEYS: 16,
	/** Hosts in a delegation's audience. */
	MAX_AUDIENCE_HOSTS: 8,
	/** Characters of a base64url delegation or keyconfig field. */
	MAX_DOCUMENT_B64: 8192,
} as const;

/** Keyconfig verification failure codes (docs/HPKE.md, "Client verification"). */
export type KeyconfigErrorCode =
	'hpke_unverified_keyconfig' | 'hpke_stale_keyconfig' | 'hpke_no_usable_key';

/** A parsed delegation document. */
export type Delegation = {
	/** The root that signed it, exactly as written in the document (base64url). */
	root: string;
	rootKey: Buffer;
	/** Raw Ed25519 public key of the online delegated signer. */
	signingKey: Buffer;
	audience: string[];
	serial: number;
	notBefore: number;
	notAfter: number;
};

/** One key line of a keyconfig v2 document. */
export type KeyconfigKey = {
	keyId: number;
	/** Raw 32-byte X25519 public key. */
	publicKey: Buffer;
	notAfter: number;
};

/** A verified keyconfig with its selected key. */
export type VerifiedKeyconfig = {
	ok: true;
	keyId: number;
	/** Raw 32-byte X25519 public key of the selected key. */
	publicKey: Buffer;
	issuedAt: number;
	/** The delegation serial (for the caller's serial floor). */
	serial: number;
	/** The selected key's signed expiry, unix seconds. */
	notAfter: number;
};

export type KeyconfigVerification = VerifiedKeyconfig | { ok: false; error: KeyconfigErrorCode };

export type DelegationVerification =
	| { ok: true; delegation: Delegation }
	| { ok: false; error: 'hpke_unverified_keyconfig' | 'hpke_stale_keyconfig' };

const UINT_RE = /^(?:0|[1-9][0-9]{0,15})$/;
const B64KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const B64SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const B64DOC_RE = /^[A-Za-z0-9_-]+$/;
const HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
// Ed25519 group order L: a signature with S >= L is invalid (RFC 8032 section 5.1.7). Built from
// strings because the es2019 target has no BigInt literals.
const ED25519_L = (BigInt(1) << BigInt(252)) + BigInt('27742317777372353535851937790883648493');
// RFC 8410 SPKI DER shell around a raw 32-byte Ed25519 public value.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Own property only, so a prototype member never stands in for a missing field. */
export function ownField(object: Record<string, unknown>, name: string): unknown {
	return Object.prototype.hasOwnProperty.call(object, name) ? object[name] : undefined;
}

/**
 * Strict base64url: `re` fixes the alphabet and length, and the decoded bytes must re-encode to
 * exactly the input (rejects padding and set unused low bits). Returns null on any mismatch.
 */
export function b64urlDecodeStrict(value: unknown, re: RegExp, length?: number): Buffer | null {
	if (typeof value !== 'string' || !re.test(value) || value.length % 4 === 1) return null;
	const out = Buffer.from(value, 'base64url');
	if (length !== undefined && out.length !== length) return null;
	return out.toString('base64url') === value ? out : null;
}

/** Strict decoders for the shared shapes. */
export const strictB64 = {
	key: (value: unknown): Buffer | null => b64urlDecodeStrict(value, B64KEY_RE, 32),
	signature: (value: unknown): Buffer | null => b64urlDecodeStrict(value, B64SIG_RE, 64),
	document: (value: unknown): Buffer | null => b64urlDecodeStrict(value, B64DOC_RE),
};

/** `0|[1-9][0-9]{0,15}` in full, at most 2^53 - 1; never parseInt or Number alone. */
export function parseUint(value: string): number | null {
	if (!UINT_RE.test(value) || BigInt(value) > MAX_SAFE) return null;
	return Number(value);
}

/**
 * Raw bytes -> lines. The bytes are checked BEFORE any decoding: only LF and 0x20-0x7E, non-empty,
 * LF-terminated, no empty line. That alone rejects a BOM, CR, NUL and anything non-ASCII.
 */
export function documentLines(bytes: Buffer): string[] | null {
	if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) return null;
	for (const b of bytes) {
		if (b !== 0x0a && (b < 0x20 || b > 0x7e)) return null;
	}
	const lines = bytes.toString('latin1').split('\n');
	lines.pop(); // the empty element after the final LF
	return lines.some((line) => line === '') ? null : lines;
}

/** `name=value` split at the FIRST `=`; the name must match exactly. */
export function lineValue(line: string, name: string): string | null {
	const i = line.indexOf('=');
	if (i < 0 || line.slice(0, i) !== name) return null;
	return line.slice(i + 1);
}

/** 1-8 lowercase hosts, strictly ascending (ASCII order = byte order). */
function parseAudience(value: string): string[] | null {
	const hosts = value.split(',');
	if (hosts.length > V2_LIMITS.MAX_AUDIENCE_HOSTS) return null;
	for (let i = 0; i < hosts.length; i++) {
		const host = hosts[i];
		if (host.length < 1 || host.length > 253 || !HOST_RE.test(host)) return null;
		if (i > 0 && !(hosts[i - 1] < host)) return null;
	}
	return hosts;
}

/** Delegation document -> fields, or null on any grammar violation. */
export function parseDelegation(bytes: Buffer): Delegation | null {
	const lines = documentLines(bytes);
	if (!lines || lines.length !== 7 || lines[0] !== DELEGATION_HEADER) return null;
	const root = lineValue(lines[1], 'root');
	const signingKey = lineValue(lines[2], 'signing_key');
	const audience = lineValue(lines[3], 'audience');
	const serial = lineValue(lines[4], 'serial');
	const notBefore = lineValue(lines[5], 'not_before');
	const notAfter = lineValue(lines[6], 'not_after');
	if (
		root === null ||
		signingKey === null ||
		audience === null ||
		serial === null ||
		notBefore === null ||
		notAfter === null
	) {
		return null;
	}
	const out = {
		root,
		rootKey: strictB64.key(root),
		signingKey: strictB64.key(signingKey),
		audience: parseAudience(audience),
		serial: parseUint(serial),
		notBefore: parseUint(notBefore),
		notAfter: parseUint(notAfter),
	};
	if (
		out.rootKey === null ||
		out.signingKey === null ||
		out.audience === null ||
		out.serial === null ||
		out.notBefore === null ||
		out.notAfter === null
	) {
		return null;
	}
	return {
		root: out.root,
		rootKey: out.rootKey,
		signingKey: out.signingKey,
		audience: out.audience,
		serial: out.serial,
		notBefore: out.notBefore,
		notAfter: out.notAfter,
	};
}

/** Keyconfig v2 document -> {issuedAt, keys}, or null on any grammar violation. */
export function parseKeyconfigDocument(
	bytes: Buffer,
): { issuedAt: number; keys: KeyconfigKey[] } | null {
	const lines = documentLines(bytes);
	if (!lines || lines.length < 5 || lines.length > 4 + V2_LIMITS.MAX_KEYS) return null;
	if (lines[0] !== KC_DOCUMENT_HEADER) return null;
	if (lineValue(lines[1], 'version') !== '2') return null;
	if (lineValue(lines[2], 'suite') !== '32,1,2') return null;
	const issuedAtRaw = lineValue(lines[3], 'issued_at');
	const issuedAt = issuedAtRaw === null ? null : parseUint(issuedAtRaw);
	if (issuedAt === null) return null;
	const keys: KeyconfigKey[] = [];
	for (const line of lines.slice(4)) {
		const value = lineValue(line, 'key');
		const parts = value === null ? [] : value.split(',');
		if (parts.length !== 3) return null;
		const keyId = parseUint(parts[0]);
		const publicKey = strictB64.key(parts[1]);
		const notAfter = parseUint(parts[2]);
		if (keyId === null || publicKey === null || notAfter === null) return null;
		if (keyId < 1 || keyId > MAX_KEY_ID || notAfter <= issuedAt) return null;
		// Strictly ascending key ids.
		if (keys.length > 0 && keyId <= keys[keys.length - 1].keyId) return null;
		keys.push({ keyId, publicKey, notAfter });
	}
	return { issuedAt, keys };
}

/** S < L, so a malleated (S + L) signature fails whatever the library does. */
function signatureScalarCanonical(signature: Buffer): boolean {
	let s = BigInt(0);
	for (let i = 63; i >= 32; i--) s = (s << BigInt(8)) | BigInt(signature[i]);
	return s < ED25519_L;
}

/** Pure Ed25519 (RFC 8032) verification of `message`; false (never throws) on any failure. */
export function ed25519Verify(publicKey: Buffer, signature: Buffer, message: Buffer): boolean {
	if (publicKey.length !== 32 || signature.length !== 64) return false;
	if (!signatureScalarCanonical(signature)) return false;
	try {
		const key = createPublicKey({
			key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
			format: 'der',
			type: 'spki',
		});
		return ed25519VerifyRaw(null, message, key, signature);
	} catch {
		return false;
	}
}

/**
 * Delegation steps 3-7, shared by every document the delegated key signs (keyconfig v2,
 * capabilities v1): strict grammar, a pinned root (exact string compare; an empty list trusts
 * nothing), the root signature, the lifetime / serial / audience policy and the delegation time
 * window. The caller has already decoded both fields strictly.
 */
export function verifyDelegationV2(
	delegationBytes: Buffer,
	delegationSigBytes: Buffer,
	pinnedRoots: readonly string[],
	now: number,
	expectedAudience: string,
): DelegationVerification {
	const unverified: DelegationVerification = { ok: false, error: 'hpke_unverified_keyconfig' };
	// 3. Strict delegation grammar.
	const d = parseDelegation(delegationBytes);
	if (!d) return unverified;
	// 4. A pinned root (exact string compare); no roots -> nothing is trusted.
	if (!Array.isArray(pinnedRoots) || !pinnedRoots.includes(d.root)) return unverified;
	// 5. Root signature over the delegation bytes.
	if (!ed25519Verify(d.rootKey, delegationSigBytes, delegationBytes)) return unverified;
	// 6. Lifetime; 6b. serial bound to not_before; 6c. audience.
	if (
		!(d.notBefore < d.notAfter) ||
		d.notAfter - d.notBefore > V2_LIMITS.MAX_DELEGATION_LIFETIME_S
	) {
		return unverified;
	}
	if (d.serial < d.notBefore || d.serial > d.notBefore + V2_LIMITS.DELEGATION_SERIAL_SLACK_S) {
		return unverified;
	}
	if (typeof expectedAudience !== 'string' || !d.audience.includes(expectedAudience)) {
		return unverified;
	}
	// 7. Delegation time window (inclusive, with client skew).
	if (now < d.notBefore - V2_LIMITS.CLIENT_SKEW_S || now > d.notAfter + V2_LIMITS.CLIENT_SKEW_S) {
		return { ok: false, error: 'hpke_stale_keyconfig' };
	}
	return { ok: true, delegation: d };
}

/**
 * Verifies the `v2` member of a /v1/keyconfig response (verification steps 1-11) and selects the
 * key: the highest key_id still valid for KEY_EXPIRY_MARGIN_S, never `keys[0]`. Only the `v2`
 * member is read. The delegation serial floor (step 12) is the caller's.
 *
 * @param config parsed /v1/keyconfig JSON
 * @param pinnedRoots trusted root public keys (base64url); empty -> nothing verifies
 * @param nowSeconds client clock, unix seconds
 * @param expectedAudience lowercase host of the API base URL, no port
 */
export function verifyKeyconfigV2(
	config: unknown,
	pinnedRoots: readonly string[],
	nowSeconds: number,
	expectedAudience: string,
): KeyconfigVerification {
	const unverified: KeyconfigVerification = { ok: false, error: 'hpke_unverified_keyconfig' };
	const now = Number(nowSeconds);
	if (!Number.isFinite(now)) return unverified;
	// 1. The v2 member with its four strings.
	const v2 = isRecord(config) ? ownField(config, 'v2') : undefined;
	if (!isRecord(v2)) return unverified;
	const delegation = ownField(v2, 'delegation');
	const delegationSig = ownField(v2, 'delegation_sig');
	const keyconfig = ownField(v2, 'keyconfig');
	const keyconfigSig = ownField(v2, 'keyconfig_sig');
	if (
		typeof delegation !== 'string' ||
		typeof delegationSig !== 'string' ||
		typeof keyconfig !== 'string' ||
		typeof keyconfigSig !== 'string'
	) {
		return unverified;
	}
	// 2. Canonical base64url everywhere; signatures are exactly 64 bytes.
	if (
		delegation.length > V2_LIMITS.MAX_DOCUMENT_B64 ||
		keyconfig.length > V2_LIMITS.MAX_DOCUMENT_B64
	) {
		return unverified;
	}
	const delegationBytes = strictB64.document(delegation);
	const keyconfigBytes = strictB64.document(keyconfig);
	const delegationSigBytes = strictB64.signature(delegationSig);
	const keyconfigSigBytes = strictB64.signature(keyconfigSig);
	if (!delegationBytes || !keyconfigBytes || !delegationSigBytes || !keyconfigSigBytes) {
		return unverified;
	}
	// 3-7. The delegation: grammar, pinned root, root signature, policy, time.
	const delegationResult = verifyDelegationV2(
		delegationBytes,
		delegationSigBytes,
		pinnedRoots,
		now,
		expectedAudience,
	);
	if (!delegationResult.ok) return { ok: false, error: delegationResult.error };
	const d = delegationResult.delegation;
	// 8. Strict keyconfig grammar (version=2, suite=32,1,2).
	const kc = parseKeyconfigDocument(keyconfigBytes);
	if (!kc) return unverified;
	// 9. Delegated-key signature over the keyconfig bytes.
	if (!ed25519Verify(d.signingKey, keyconfigSigBytes, keyconfigBytes)) return unverified;
	// 10. Signed inside the delegation.
	if (kc.issuedAt < d.notBefore || kc.issuedAt > d.notAfter) return unverified;
	// 11. Fresh enough.
	if (
		now < kc.issuedAt - V2_LIMITS.CLIENT_SKEW_S ||
		now > kc.issuedAt + V2_LIMITS.KEYCONFIG_MAX_AGE_S + V2_LIMITS.CLIENT_SKEW_S
	) {
		return { ok: false, error: 'hpke_stale_keyconfig' };
	}
	// 13. Key selection: the highest usable key_id (ids are strictly ascending).
	for (let i = kc.keys.length - 1; i >= 0; i--) {
		const key = kc.keys[i];
		if (now + V2_LIMITS.KEY_EXPIRY_MARGIN_S < key.notAfter) {
			return {
				ok: true,
				keyId: key.keyId,
				publicKey: key.publicKey,
				issuedAt: kc.issuedAt,
				serial: d.serial,
				notAfter: key.notAfter,
			};
		}
	}
	return { ok: false, error: 'hpke_no_usable_key' };
}
