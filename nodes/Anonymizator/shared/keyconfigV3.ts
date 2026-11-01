/**
 * EXPERIMENTAL keyconfig v3 (gateway repository, docs/HPKE-V3-EXPERIMENTAL.md section 7): the
 * X-Wing keys of protocol v3, published as a SIBLING `v3` member of /v1/keyconfig and signed by the
 * same delegated key under the same delegation as `v2`. The v2 document and its verifier
 * (`keyconfig.ts`) are untouched: v2 never reads `v3`, and this file never reads `v2`.
 *
 *   pgw-keyconfig-v3
 *   version=3
 *   suite=25722,1,2
 *   issued_at=<uint>
 *   key=<key_id>,<b64 of exactly 1216 bytes>,<not_after>     (1 to 8 lines)
 *
 * The v2 encoding rules apply unchanged (raw bytes checked first, LF only, fixed order, full-match
 * numbers, canonical base64url). Every key's ML-KEM part must pass the FIPS 203 modulus check while
 * parsing, so a bad key never verifies. Failures: a missing or malformed `v3` member is
 * `hpke_pq_unavailable` (never a reason to use v2); everything else reuses the v2 codes.
 */
import {
	b64urlDecodeStrict,
	documentLines,
	ed25519Verify,
	lineValue,
	ownField,
	parseUint,
	strictB64,
	V2_LIMITS,
	verifyDelegationV2,
	type KeyconfigErrorCode,
} from './keyconfig';
import { MAX_KEY_ID } from './hpke';
import { MLKEM768_PUBLIC_LENGTH, mlkemPublicKeyValid, XWING_PUBLIC_LENGTH } from './hpkeV3';

/** Frozen v3 document header, signed by the delegated key. Never rename. */
export const KC_V3_DOCUMENT_HEADER = 'pgw-keyconfig-v3';

/** Protocol v3 keyconfig limits (frozen; the gateway uses the same values). */
export const V3_LIMITS = {
	/** Key lines a client accepts in one document. */
	MAX_KEYS: 8,
	/** Decoded document size cap, bytes. */
	MAX_DOCUMENT_BYTES: 16384,
	/** Characters of the base64url `keyconfig` field (the canonical length of 16 384 bytes). */
	MAX_DOCUMENT_B64: 21846,
} as const;

/** v3 verification failure codes: v2's, plus `hpke_pq_unavailable` for a missing `v3` member. */
export type KeyconfigV3ErrorCode = KeyconfigErrorCode | 'hpke_pq_unavailable';

/** One key line of a keyconfig v3 document. */
export type KeyconfigV3Key = {
	keyId: number;
	/** Raw 1216-byte X-Wing public key (pk_M || pk_X). */
	publicKey: Buffer;
	notAfter: number;
};

/** A verified keyconfig v3 with its selected key. */
export type VerifiedKeyconfigV3 = {
	ok: true;
	keyId: number;
	/** Raw 1216-byte X-Wing public key of the selected key. */
	publicKey: Buffer;
	issuedAt: number;
	/** The delegation serial (for the caller's serial floor, shared with v2). */
	serial: number;
	/** The selected key's signed expiry, unix seconds. */
	notAfter: number;
};

export type KeyconfigV3Verification =
	VerifiedKeyconfigV3 | { ok: false; error: KeyconfigV3ErrorCode };

// 1216 bytes are exactly 1622 canonical base64url characters.
const B64PQ_RE = /^[A-Za-z0-9_-]{1622}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Keyconfig v3 document -> {issuedAt, keys}, or null on any grammar or key-check violation. */
export function parseKeyconfigV3Document(
	bytes: Buffer,
): { issuedAt: number; keys: KeyconfigV3Key[] } | null {
	if (!Buffer.isBuffer(bytes) || bytes.length > V3_LIMITS.MAX_DOCUMENT_BYTES) return null;
	const lines = documentLines(bytes);
	if (!lines || lines.length < 5 || lines.length > 4 + V3_LIMITS.MAX_KEYS) return null;
	if (lines[0] !== KC_V3_DOCUMENT_HEADER) return null;
	if (lineValue(lines[1], 'version') !== '3') return null;
	if (lineValue(lines[2], 'suite') !== '25722,1,2') return null;
	const issuedAtRaw = lineValue(lines[3], 'issued_at');
	const issuedAt = issuedAtRaw === null ? null : parseUint(issuedAtRaw);
	if (issuedAt === null) return null;
	const keys: KeyconfigV3Key[] = [];
	for (const line of lines.slice(4)) {
		const value = lineValue(line, 'key');
		const parts = value === null ? [] : value.split(',');
		if (parts.length !== 3) return null;
		const keyId = parseUint(parts[0]);
		const publicKey = b64urlDecodeStrict(parts[1], B64PQ_RE, XWING_PUBLIC_LENGTH);
		const notAfter = parseUint(parts[2]);
		if (keyId === null || publicKey === null || notAfter === null) return null;
		if (keyId < 1 || keyId > MAX_KEY_ID || notAfter <= issuedAt) return null;
		// Strictly ascending key ids.
		if (keys.length > 0 && keyId <= keys[keys.length - 1].keyId) return null;
		// FIPS 203 encapsulation-key check on pk_M, at parse time (pk_X is not checked here).
		if (!mlkemPublicKeyValid(publicKey.subarray(0, MLKEM768_PUBLIC_LENGTH))) return null;
		keys.push({ keyId, publicKey, notAfter });
	}
	return { issuedAt, keys };
}

/**
 * Verifies the `v3` member of a /v1/keyconfig response (section 7.4, steps 1-11) and selects the
 * key: the highest key_id still valid for KEY_EXPIRY_MARGIN_S. Only the `v3` member is read; the
 * delegation is checked by the same `verifyDelegationV2` as v2. The delegation serial floor
 * (step 12) is the caller's, shared with v2.
 *
 * @param config parsed /v1/keyconfig JSON
 * @param pinnedRoots trusted root public keys (base64url); empty -> nothing verifies
 * @param nowSeconds client clock, unix seconds
 * @param expectedAudience lowercase host of the API base URL, no port
 */
export function verifyKeyconfigV3(
	config: unknown,
	pinnedRoots: readonly string[],
	nowSeconds: number,
	expectedAudience: string,
): KeyconfigV3Verification {
	const unverified: KeyconfigV3Verification = { ok: false, error: 'hpke_unverified_keyconfig' };
	// 1. The v3 member, a non-array object with its four strings; anything else means the gateway
	// does not offer v3. Never a reason to read v2.
	const v3 = isRecord(config) ? ownField(config, 'v3') : undefined;
	if (!isRecord(v3)) return { ok: false, error: 'hpke_pq_unavailable' };
	const delegation = ownField(v3, 'delegation');
	const delegationSig = ownField(v3, 'delegation_sig');
	const keyconfig = ownField(v3, 'keyconfig');
	const keyconfigSig = ownField(v3, 'keyconfig_sig');
	if (
		typeof delegation !== 'string' ||
		typeof delegationSig !== 'string' ||
		typeof keyconfig !== 'string' ||
		typeof keyconfigSig !== 'string'
	) {
		return { ok: false, error: 'hpke_pq_unavailable' };
	}
	const now = Number(nowSeconds);
	if (!Number.isFinite(now)) return unverified;
	// 2. Field lengths before decoding, then canonical base64url; signatures exactly 64 bytes.
	if (
		delegation.length > V2_LIMITS.MAX_DOCUMENT_B64 ||
		keyconfig.length > V3_LIMITS.MAX_DOCUMENT_B64
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
	if (keyconfigBytes.length > V3_LIMITS.MAX_DOCUMENT_BYTES) return unverified;
	// 3-7. The delegation, through the one shared helper.
	const delegationResult = verifyDelegationV2(
		delegationBytes,
		delegationSigBytes,
		pinnedRoots,
		now,
		expectedAudience,
	);
	if (!delegationResult.ok) return { ok: false, error: delegationResult.error };
	const d = delegationResult.delegation;
	// 8. Strict v3 grammar, with the modulus check on every key.
	const kc = parseKeyconfigV3Document(keyconfigBytes);
	if (!kc) return unverified;
	// 9. Delegated-key signature over the document bytes.
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
