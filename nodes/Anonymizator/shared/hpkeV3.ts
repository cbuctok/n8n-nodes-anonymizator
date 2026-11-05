/**
 * Post-quantum protocol v3 (gateway repository, docs/HPKE-V3-EXPERIMENTAL.md): RFC 9180 HPKE, base
 * mode, single shot, with the hybrid KEM X-Wing (X25519 + ML-KEM-768, KEM 0x647a), HKDF-SHA256 and
 * AES-256-GCM. Chosen per send by `gateway.ts` from the credential's Encryption setting: Automatic
 * uses it only with Node.js's native ML-KEM-768 (`nativeMlKemAvailable`) and a gateway that offers
 * v3; Always Post-Quantum (experimental) uses it always, with the vendored ML-KEM where Node.js has
 * none.
 *
 * v3 is v2 with another KEM. Everything else is v2's: the frame layout (with a 1120-byte `enc`),
 * the AAD (the 13-byte prefix), padding, and the response sealed with RFC 9458 section 4.4 keys,
 * here from `Export('pgw response v3', 32)` salted with the whole `enc` and a fresh response nonce.
 *
 * Request frame: 0x03 || key_id u32BE || unix seconds u64BE || enc(1120) || ct, at least 1149 bytes.
 * Response:      0x03 || response_nonce(32) || ct, at least 49 bytes.
 *
 * X-Wing (draft-connolly-cfrg-xwing-kem-11, section 5), with the X25519 half on node:crypto and the
 * ML-KEM-768 half from one of two backends (`MlKemBackend`):
 *   ek_X = eseed[32:64]; ct_X = X25519(ek_X, 9); ss_X = X25519(ek_X, pk_X)
 *   (ss_M, ct_M) = ML-KEM-768.Encaps_internal(pk_M, m = eseed[0:32])
 *   ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\"), enc = ct_M || ct_X
 * X-Wing's 32-byte output is HPKE's shared_secret as is: unlike DHKEM there is no
 * ExtractAndExpand inside the KEM.
 *
 * Backends:
 * - `native`: Node.js's own ML-KEM-768 (`crypto.encapsulate`, OpenSSL 3.5, Node.js 24.7.0 and
 *   later), found by a feature test, never by the version number. SHA3-256 from node:crypto too.
 *   OpenSSL draws `m` itself, so this is X-Wing `Encapsulate` (= EncapsulateDerand with a random
 *   `m`) and `eseed[0:32]` is unused; the bytes on the wire follow the same construction, and the
 *   tests check the native half against the official and shared vectors through decapsulation.
 * - `noble`: the vendored @noble ML-KEM-768 and SHA3-256 (`vendor/noblePq.ts`, not independently
 *   audited), EncapsulateDerand with `m = eseed[0:32]` passed explicitly, so its own random source
 *   (which throws in the vendored subset) is never reached. The only backend that reproduces the
 *   frame vectors byte for byte (a fixed `eseed`).
 *
 * Production randomness: `eseed` is 64 bytes from node:crypto.randomBytes. Intermediates are
 * zeroed after use on a best-effort basis.
 *
 * Leak rule: no key material, plaintext, frame bytes or `enc` in an error. Failures are fixed codes
 * (`hpke_seal_failed`, `hpke_bad_response`).
 */
import * as nodeCrypto from 'node:crypto';
import {
	createHash,
	createPublicKey,
	diffieHellman,
	randomBytes,
	type KeyObject,
} from 'node:crypto';

import {
	aeadOpen,
	aeadSeal,
	deriveResponseKeys,
	labeledExpand,
	labeledExtract,
	MAX_KEY_ID,
	padToBucket,
	privateFromRaw,
	publicFromRaw,
	rawPublic,
	REQUEST_PREFIX_LENGTH,
	RESPONSE_NONCE_LENGTH,
	type SealedRequest,
} from './hpke';
import { ml_kem768, sha3_256 } from './vendor/noblePq';

/** Wire format version byte of protocol v3, request and response. */
export const WIRE_VERSION_V3 = 0x03;

/** Frozen HPKE `info` of a v3 request, shared with the server. Never rename. */
export const REQUEST_INFO_V3 = 'pgw request v3';

/** Frozen exporter label of a v3 response, shared with the server. Never rename. */
export const RESPONSE_EXPORT_LABEL_V3 = 'pgw response v3';

/** HPKE KEM codepoint of X-Wing (MLKEM768-X25519 in draft-ietf-hpke-pq-05). */
export const XWING_KEM_ID = 0x647a;

/** X-Wing sizes: `enc` (ct_M || ct_X), the public key (pk_M || pk_X) and its ML-KEM part. */
export const XWING_ENC_LENGTH = 1120;
export const XWING_PUBLIC_LENGTH = 1216;
export const MLKEM768_PUBLIC_LENGTH = 1184;
const MLKEM768_CT_LENGTH = 1088;
const X25519_LENGTH = 32;
const ESEED_LENGTH = 64;

/** Shortest possible v3 frame: prefix, enc and a bare GCM tag. */
export const MIN_FRAME_LENGTH_V3 = REQUEST_PREFIX_LENGTH + XWING_ENC_LENGTH + 16;

/** Shortest possible v3 response: version, nonce and a bare GCM tag. */
export const MIN_RESPONSE_LENGTH_V3 = 1 + RESPONSE_NONCE_LENGTH + 16;

// suite_id = "HPKE" || kem 0x647a || kdf 0x0001 || aead 0x0002
const SUITE_ID_V3 = Buffer.from([0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x02]);
// XWingLabel, the 6 ASCII bytes \./ /^\
const XWING_LABEL = Buffer.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
// FIPS 203 modulus.
const MLKEM_Q = 3329;
const NK = 32;
const NN = 12;
const NH = 32;
const EMPTY = Buffer.alloc(0);

/**
 * FIPS 203 section 7.2 encapsulation-key modulus check on an ML-KEM-768 public key `pk_M`
 * (1184 bytes): the first 1152 bytes are 768 coefficients of 12 bits each, and every one must be
 * below q = 3329. Our own helper (not the vendored internals), used by the keyconfig v3 parser on
 * every key line and again before encapsulation.
 */
export function mlkemPublicKeyValid(pkM: Buffer | Uint8Array): boolean {
	if (pkM.length !== MLKEM768_PUBLIC_LENGTH) return false;
	for (let i = 0; i < 1152; i += 3) {
		const b0 = pkM[i];
		const b1 = pkM[i + 1];
		const b2 = pkM[i + 2];
		const c0 = b0 | ((b1 & 0x0f) << 8);
		const c1 = (b1 >> 4) | (b2 << 4);
		if (c0 >= MLKEM_Q || c1 >= MLKEM_Q) return false;
	}
	return true;
}

/** Which ML-KEM-768 implementation an X-Wing encapsulation used. */
export type MlKemBackend = 'native' | 'noble';

// SubjectPublicKeyInfo DER prefix of an ML-KEM-768 public key (OID 2.16.840.1.101.3.4.4.2, RFC
// 9935 / draft-ietf-lamps-kyber-certificates): SEQUENCE { SEQUENCE { OID }, BIT STRING (1185) }.
// Checked against Node.js's own export of a generated key in the tests.
const MLKEM768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');

/**
 * The node:crypto KEM functions that `@types/node` 18 (this package's typings) does not declare.
 * Node.js 24.7.0 and later have them for 'ml-kem-768'; older versions have neither.
 */
type NativeKem = {
	encapsulate?: (key: KeyObject) => { sharedKey: Buffer; ciphertext: Buffer };
	decapsulate?: (key: KeyObject, ciphertext: Buffer) => Buffer;
	generateKeyPairSync: (type: string) => { publicKey: KeyObject; privateKey: KeyObject };
};

let nativeMlKem: boolean | undefined;

/**
 * Whether this Node.js has a working native ML-KEM-768 (feature test, run once per process): the
 * KEM functions exist, a generated key pair round-trips, and a public key imports from its SPKI
 * form as `encapsulateNative` does it. Any exception means no. Never sniffs `process.version`.
 */
export function nativeMlKemAvailable(): boolean {
	if (nativeMlKem === undefined) nativeMlKem = probeNativeMlKem();
	return nativeMlKem;
}

function probeNativeMlKem(): boolean {
	const kem = nodeCrypto as unknown as NativeKem;
	if (typeof kem.encapsulate !== 'function' || typeof kem.decapsulate !== 'function') return false;
	try {
		const { publicKey, privateKey } = kem.generateKeyPairSync('ml-kem-768');
		const spki = publicKey.export({ type: 'spki', format: 'der' });
		if (
			spki.length !== MLKEM768_SPKI_PREFIX.length + MLKEM768_PUBLIC_LENGTH ||
			!spki.subarray(0, MLKEM768_SPKI_PREFIX.length).equals(MLKEM768_SPKI_PREFIX)
		) {
			return false;
		}
		const encapsulated = encapsulateNative(spki.subarray(MLKEM768_SPKI_PREFIX.length));
		const shared = kem.decapsulate(privateKey, Buffer.from(encapsulated.cipherText));
		const ok =
			encapsulated.cipherText.length === MLKEM768_CT_LENGTH &&
			encapsulated.sharedSecret.length === NH &&
			Buffer.from(encapsulated.sharedSecret).equals(shared);
		shared.fill(0);
		encapsulated.sharedSecret.fill(0);
		return ok;
	} catch {
		return false;
	}
}

/** ML-KEM-768 encapsulation to `pkM` (1184 bytes) with Node.js's native implementation. */
function encapsulateNative(pkM: Buffer | Uint8Array): {
	cipherText: Uint8Array;
	sharedSecret: Uint8Array;
} {
	const kem = nodeCrypto as unknown as NativeKem;
	if (typeof kem.encapsulate !== 'function') throw new Error('hpke_seal_failed');
	const key = createPublicKey({
		key: Buffer.concat([MLKEM768_SPKI_PREFIX, pkM]),
		format: 'der',
		type: 'spki',
	});
	const { sharedKey, ciphertext } = kem.encapsulate(key);
	return { cipherText: ciphertext, sharedSecret: sharedKey };
}

/** Result of `xwingEncapsulate`. The caller zeroes `sharedSecret` after use. */
export type XWingEncapsulation = { sharedSecret: Buffer; enc: Buffer };

/**
 * X-Wing EncapsulateDerand(pk, eseed) (draft-11 section 5.4). `eseed` is 64 bytes: `m` (32) for
 * ML-KEM and `ek_X` (32) for X25519. With the `native` backend, ML-KEM draws its own `m` inside
 * OpenSSL and `eseed[0:32]` is ignored (X-Wing `Encapsulate`); the X25519 half and the combiner
 * are the same code for both. Throws `Error('hpke_seal_failed')` on a wrong length, a public key
 * that fails the modulus check, an all-zero X25519 output (a low-order `pk_X`), a `native` backend
 * this Node.js does not have, or any library failure. Does not zero `eseed`; the caller owns it.
 */
export function xwingEncapsulate(
	pk: Buffer,
	eseed: Buffer,
	backend: MlKemBackend = 'noble',
): XWingEncapsulation {
	if (backend !== 'noble' && (backend !== 'native' || !nativeMlKemAvailable())) {
		throw new Error('hpke_seal_failed');
	}
	if (!Buffer.isBuffer(pk) || pk.length !== XWING_PUBLIC_LENGTH)
		throw new Error('hpke_seal_failed');
	if (!Buffer.isBuffer(eseed) || eseed.length !== ESEED_LENGTH) throw new Error('hpke_seal_failed');
	const pkM = pk.subarray(0, MLKEM768_PUBLIC_LENGTH);
	const pkX = pk.subarray(MLKEM768_PUBLIC_LENGTH);
	if (!mlkemPublicKeyValid(pkM)) throw new Error('hpke_seal_failed');

	const m = Buffer.from(eseed.subarray(0, 32));
	const ekX = Buffer.from(eseed.subarray(32, 64));
	let ssX: Buffer | undefined;
	let ctX: Buffer | undefined;
	let ssM: Uint8Array | undefined;
	let ctM: Uint8Array | undefined;
	let failed = false;
	try {
		const ekXKey = privateFromRaw(ekX);
		ctX = rawPublic(createPublicKey(ekXKey));
		ssX = diffieHellman({ privateKey: ekXKey, publicKey: publicFromRaw(Buffer.from(pkX)) });
		// noble: the derandomized form, `m` given explicitly, so the vendored random source is
		// unused. native: OpenSSL draws `m` from its own CSPRNG.
		const encapsulated =
			backend === 'native'
				? encapsulateNative(pkM)
				: (ml_kem768.encapsulate(Uint8Array.from(pkM), Uint8Array.from(m)) as {
						cipherText: Uint8Array;
						sharedSecret: Uint8Array;
					});
		ctM = encapsulated.cipherText;
		ssM = encapsulated.sharedSecret;
	} catch {
		failed = true;
	} finally {
		m.fill(0);
		ekX.fill(0);
	}
	if (
		failed ||
		!ssX ||
		!ctX ||
		!ssM ||
		!ctM ||
		ssX.length !== X25519_LENGTH ||
		ctX.length !== X25519_LENGTH ||
		ssM.length !== NH ||
		ctM.length !== MLKEM768_CT_LENGTH ||
		ssX.every((b) => b === 0)
	) {
		ssX?.fill(0);
		ssM?.fill(0);
		throw new Error('hpke_seal_failed');
	}
	const combined = Buffer.concat([ssM, ssX, ctX, pkX, XWING_LABEL]);
	// SHA3-256 from OpenSSL with the native backend, so it uses no vendored code at all.
	const sharedSecret =
		backend === 'native'
			? createHash('sha3-256').update(combined).digest()
			: Buffer.from(sha3_256(Uint8Array.from(combined)) as Uint8Array);
	combined.fill(0);
	ssM.fill(0);
	ssX.fill(0);
	return { sharedSecret, enc: Buffer.concat([ctM, ctX]) };
}

/** The base-mode key schedule values for one context (RFC 9180 section 5.1, mode_base). */
export type KeyScheduleV3 = {
	pskIdHash: Buffer;
	infoHash: Buffer;
	secret: Buffer;
	key: Buffer;
	baseNonce: Buffer;
	exporterSecret: Buffer;
};

/**
 * RFC 9180 KeySchedule for this one suite, base mode, default (empty) PSK. `suiteId` exists only
 * for the draft-ietf-hpke-pq-05 A.5 vector (AEAD 3), whose suite_id differs in the last byte.
 */
export function keyScheduleV3(
	sharedSecret: Buffer,
	info: Buffer,
	suiteId: Buffer = SUITE_ID_V3,
): KeyScheduleV3 {
	const pskIdHash = labeledExtract(suiteId, EMPTY, 'psk_id_hash', EMPTY);
	const infoHash = labeledExtract(suiteId, EMPTY, 'info_hash', info);
	const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
	const secret = labeledExtract(suiteId, sharedSecret, 'secret', EMPTY);
	return {
		pskIdHash,
		infoHash,
		secret,
		key: labeledExpand(suiteId, secret, 'key', context, NK),
		baseNonce: labeledExpand(suiteId, secret, 'base_nonce', context, NN),
		exporterSecret: labeledExpand(suiteId, secret, 'exp', context, NH),
	};
}

/** RFC 9180 Export(exporter_context, L) = LabeledExpand(exporter_secret, "sec", context, L). */
export function exportV3(
	exporterSecret: Buffer,
	exporterContext: string | Buffer,
	length: number,
	suiteId: Buffer = SUITE_ID_V3,
): Buffer {
	const context =
		typeof exporterContext === 'string' ? Buffer.from(exporterContext, 'utf8') : exporterContext;
	return labeledExpand(suiteId, exporterSecret, 'sec', context, length);
}

/** The 13-byte v3 frame prefix (also the AAD): 0x03 || key_id || timestamp. */
export function framePrefixV3(keyId: number, nowSeconds?: number): Buffer {
	const seconds = Math.floor(nowSeconds !== undefined ? nowSeconds : Date.now() / 1000);
	const prefix = Buffer.alloc(REQUEST_PREFIX_LENGTH);
	prefix.writeUInt8(WIRE_VERSION_V3, 0);
	prefix.writeUInt32BE(keyId >>> 0, 1);
	prefix.writeBigUInt64BE(BigInt(seconds), 5);
	return prefix;
}

/**
 * Seals `payload` (JSON-serialised, padded to the v2 buckets) for the v3 gateway key
 * `keyId` / `pkR` (1216 bytes) and returns the frame plus the opener of its response. Every HTTP
 * attempt needs a fresh seal (the gateway refuses a resent frame with `hpke_replay`).
 *
 * `backend` picks the ML-KEM-768 implementation (`native` only where `nativeMlKemAvailable()`).
 * `testEseed` (64 bytes) is for the test vectors only: reusing it with `noble` reuses the AES-GCM
 * key and nonce (with `native` only the X25519 half is fixed, the ML-KEM half stays random).
 * Throws `Error('hpke_seal_failed')` on an invalid key, key id or any encapsulation failure.
 */
export function sealRequestV3(
	pkR: Buffer,
	keyId: number,
	payload: unknown,
	nowSeconds?: number,
	testEseed?: Buffer,
	backend: MlKemBackend = 'noble',
): SealedRequest {
	if (!Buffer.isBuffer(pkR) || pkR.length !== XWING_PUBLIC_LENGTH) {
		throw new Error('hpke_seal_failed');
	}
	if (!Number.isInteger(keyId) || keyId < 1 || keyId > MAX_KEY_ID) {
		throw new Error('hpke_seal_failed');
	}
	if (
		testEseed !== undefined &&
		(!Buffer.isBuffer(testEseed) || testEseed.length !== ESEED_LENGTH)
	) {
		throw new Error('hpke_seal_failed');
	}
	const eseed = testEseed !== undefined ? Buffer.from(testEseed) : randomBytes(ESEED_LENGTH);
	let encapsulated: XWingEncapsulation;
	try {
		encapsulated = xwingEncapsulate(pkR, eseed, backend);
	} finally {
		eseed.fill(0);
	}
	const prefix = framePrefixV3(keyId, nowSeconds);
	const pt = Buffer.from(padToBucket(JSON.stringify(payload)), 'utf8');
	const schedule = keyScheduleV3(encapsulated.sharedSecret, Buffer.from(REQUEST_INFO_V3, 'utf8'));
	encapsulated.sharedSecret.fill(0);
	const ct = aeadSeal(schedule.key, schedule.baseNonce, prefix, pt);
	pt.fill(0);
	schedule.secret.fill(0);
	schedule.key.fill(0);
	schedule.baseNonce.fill(0);
	const exporterSecret = schedule.exporterSecret;
	const enc = Buffer.from(encapsulated.enc);
	const body: Buffer = Buffer.concat([prefix, enc, ct]);
	let opened = false;

	return {
		body,
		openResponse(bytes: Buffer): unknown {
			// Only a v3 body answers a v3 request, and each request is answered at most once.
			if (
				opened ||
				!Buffer.isBuffer(bytes) ||
				bytes.length < MIN_RESPONSE_LENGTH_V3 ||
				bytes[0] !== WIRE_VERSION_V3
			) {
				throw new Error('hpke_bad_response');
			}
			const secret = exportV3(exporterSecret, RESPONSE_EXPORT_LABEL_V3, NH);
			// The full 1152-byte salt: HMAC hashes a key longer than its block itself (RFC 2104).
			const { prk, key, nonce } = deriveResponseKeys(
				secret,
				enc,
				bytes.subarray(1, 1 + RESPONSE_NONCE_LENGTH),
			);
			let plaintext: Buffer | undefined;
			try {
				plaintext = aeadOpen(key, nonce, EMPTY, bytes.subarray(1 + RESPONSE_NONCE_LENGTH));
			} catch {
				plaintext = undefined;
			} finally {
				secret.fill(0);
				prk.fill(0);
				key.fill(0);
				nonce.fill(0);
			}
			if (plaintext === undefined) throw new Error('hpke_bad_response');
			opened = true;
			exporterSecret.fill(0);
			const parsed: unknown = JSON.parse(plaintext.toString('utf8').trimEnd());
			plaintext.fill(0);
			return parsed;
		},
	};
}
