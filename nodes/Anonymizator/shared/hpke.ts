/**
 * RFC 9180 HPKE (Base mode, single shot) and the gateway wire frame.
 *
 * Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM. Port of the extension's
 * `lib/hpke.js` using classic synchronous `node:crypto` (critique R1). There is deliberately no
 * suite negotiation.
 *
 * Request frame: 0x01 || key_id u32BE || unix seconds u64BE || enc(32) || ct, AAD = 13-byte prefix,
 * plaintext = JSON padded with spaces to a UTF-8 size bucket. Response: 0x01 || ct, key||nonce =
 * export('pgw response v1', 44), empty AAD.
 */
import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	type KeyObject,
} from 'node:crypto';

/** Frozen exporter label shared with the server. Never rename. */
export const RESPONSE_EXPORT_LABEL = 'pgw response v1';

/** Plaintext size buckets in UTF-8 bytes; beyond the last, round up to a multiple of 4096. */
export const PAD_BUCKETS: readonly number[] = [256, 1024, 4096, 16384, 65536];

/** Wire format version byte for both request and response frames. */
export const WIRE_VERSION = 0x01;

/** Length of the request prefix (version, key_id, timestamp) that is also the AAD. */
export const REQUEST_PREFIX_LENGTH = 13;

// suite_id = "HPKE" || kem(2) || kdf(2) || aead(2); kem_suite_id = "KEM" || kem(2)
const SUITE_ID = Buffer.from([0x48, 0x50, 0x4b, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02]);
const KEM_SUITE_ID = Buffer.from([0x4b, 0x45, 0x4d, 0x00, 0x20]);
const HPKE_V1 = Buffer.from('HPKE-v1', 'utf8');
const NK = 32;
const NN = 12;
const NH = 32;
const TAG_LENGTH = 16;
const X25519_LENGTH = 32;
// RFC 8410 DER shells around a raw 32-byte X25519 scalar / public value.
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const EMPTY = Buffer.alloc(0);

/** Deterministic ephemeral key pair, for the RFC 9180 test vector only. */
export interface TestEphemeral {
	sk: Buffer;
	pkE: Buffer;
}

export type HpkeSealResult = {
	/** Encapsulated ephemeral public key, 32 bytes. */
	enc: Buffer;
	/** Ciphertext with the 16-byte GCM tag appended. */
	ct: Buffer;
	/** RFC 9180 secret export from this context. */
	exportSecret: (exporterContext: string | Buffer, length: number) => Buffer;
};

export type SealedRequest = {
	/** The complete binary request body. Always a Buffer (never a Uint8Array view). */
	body: Buffer;
	/** Opens a `0x01 || ct` response sealed for this request; returns the parsed JSON. Throws on failure. */
	openResponse: (bytes: Buffer) => unknown;
};

/**
 * HMAC-SHA256. An empty key becomes HashLen zero bytes (RFC 5869: an absent salt is HashLen zeros),
 * which keeps the output identical to the extension's WebCrypto implementation.
 */
function hmac(key: Buffer, data: Buffer): Buffer {
	return createHmac('sha256', key.length > 0 ? key : Buffer.alloc(NH))
		.update(data)
		.digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
	const out = Buffer.alloc(length);
	let t: Buffer = EMPTY;
	let done = 0;
	for (let i = 1; done < length; i++) {
		t = hmac(prk, Buffer.concat([t, info, Buffer.from([i])]));
		t.copy(out, done, 0, Math.min(t.length, length - done));
		done += t.length;
	}
	return out;
}

function labeledExtract(suiteId: Buffer, salt: Buffer, label: string, ikm: Buffer): Buffer {
	return hmac(salt, Buffer.concat([HPKE_V1, suiteId, Buffer.from(label, 'utf8'), ikm]));
}

function labeledExpand(
	suiteId: Buffer,
	prk: Buffer,
	label: string,
	info: Buffer,
	length: number,
): Buffer {
	const labeledInfo = Buffer.concat([
		Buffer.from([(length >> 8) & 0xff, length & 0xff]),
		HPKE_V1,
		suiteId,
		Buffer.from(label, 'utf8'),
		info,
	]);
	return hkdfExpand(prk, labeledInfo, length);
}

function privateFromRaw(sk: Buffer): KeyObject {
	return createPrivateKey({
		key: Buffer.concat([X25519_PKCS8_PREFIX, sk]),
		format: 'der',
		type: 'pkcs8',
	});
}

function publicFromRaw(pk: Buffer): KeyObject {
	return createPublicKey({
		key: Buffer.concat([X25519_SPKI_PREFIX, pk]),
		format: 'der',
		type: 'spki',
	});
}

function rawPublic(publicKeyObject: KeyObject): Buffer {
	const der = publicKeyObject.export({ format: 'der', type: 'spki' });
	return Buffer.from(der.subarray(der.length - X25519_LENGTH));
}

function aeadSeal(k: Buffer, nonce: Buffer, aad: Buffer, pt: Buffer): Buffer {
	const cipher = createCipheriv('aes-256-gcm', k, nonce, { authTagLength: TAG_LENGTH });
	cipher.setAAD(aad);
	return Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]);
}

function aeadOpen(k: Buffer, nonce: Buffer, aad: Buffer, ct: Buffer): Buffer {
	if (ct.length < TAG_LENGTH) throw new Error('hpke_bad_response');
	const decipher = createDecipheriv('aes-256-gcm', k, nonce, { authTagLength: TAG_LENGTH });
	decipher.setAAD(aad);
	decipher.setAuthTag(ct.subarray(ct.length - TAG_LENGTH));
	return Buffer.concat([decipher.update(ct.subarray(0, ct.length - TAG_LENGTH)), decipher.final()]);
}

/** Single-shot HPKE seal to the recipient's raw X25519 public key `pkR`. */
export function seal(
	pkR: Buffer,
	pt: Buffer,
	aad: Buffer,
	info: Buffer = EMPTY,
	eph?: TestEphemeral,
): HpkeSealResult {
	if (pkR.length !== X25519_LENGTH) throw new Error('hpke_bad_public_key');
	let skE: KeyObject;
	let enc: Buffer;
	if (eph) {
		skE = privateFromRaw(eph.sk);
		enc = Buffer.from(eph.pkE);
	} else {
		const pair = generateKeyPairSync('x25519');
		skE = pair.privateKey;
		enc = rawPublic(pair.publicKey);
	}

	// Encap: DH, then ExtractAndExpand with kem_context = enc || pkR.
	const dh = diffieHellman({ privateKey: skE, publicKey: publicFromRaw(pkR) });
	const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, 'eae_prk', dh);
	const sharedSecret = labeledExpand(
		KEM_SUITE_ID,
		eaePrk,
		'shared_secret',
		Buffer.concat([enc, pkR]),
		NH,
	);
	dh.fill(0);
	eaePrk.fill(0);

	// Key schedule, Base mode (mode 0, empty psk and psk_id).
	const keyScheduleContext = Buffer.concat([
		Buffer.from([0]),
		labeledExtract(SUITE_ID, EMPTY, 'psk_id_hash', EMPTY),
		labeledExtract(SUITE_ID, EMPTY, 'info_hash', info),
	]);
	const scheduleSecret = labeledExtract(SUITE_ID, sharedSecret, 'secret', EMPTY);
	sharedSecret.fill(0);
	const aeadK = labeledExpand(SUITE_ID, scheduleSecret, 'key', keyScheduleContext, NK);
	const baseNonce = labeledExpand(SUITE_ID, scheduleSecret, 'base_nonce', keyScheduleContext, NN);
	const exporterSecret = labeledExpand(SUITE_ID, scheduleSecret, 'exp', keyScheduleContext, NH);
	scheduleSecret.fill(0);

	// Single shot: sequence number 0, so the nonce is the base nonce.
	const ct = aeadSeal(aeadK, baseNonce, aad, pt);
	aeadK.fill(0);
	baseNonce.fill(0);

	return {
		enc,
		ct,
		exportSecret: (exporterContext: string | Buffer, length: number): Buffer =>
			labeledExpand(
				SUITE_ID,
				exporterSecret,
				'sec',
				typeof exporterContext === 'string'
					? Buffer.from(exporterContext, 'utf8')
					: exporterContext,
				length,
			),
	};
}

/** Pads a JSON string with trailing spaces to the next bucket, measured in UTF-8 bytes. */
export function padToBucket(json: string): string {
	const length = Buffer.byteLength(json, 'utf8');
	let target = PAD_BUCKETS.find((bucket) => length <= bucket);
	if (target === undefined) target = Math.ceil(length / 4096) * 4096;
	return json + ' '.repeat(target - length);
}

/**
 * Seals `payload` (JSON-serialised, padded) for the gateway key `keyId`/`pkR`.
 * `nowSeconds` defaults to the current unix time; tests pass a fixed value.
 */
export function sealRequest(
	pkR: Buffer,
	keyId: number,
	payload: unknown,
	nowSeconds?: number,
): SealedRequest {
	const seconds = Math.floor(nowSeconds !== undefined ? nowSeconds : Date.now() / 1000);
	const prefix = Buffer.alloc(REQUEST_PREFIX_LENGTH);
	prefix.writeUInt8(WIRE_VERSION, 0);
	prefix.writeUInt32BE(keyId >>> 0, 1);
	prefix.writeBigUInt64BE(BigInt(seconds), 5);

	const pt = Buffer.from(padToBucket(JSON.stringify(payload)), 'utf8');
	const sealed = seal(pkR, pt, prefix);
	pt.fill(0);
	const body: Buffer = Buffer.concat([prefix, sealed.enc, sealed.ct]);

	return {
		body,
		openResponse(bytes: Buffer): unknown {
			if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes[0] !== WIRE_VERSION) {
				throw new Error('hpke_bad_response');
			}
			const keyNonce = sealed.exportSecret(RESPONSE_EXPORT_LABEL, NK + NN);
			const opened = aeadOpen(
				keyNonce.subarray(0, NK),
				keyNonce.subarray(NK),
				EMPTY,
				bytes.subarray(1),
			);
			keyNonce.fill(0);
			const parsed: unknown = JSON.parse(opened.toString('utf8').trimEnd());
			opened.fill(0);
			return parsed;
		},
	};
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url decode. Throws on characters outside the base64url alphabet. */
export function b64urlDecode(value: string): Buffer {
	const trimmed = value.replace(/=+$/, '');
	if (!B64URL_RE.test(trimmed) || trimmed.length % 4 === 1) {
		throw new Error('invalid base64url');
	}
	return Buffer.from(trimmed, 'base64url');
}

/** Unpadded base64url encode. */
export function b64urlEncode(bytes: Buffer): string {
	return Buffer.from(bytes).toString('base64url');
}
