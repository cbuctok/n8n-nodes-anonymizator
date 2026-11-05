// Protocol v3 with Node.js's NATIVE ML-KEM-768 (node:crypto, Node.js 24.7.0 and later) against the
// same vectors as the vendored path: the official X-Wing draft-11 and draft-ietf-hpke-pq-05 A.5
// vectors and every encapsulation-related section of the shared pgw-v3 vectors.
//
// Node.js has no derandomized ML-KEM encapsulation (OpenSSL draws `m` itself), so the native path
// cannot repeat a frame byte for byte from a fixed `eseed`; neither can the gateway's Python
// (`cryptography`), spec section 12.1. What is checked instead, with a native ML-KEM written
// independently in test/helpers/pgwV3.mjs:
// - keygen: every vector seed gives the vector's public key through Node.js's ML-KEM (FIPS 203
//   seed d || z, the X-Wing key expansion);
// - decapsulation: every vector ciphertext gives the vector's ss_M / ss / shared_secret;
// - encapsulation: hpkeV3.ts's native backend with the vector's eseed gives the vector's X25519
//   half byte for byte, a fresh ML-KEM half that both the native and the vendored ML-KEM
//   decapsulate to the same secret, and a frame the independent recipient opens to the vector's
//   padded payload, with the response opened by the request's own context;
// - differential: many native encapsulations decapsulated by the vendored ML-KEM, and the other
//   way round.
// On a Node.js without native ML-KEM (Node 22), the native backend must refuse (hpke_seal_failed)
// and the feature test must say no; the rest is skipped there.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as nodeCrypto from 'node:crypto';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import { hex } from './helpers/pgw.mjs';
import {
	NATIVE_MLKEM,
	NATIVE_SKIP,
	V3,
	XWING,
	keySchedule,
	makeRecipientV3,
	nativeMlKemFromSeed,
	xwingDecapsulate,
	xwingDecapsulateNative,
	xwingExpand,
	xwingExpandNative,
} from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const H3 = require('../dist/nodes/Anonymizator/shared/hpkeV3.js');
const K3 = require('../dist/nodes/Anonymizator/shared/keyconfigV3.js');
const noble = require('../dist/nodes/Anonymizator/shared/vendor/noblePq.js');

const KEY_BY_ID = new Map(V3.keys.map((k) => [k.key_id, k]));
const REQ = V3.request;
const A5 = XWING.hpke_mlkem768_x25519;

describe('native ML-KEM-768: feature test', () => {
	it(`nativeMlKemAvailable() agrees with an independent check (${NATIVE_MLKEM ? 'present' : 'absent'} on ${process.version})`, () => {
		assert.equal(H3.nativeMlKemAvailable(), NATIVE_MLKEM);
		assert.equal(H3.nativeMlKemAvailable(), NATIVE_MLKEM, 'memoised, same answer');
	});

	it(
		'absent: the native backend refuses with hpke_seal_failed, the vendored one still works',
		{ skip: NATIVE_MLKEM ? 'native ML-KEM present' : false },
		() => {
			const pk = hex(KEY_BY_ID.get(REQ.key_id).pk);
			assert.throws(
				() => H3.xwingEncapsulate(pk, hex(REQ.eseed), 'native'),
				/^Error: hpke_seal_failed$/,
			);
			assert.throws(
				() => H3.sealRequestV3(pk, REQ.key_id, { text: 'x' }, REQ.timestamp, undefined, 'native'),
				/^Error: hpke_seal_failed$/,
			);
			const sealed = H3.sealRequestV3(
				pk,
				REQ.key_id,
				JSON.parse(REQ.payload_json),
				REQ.timestamp,
				hex(REQ.eseed),
				'noble',
			);
			assert.equal(sealed.body.toString('hex'), REQ.frame);
		},
	);

	it('an unknown backend is refused', () => {
		const pk = hex(KEY_BY_ID.get(REQ.key_id).pk);
		assert.throws(
			() => H3.xwingEncapsulate(pk, hex(REQ.eseed), 'other'),
			/^Error: hpke_seal_failed$/,
		);
	});

	it('the SPKI form hpkeV3.ts builds is the one Node.js exports', { skip: NATIVE_SKIP }, () => {
		const { publicKey } = nodeCrypto.generateKeyPairSync('ml-kem-768');
		const spki = publicKey.export({ type: 'spki', format: 'der' });
		assert.equal(spki.length, 22 + 1184);
		assert.equal(
			spki.subarray(0, 22).toString('hex'),
			'308204b2300b0609608648016503040402038204a100',
		);
	});
});

describe('official X-Wing vectors through the native ML-KEM-768', { skip: NATIVE_SKIP }, () => {
	for (const [i, t] of XWING.xwing_kem.entries()) {
		it(`vector ${i}: native keygen from sk gives pk; native Decapsulate(ct) gives ss`, () => {
			const native = xwingExpandNative(hex(t.sk));
			assert.equal(native.pk.toString('hex'), t.pk);
			const { ss } = xwingDecapsulateNative(hex(t.ct), native);
			assert.equal(ss.toString('hex'), t.ss);
			// The vendored path agrees on the same ML-KEM shared secret.
			const vendored = xwingExpand(hex(t.sk));
			assert.equal(xwingDecapsulate(hex(t.ct), vendored).toString('hex'), t.ss);
		});

		it(`vector ${i}: native Encapsulate(pk) with the vector eseed: same ct_X, a secret both ML-KEMs agree on`, () => {
			const { sharedSecret, enc } = H3.xwingEncapsulate(hex(t.pk), hex(t.eseed), 'native');
			assert.equal(enc.length, 1120);
			// The X25519 half comes from eseed[32:64] and is the vector's, byte for byte.
			assert.equal(enc.subarray(1088).toString('hex'), t.ct.slice(1088 * 2));
			// The ML-KEM half is fresh (OpenSSL draws m), so it differs from the derandomized vector.
			assert.notEqual(enc.subarray(0, 1088).toString('hex'), t.ct.slice(0, 1088 * 2));
			const native = xwingExpandNative(hex(t.sk));
			assert.equal(
				xwingDecapsulateNative(enc, native).ss.toString('hex'),
				sharedSecret.toString('hex'),
			);
			assert.equal(
				xwingDecapsulate(enc, xwingExpand(hex(t.sk))).toString('hex'),
				sharedSecret.toString('hex'),
			);
		});
	}
});

describe('official HPKE vector A.5 through the native ML-KEM-768', { skip: NATIVE_SKIP }, () => {
	const SUITE_A5 = Buffer.from('48504b45647a00010003', 'hex');

	it('skRm natively expands to pkRm and decapsulates enc to shared_secret', () => {
		const native = xwingExpandNative(hex(A5.skRm));
		assert.equal(native.pk.toString('hex'), A5.pkRm);
		assert.equal(xwingDecapsulateNative(hex(A5.enc), native).ss.toString('hex'), A5.shared_secret);
	});

	it('Encapsulate(pkRm) natively with ikmE: the X25519 half of enc, and a schedule the recipient derives too', () => {
		const { sharedSecret, enc } = H3.xwingEncapsulate(hex(A5.pkRm), hex(A5.ikmE), 'native');
		assert.equal(enc.subarray(1088).toString('hex'), A5.enc.slice(1088 * 2));
		const recovered = xwingDecapsulateNative(enc, xwingExpandNative(hex(A5.skRm))).ss;
		assert.equal(recovered.toString('hex'), sharedSecret.toString('hex'));
		const ours = H3.keyScheduleV3(sharedSecret, hex(A5.info), SUITE_A5);
		const theirs = keySchedule(recovered, hex(A5.info), SUITE_A5);
		assert.equal(ours.key.toString('hex'), theirs.key.toString('hex'));
		assert.equal(ours.baseNonce.toString('hex'), theirs.baseNonce.toString('hex'));
		assert.equal(ours.exporterSecret.toString('hex'), theirs.exporterSecret.toString('hex'));
	});
});

describe(
	'shared v3 vectors (pgw-v3.json) through the native ML-KEM-768',
	{ skip: NATIVE_SKIP },
	() => {
		it('keygen: every vector seed natively expands to its pk', () => {
			for (const k of V3.keys) {
				assert.equal(xwingExpandNative(hex(k.seed)).pk.toString('hex'), k.pk);
			}
		});

		it('request: native decapsulation of the vector enc gives ss_M, ss_X and ss', () => {
			const native = xwingExpandNative(hex(KEY_BY_ID.get(REQ.key_id).seed));
			const { ssM, ssX, ss } = xwingDecapsulateNative(hex(REQ.enc), native);
			assert.equal(ssM.toString('hex'), REQ.ss_m);
			assert.equal(ssX.toString('hex'), REQ.ss_x);
			assert.equal(ss.toString('hex'), REQ.ss);
			// And the native ML-KEM of the vector seed is the vendored one's key.
			const e = nodeCrypto
				.createHash('shake256', { outputLength: 96 })
				.update(hex(KEY_BY_ID.get(REQ.key_id).seed))
				.digest();
			const { pkM } = nativeMlKemFromSeed(Buffer.from(e.subarray(0, 64)));
			assert.equal(
				pkM.toString('hex'),
				Buffer.from(noble.ml_kem768.keygen(Uint8Array.from(e.subarray(0, 64))).publicKey).toString(
					'hex',
				),
			);
		});

		it('request: the vector frame opens through native decapsulation to the padded payload', () => {
			const frame = hex(REQ.frame);
			const native = xwingExpandNative(hex(KEY_BY_ID.get(REQ.key_id).seed));
			const { ss } = xwingDecapsulateNative(frame.subarray(13, 1133), native);
			const s = keySchedule(ss, hex(REQ.info));
			assert.equal(s.key.toString('hex'), REQ.key);
			assert.equal(s.baseNonce.toString('hex'), REQ.base_nonce);
			const ct = frame.subarray(1133);
			const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', s.key, s.baseNonce);
			decipher.setAAD(frame.subarray(0, 13));
			decipher.setAuthTag(ct.subarray(ct.length - 16));
			const pt = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
			assert.equal(pt.toString('hex'), REQ.pt);
		});

		it('request: sealRequestV3 native with the vector eseed: same prefix, ct_X and length; opens to the vector payload', () => {
			const pk = hex(KEY_BY_ID.get(REQ.key_id).pk);
			const sealed = H3.sealRequestV3(
				pk,
				REQ.key_id,
				JSON.parse(REQ.payload_json),
				REQ.timestamp,
				hex(REQ.eseed),
				'native',
			);
			assert.equal(sealed.body.length, REQ.frame_length);
			assert.equal(sealed.body.subarray(0, 13).toString('hex'), REQ.aad);
			assert.equal(sealed.body.subarray(13 + 1088, 13 + 1120).toString('hex'), REQ.ct_x);
			assert.notEqual(sealed.body.toString('hex'), REQ.frame, 'the ML-KEM half is fresh');
			const recipient = makeRecipientV3([
				{ keyId: REQ.key_id, seed: hex(KEY_BY_ID.get(REQ.key_id).seed), notAfter: V3.now + 3600 },
			]);
			const opened = recipient.open(sealed.body, { now: REQ.timestamp });
			assert.equal(opened.code, undefined);
			assert.equal(opened.plaintext.toString('hex'), REQ.pt);
			assert.equal(opened.payloadJson, REQ.payload_json);
			const success = V3.response.success;
			const body = opened.seal(JSON.parse(success.payload_json), hex(success.response_nonce));
			assert.deepEqual(sealed.openResponse(body), JSON.parse(success.payload_json));
		});

		it('exchange possible_emoji: the native seal opens to its payload and its response', () => {
			const x = V3.exchanges.find((e) => e.name === 'possible_emoji');
			const k = KEY_BY_ID.get(x.request.key_id);
			const sealed = H3.sealRequestV3(
				hex(k.pk),
				x.request.key_id,
				JSON.parse(x.request.payload_json),
				x.request.timestamp,
				hex(x.request.eseed),
				'native',
			);
			assert.equal(sealed.body.length, x.request.frame.length / 2);
			const recipient = makeRecipientV3([
				{ keyId: k.key_id, seed: hex(k.seed), notAfter: V3.now + 3600 },
			]);
			const opened = recipient.open(sealed.body, { now: x.request.timestamp });
			assert.equal(opened.payloadJson, x.request.payload_json);
			const reply = JSON.parse(x.response.payload_json);
			assert.deepEqual(sealed.openResponse(opened.seal(reply)), reply);
		});

		it('exchange wrong_version_response: a 0x02 body to a native v3 request is hpke_bad_response', () => {
			const x = V3.exchanges.find((e) => e.name === 'wrong_version_response');
			const sealed = H3.sealRequestV3(
				hex(KEY_BY_ID.get(REQ.key_id).pk),
				REQ.key_id,
				{ text: 'x' },
				REQ.timestamp,
				undefined,
				'native',
			);
			assert.throws(() => sealed.openResponse(hex(x.body)), /^Error: hpke_bad_response$/);
		});

		for (const c of V3.seal_cases) {
			it(`seal case ${c.name}: verifies, then the native seal fails too (hpke_seal_failed)`, () => {
				const r = K3.verifyKeyconfigV3(
					c.keyconfig_json,
					c.pinned_roots,
					c.now,
					c.expected_audience,
				);
				assert.equal(r.ok, true);
				assert.throws(
					() =>
						H3.sealRequestV3(
							r.publicKey,
							r.keyId,
							JSON.parse(c.payload_json),
							c.now,
							hex(c.eseed),
							'native',
						),
					new RegExp(`^Error: ${c.expect.seal_error}$`),
				);
				assert.throws(
					() =>
						H3.sealRequestV3(
							r.publicKey,
							r.keyId,
							JSON.parse(c.payload_json),
							c.now,
							undefined,
							'native',
						),
					/^Error: hpke_seal_failed$/,
				);
			});
		}

		it('the FIPS 203 modulus check runs before the native ML-KEM (a coefficient = q is hpke_seal_failed)', () => {
			const pk = Buffer.from(hex(KEY_BY_ID.get(1000001).pk));
			// First coefficient := 3329 (0xd01): bytes 0..1 low 12 bits.
			pk[0] = 0x01;
			pk[1] = (pk[1] & 0xf0) | 0x0d;
			assert.equal(H3.mlkemPublicKeyValid(pk.subarray(0, 1184)), false);
			assert.throws(
				() => H3.xwingEncapsulate(pk, randomBytes(64), 'native'),
				/^Error: hpke_seal_failed$/,
			);
		});
	},
);

describe('native ML-KEM-768 in production mode', { skip: NATIVE_SKIP }, () => {
	const k = KEY_BY_ID.get(1000001);

	it('fresh randomness every time; never through the vendored random source', () => {
		const pk = hex(k.pk);
		const a = H3.sealRequestV3(pk, 1000001, { text: 'x' }, undefined, undefined, 'native');
		const b = H3.sealRequestV3(pk, 1000001, { text: 'x' }, undefined, undefined, 'native');
		assert.notEqual(
			a.body.subarray(13, 1133).toString('hex'),
			b.body.subarray(13, 1133).toString('hex'),
		);
		const now = Math.floor(Date.now() / 1000);
		const recipient = makeRecipientV3([
			{ keyId: 1000001, seed: hex(k.seed), notAfter: now + 3600 },
		]);
		const opened = recipient.open(a.body, { now });
		assert.deepEqual(opened.payload, { text: 'x' });
		assert.deepEqual(a.openResponse(opened.seal({ entities: [] })), { entities: [] });
	});

	it('differential: 64 native encapsulations open with the vendored ML-KEM, 64 vendored ones with the native', () => {
		for (let i = 0; i < 64; i++) {
			const seed = randomBytes(32);
			const vendored = xwingExpand(seed);
			const native = xwingExpandNative(seed);
			assert.equal(native.pk.toString('hex'), vendored.pk.toString('hex'));
			const n = H3.xwingEncapsulate(vendored.pk, randomBytes(64), 'native');
			assert.equal(
				xwingDecapsulate(n.enc, vendored).toString('hex'),
				n.sharedSecret.toString('hex'),
			);
			const v = H3.xwingEncapsulate(vendored.pk, randomBytes(64), 'noble');
			assert.equal(
				xwingDecapsulateNative(v.enc, native).ss.toString('hex'),
				v.sharedSecret.toString('hex'),
			);
		}
	});
});
