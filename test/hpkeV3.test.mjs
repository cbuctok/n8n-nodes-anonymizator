// EXPERIMENTAL protocol v3 (X-Wing) against the compiled dist/: the official X-Wing draft-11 and
// draft-ietf-hpke-pq-05 A.5 vectors, and every section of the gateway's shared v3 vectors
// (test/fixtures/pgw-v3.json): keys, the request frame byte for byte (fixed eseed), the key
// schedule, the responses, the exchanges, every keyconfig, capabilities, frame and seal case, and
// v2 unchanged next to a `v3` member.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import { VECTORS as V2, hex } from './helpers/pgw.mjs';
import {
	V3,
	XWING,
	keySchedule,
	makeRecipientV3,
	openRequestForTestV3,
	sealResponseV3,
	xwingDecapsulate,
	xwingExpand,
} from './helpers/pgwV3.mjs';

const require = createRequire(import.meta.url);
const H3 = require('../dist/nodes/Anonymizator/shared/hpkeV3.js');
const K3 = require('../dist/nodes/Anonymizator/shared/keyconfigV3.js');
const K2 = require('../dist/nodes/Anonymizator/shared/keyconfig.js');
const C = require('../dist/nodes/Anonymizator/shared/capabilities.js');
const noble = require('../dist/nodes/Anonymizator/shared/vendor/noblePq.js');

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const KEY_BY_ID = new Map(V3.keys.map((k) => [k.key_id, k]));
const REQ = V3.request;

describe('official X-Wing vectors (draft-connolly-cfrg-xwing-kem-11, Appendix C)', () => {
	it('the fixture names its sources', () => {
		assert.equal(XWING.format, 'xwing-official-vectors-1');
		assert.equal(XWING.sources.xwing.revision, '11');
		assert.equal(
			XWING.sources.xwing.sha256,
			'1353f61f0d706199d86b6802eab83cabbb5195b2d99fb35bca20f5e4f83db786',
		);
		assert.equal(XWING.sources.hpke_pq.revision, '05');
		assert.equal(XWING.xwing_kem.length, 3);
	});

	for (const [i, t] of XWING.xwing_kem.entries()) {
		it(`vector ${i}: keygen from sk, EncapsulateDerand(pk, eseed) and Decapsulate`, () => {
			const expanded = xwingExpand(hex(t.sk));
			assert.equal(expanded.pk.toString('hex'), t.pk);
			const { sharedSecret, enc } = H3.xwingEncapsulate(hex(t.pk), hex(t.eseed));
			assert.equal(enc.toString('hex'), t.ct);
			assert.equal(sharedSecret.toString('hex'), t.ss);
			assert.equal(xwingDecapsulate(hex(t.ct), expanded).toString('hex'), t.ss);
		});
	}
});

describe('official HPKE vector (draft-ietf-hpke-pq-05, A.5: MLKEM768-X25519, HKDF-SHA256, AEAD 3)', () => {
	const A5 = XWING.hpke_mlkem768_x25519;
	// Our suite differs only in the AEAD id; Nk and Nn are the same for both AEADs.
	const SUITE_A5 = Buffer.from('48504b45647a00010003', 'hex');

	it('is the X-Wing codepoint 0x647a with HKDF-SHA256, base mode', () => {
		assert.equal(A5.kem_id, 0x647a);
		assert.equal(H3.XWING_KEM_ID, A5.kem_id);
		assert.equal(A5.kdf_id, 1);
		assert.equal(A5.aead_id, 3);
		assert.equal(A5.mode, 0);
	});

	it('skRm expands to pkRm and decapsulates enc to shared_secret', () => {
		const expanded = xwingExpand(hex(A5.skRm));
		assert.equal(expanded.pk.toString('hex'), A5.pkRm);
		assert.equal(xwingDecapsulate(hex(A5.enc), expanded).toString('hex'), A5.shared_secret);
	});

	it('EncapsulateDerand(pkRm, ikmE) gives enc and shared_secret (ikmE consumed as eseed)', () => {
		const { sharedSecret, enc } = H3.xwingEncapsulate(hex(A5.pkRm), hex(A5.ikmE));
		assert.equal(enc.toString('hex'), A5.enc);
		assert.equal(sharedSecret.toString('hex'), A5.shared_secret);
	});

	it('the key schedule with the AEAD 3 suite_id override gives key, base_nonce, exporter_secret', () => {
		const s = H3.keyScheduleV3(hex(A5.shared_secret), hex(A5.info), SUITE_A5);
		assert.equal(s.key.toString('hex'), A5.key);
		assert.equal(s.baseNonce.toString('hex'), A5.base_nonce);
		assert.equal(s.exporterSecret.toString('hex'), A5.exporter_secret);
		assert.ok(A5.exports.length >= 1);
		for (const e of A5.exports) {
			const value = H3.exportV3(s.exporterSecret, hex(e.exporter_context), e.L, SUITE_A5);
			assert.equal(value.toString('hex'), e.exported_value);
		}
	});

	it('our own suite_id is 48504b45647a00010002 and a DHKEM-style extract would not match', () => {
		assert.equal(V3.suite.suite_id, '48504b45647a00010002');
		// The most likely port bug: X-Wing's output is the shared secret as is.
		const s = H3.keyScheduleV3(hex(A5.shared_secret), hex(A5.info), SUITE_A5);
		const wrong = H3.keyScheduleV3(
			createHash('sha256').update(hex(A5.shared_secret)).digest(),
			hex(A5.info),
			SUITE_A5,
		);
		assert.notEqual(wrong.key.toString('hex'), s.key.toString('hex'));
	});
});

describe('FIPS 203 encapsulation-key modulus check', () => {
	const pkM = hex(KEY_BY_ID.get(1000001).pk).subarray(0, 1184);

	it('accepts the vector keys and refuses a coefficient equal to q (3329)', () => {
		assert.equal(H3.mlkemPublicKeyValid(pkM), true);
		const bad = Buffer.from(pkM);
		// First coefficient = 3329 = 0xd01: byte 0 = 0x01, low nibble of byte 1 = 0xd.
		bad[0] = 0x01;
		bad[1] = (bad[1] & 0xf0) | 0x0d;
		assert.equal(H3.mlkemPublicKeyValid(bad), false);
		// The second coefficient of a triple (high nibble of byte 1 and byte 2), = 4095.
		const bad2 = Buffer.from(pkM);
		bad2[1] |= 0xf0;
		bad2[2] = 0xff;
		assert.equal(H3.mlkemPublicKeyValid(bad2), false);
		assert.equal(H3.mlkemPublicKeyValid(pkM.subarray(0, 1183)), false);
	});

	it('xwingEncapsulate refuses such a key (defence in depth: hpke_seal_failed)', () => {
		const pk = Buffer.from(hex(KEY_BY_ID.get(1000001).pk));
		pk[0] = 0x01;
		pk[1] = (pk[1] & 0xf0) | 0x0d;
		assert.throws(() => H3.xwingEncapsulate(pk, hex(REQ.eseed)), /^Error: hpke_seal_failed$/);
	});
});

describe('shared v3 vectors (pgw-v3.json)', () => {
	it('is the gateway format with the expected constants and suite', () => {
		assert.equal(V3.format, 'pgw-v3-test-vectors-1');
		assert.equal(V3.constants.enc_len, H3.XWING_ENC_LENGTH);
		assert.equal(V3.constants.public_key_len, H3.XWING_PUBLIC_LENGTH);
		assert.equal(V3.constants.min_frame_len, H3.MIN_FRAME_LENGTH_V3);
		assert.equal(V3.constants.min_response_len, H3.MIN_RESPONSE_LENGTH_V3);
		assert.equal(V3.constants.max_keyconfig_v3_keys, K3.V3_LIMITS.MAX_KEYS);
		assert.equal(V3.constants.max_keyconfig_v3_bytes, K3.V3_LIMITS.MAX_DOCUMENT_BYTES);
		assert.equal(V3.constants.max_keyconfig_v3_b64, K3.V3_LIMITS.MAX_DOCUMENT_B64);
		assert.equal(hex(V3.suite.request_info).toString(), H3.REQUEST_INFO_V3);
		assert.equal(hex(V3.suite.response_export_label).toString(), H3.RESPONSE_EXPORT_LABEL_V3);
		assert.equal(V3.suite.kem, H3.XWING_KEM_ID);
	});

	it('keygen: every seed expands to its pk', () => {
		for (const k of V3.keys) {
			const pk = xwingExpand(hex(k.seed)).pk;
			assert.equal(pk.toString('hex'), k.pk);
			assert.equal(pk.toString('base64url'), k.pk_b64);
			assert.equal(sha256(pk), k.pk_sha256);
		}
	});

	it('request: X-Wing intermediates and enc from the fixed eseed', () => {
		const pk = hex(KEY_BY_ID.get(REQ.key_id).pk);
		const { sharedSecret, enc } = H3.xwingEncapsulate(pk, hex(REQ.eseed));
		assert.equal(REQ.eseed.slice(0, 64), REQ.m);
		assert.equal(REQ.eseed.slice(64), REQ.ek_x);
		assert.equal(enc.toString('hex'), REQ.enc);
		assert.equal(enc.subarray(0, 1088).toString('hex'), REQ.ct_m);
		assert.equal(enc.subarray(1088).toString('hex'), REQ.ct_x);
		assert.equal(sharedSecret.toString('hex'), REQ.ss);
		// The combiner, from the vector's own halves.
		const combined = createHash('sha3-256')
			.update(
				Buffer.concat([
					hex(REQ.ss_m),
					hex(REQ.ss_x),
					hex(REQ.ct_x),
					pk.subarray(1184),
					hex(V3.suite.xwing_label),
				]),
			)
			.digest('hex');
		assert.equal(combined, REQ.ss);
	});

	it('request: the key schedule (psk_id_hash, info_hash, secret, key, base_nonce, exporter_secret)', () => {
		const s = H3.keyScheduleV3(hex(REQ.ss), hex(REQ.info));
		assert.equal(s.pskIdHash.toString('hex'), REQ.psk_id_hash);
		assert.equal(s.infoHash.toString('hex'), REQ.info_hash);
		assert.equal(s.secret.toString('hex'), REQ.secret);
		assert.equal(s.key.toString('hex'), REQ.key);
		assert.equal(s.baseNonce.toString('hex'), REQ.base_nonce);
		assert.equal(s.exporterSecret.toString('hex'), REQ.exporter_secret);
		assert.equal(
			H3.exportV3(s.exporterSecret, 'pgw response v3', 32).toString('hex'),
			V3.response.export_secret,
		);
	});

	it('request: sealRequestV3 with the fixed eseed gives the frame byte for byte (1405 bytes)', () => {
		const payload = JSON.parse(REQ.payload_json);
		assert.equal(JSON.stringify(payload), REQ.payload_json);
		const sealed = H3.sealRequestV3(
			hex(KEY_BY_ID.get(REQ.key_id).pk),
			REQ.key_id,
			payload,
			REQ.timestamp,
			hex(REQ.eseed),
		);
		assert.ok(Buffer.isBuffer(sealed.body));
		assert.equal(sealed.body.length, REQ.frame_length);
		assert.equal(sealed.body.length, 1405);
		assert.equal(sealed.body.subarray(0, 13).toString('hex'), REQ.aad);
		assert.equal(sealed.body.toString('hex'), REQ.frame);
		assert.equal(sha256(sealed.body), REQ.frame_sha256);
	});

	it('request: the independent recipient opens the frame to the padded payload', () => {
		const { result } = openRequestForTestV3(hex(REQ.frame), { v3Enabled: true });
		assert.equal(result.code, undefined);
		assert.equal(result.plaintext.toString('hex'), REQ.pt);
		assert.equal(result.payloadJson, REQ.payload_json);
		assert.equal(result.exportSecret.toString('hex'), V3.response.export_secret);
	});

	for (const name of ['success', 'sealed_error']) {
		const R = V3.response[name];
		it(`response ${name}: opens to the expected result; the recipient reproduces the body`, () => {
			const sealed = H3.sealRequestV3(
				hex(KEY_BY_ID.get(REQ.key_id).pk),
				REQ.key_id,
				JSON.parse(REQ.payload_json),
				REQ.timestamp,
				hex(REQ.eseed),
			);
			assert.equal(sha256(hex(R.body)), R.body_sha256);
			assert.equal(R.salt, REQ.enc + R.response_nonce);
			assert.deepEqual(sealed.openResponse(hex(R.body)), R.expect);
			const body = sealResponseV3(
				hex(V3.response.export_secret),
				hex(REQ.enc),
				R.payload_json,
				hex(R.response_nonce),
			);
			assert.equal(body.toString('hex'), R.body);
		});
	}

	it('response: one open per request, and a tampered body is hpke_bad_response', () => {
		const make = () =>
			H3.sealRequestV3(
				hex(KEY_BY_ID.get(REQ.key_id).pk),
				REQ.key_id,
				JSON.parse(REQ.payload_json),
				REQ.timestamp,
				hex(REQ.eseed),
			);
		const body = hex(V3.response.success.body);
		const tampered = Buffer.from(body);
		tampered[tampered.length - 1] ^= 1;
		assert.throws(() => make().openResponse(tampered), /^Error: hpke_bad_response$/);
		assert.throws(() => make().openResponse(body.subarray(0, 48)), /^Error: hpke_bad_response$/);
		const once = make();
		once.openResponse(body);
		assert.throws(() => once.openResponse(body), /^Error: hpke_bad_response$/);
	});

	it('exchange possible_emoji: frame, export secret and response', () => {
		const x = V3.exchanges.find((e) => e.name === 'possible_emoji');
		const pk = hex(KEY_BY_ID.get(x.request.key_id).pk);
		const sealed = H3.sealRequestV3(
			pk,
			x.request.key_id,
			JSON.parse(x.request.payload_json),
			x.request.timestamp,
			hex(x.request.eseed),
		);
		assert.equal(sealed.body.toString('hex'), x.request.frame);
		const { result } = openRequestForTestV3(sealed.body, { v3Enabled: true });
		assert.equal(result.exportSecret.toString('hex'), x.export_secret);
		const opened = sealed.openResponse(hex(x.response.body));
		assert.deepEqual(opened, JSON.parse(x.response.payload_json));
		assert.ok(Array.isArray(x.expect.entities_utf16));
	});

	it('exchange wrong_version_response: a 0x02 body to a v3 request is hpke_bad_response', () => {
		const x = V3.exchanges.find((e) => e.name === 'wrong_version_response');
		assert.equal(x.request, 'request');
		assert.equal(x.expect.error, 'hpke_bad_response');
		const sealed = H3.sealRequestV3(
			hex(KEY_BY_ID.get(REQ.key_id).pk),
			REQ.key_id,
			JSON.parse(REQ.payload_json),
			REQ.timestamp,
			hex(REQ.eseed),
		);
		assert.equal(hex(x.body)[0], 2);
		assert.throws(() => sealed.openResponse(hex(x.body)), /^Error: hpke_bad_response$/);
	});
});

describe('keyconfig v3 cases', () => {
	it('the vector document is the one signed in keyconfig_json', () => {
		assert.equal(
			Buffer.from(V3.keyconfig_v3.b64, 'base64url').toString('latin1'),
			V3.keyconfig_v3.text,
		);
		assert.equal(V3.keyconfig_json.v3.keyconfig, V3.keyconfig_v3.b64);
		assert.equal(V3.keyconfig_json.v3.delegation, V3.keyconfig_json.v2.delegation);
		assert.equal(V3.keyconfig_json.v3.delegation_sig, V3.keyconfig_json.v2.delegation_sig);
		const r = K3.verifyKeyconfigV3(
			V3.keyconfig_json,
			[V3.roots.primary.public_key_b64],
			V3.now,
			V3.expected_audience,
		);
		assert.equal(r.ok, true);
		assert.equal(r.keyId, V3.expected_selection.key_id);
		assert.equal(r.serial, V3.expected_selection.serial);
		assert.equal(r.issuedAt, V3.expected_selection.issued_at);
		assert.equal(r.publicKey.toString('hex'), KEY_BY_ID.get(r.keyId).pk);
	});

	assert.ok(V3.keyconfig_cases.length >= 60);
	for (const c of V3.keyconfig_cases) {
		it(`${c.name} (${c.verifier}) -> ${JSON.stringify(c.expect)}`, () => {
			const verify = c.verifier === 'v2' ? K2.verifyKeyconfigV2 : K3.verifyKeyconfigV3;
			assert.ok(c.verifier === 'v2' || c.verifier === 'v3');
			const r = verify(c.keyconfig_json, c.pinned_roots, c.now, c.expected_audience);
			if (c.expect.error) {
				assert.deepEqual(r, { ok: false, error: c.expect.error });
			} else {
				assert.equal(r.ok, true, JSON.stringify(r));
				assert.equal(r.keyId, c.expect.key_id);
			}
		});
	}

	it('oversize fields (generated): keyconfig over 21 846 and delegation over 8192 characters', () => {
		const base = V3.keyconfig_json;
		const roots = [V3.roots.primary.public_key_b64];
		const big = { ...base, v3: { ...base.v3, keyconfig: 'A'.repeat(21847) } };
		assert.deepEqual(K3.verifyKeyconfigV3(big, roots, V3.now, V3.expected_audience), {
			ok: false,
			error: 'hpke_unverified_keyconfig',
		});
		const bigDelegation = { ...base, v3: { ...base.v3, delegation: 'A'.repeat(8193) } };
		assert.deepEqual(K3.verifyKeyconfigV3(bigDelegation, roots, V3.now, V3.expected_audience), {
			ok: false,
			error: 'hpke_unverified_keyconfig',
		});
		// 21 846 characters decode to at most 16 384 bytes, so the parser's own byte cap is checked
		// directly: the vector document padded past 16 384 bytes is refused before any line is read.
		assert.equal(Buffer.alloc(16385).toString('base64url').length, 21847);
		const text = Buffer.from(V3.keyconfig_v3.text, 'latin1');
		assert.ok(K3.parseKeyconfigV3Document(text));
		assert.equal(
			K3.parseKeyconfigV3Document(Buffer.concat([text, Buffer.alloc(16385 - text.length, 0x0a)])),
			null,
		);
	});

	it("v2_unchanged: the JSON with `v3` gives the v2 verifier exactly pgw-v2's selection", () => {
		const u = V3.v2_unchanged;
		const r = K2.verifyKeyconfigV2(u.keyconfig_json, u.pinned_roots, u.now, u.expected_audience);
		assert.equal(r.ok, true);
		assert.equal(r.keyId, u.expect.key_id);
		assert.equal(r.serial, u.expect.serial);
		assert.equal(r.issuedAt, u.expect.issued_at);
		// The v2 member is byte-identical to pgw-v2's.
		assert.deepEqual(u.keyconfig_json.v2, V2.keyconfig_json.v2);
	});

	it('the v3 verifier never reads v2: a valid v2 member without v3 is hpke_pq_unavailable', () => {
		const { v3, ...withoutV3 } = V3.keyconfig_json;
		assert.ok(v3);
		const r = K3.verifyKeyconfigV3(
			withoutV3,
			[V3.roots.primary.public_key_b64],
			V3.now,
			V3.expected_audience,
		);
		assert.deepEqual(r, { ok: false, error: 'hpke_pq_unavailable' });
		for (const config of [null, 'x', [], {}, { v3: null }, { v3: [] }, { v3: 'x' }]) {
			assert.deepEqual(
				K3.verifyKeyconfigV3(
					config,
					[V3.roots.primary.public_key_b64],
					V3.now,
					V3.expected_audience,
				),
				{ ok: false, error: 'hpke_pq_unavailable' },
			);
		}
	});
});

describe('capabilities cases (domain separation)', () => {
	assert.ok(V3.capabilities_cases.length >= 1);
	for (const c of V3.capabilities_cases) {
		it(`${c.name}: the capabilities verifier refuses it`, () => {
			const r = C.verifyCapabilitiesV1(
				c.capabilities_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			assert.equal(r.ok, false);
			assert.equal(r.error, c.expect.error);
		});
	}
});

describe('frame cases (the gateway open path, through openRequestForTestV3)', () => {
	assert.ok(V3.frame_cases.length >= 9);
	for (const c of V3.frame_cases) {
		it(`${c.name} (v3 ${c.v3_enabled ? 'on' : 'off'}) -> ${c.expected_code}, nothing in the replay cache`, () => {
			const frame = hex(c.frame);
			assert.equal(frame.length, c.frame_length);
			const { result, replay } = openRequestForTestV3(frame, { v3Enabled: c.v3_enabled });
			assert.equal(result.code, c.expected_code);
			assert.equal(c.replay_cached, false);
			assert.equal(replay.size, 0);
		});
	}

	it('the valid frame opens once, then is a replay', () => {
		const recipient = makeRecipientV3(
			V3.keys.map((k) => ({ keyId: k.key_id, seed: hex(k.seed), notAfter: k.not_after })),
		);
		const first = openRequestForTestV3(hex(REQ.frame), { v3Enabled: true, recipient });
		assert.equal(first.result.code, undefined);
		assert.equal(first.replay.size, 1);
		assert.equal(
			openRequestForTestV3(hex(REQ.frame), { v3Enabled: true, recipient }).result.code,
			'hpke_replay',
		);
	});
});

describe('seal cases', () => {
	assert.ok(V3.seal_cases.length >= 1);
	for (const c of V3.seal_cases) {
		it(`${c.name}: verifies (pk_X is not checked at parse time), then sealing fails`, () => {
			const r = K3.verifyKeyconfigV3(c.keyconfig_json, c.pinned_roots, c.now, c.expected_audience);
			assert.equal(r.ok, true);
			assert.equal(r.keyId, c.expect.key_id);
			assert.throws(
				() =>
					H3.sealRequestV3(r.publicKey, r.keyId, JSON.parse(c.payload_json), c.now, hex(c.eseed)),
				new RegExp(`^Error: ${c.expect.seal_error}$`),
			);
			assert.throws(
				() => H3.sealRequestV3(r.publicKey, r.keyId, JSON.parse(c.payload_json), c.now),
				/^Error: hpke_seal_failed$/,
			);
		});
	}
});

describe('sealRequestV3 in production mode', () => {
	const pk = hex(KEY_BY_ID.get(1000001).pk);

	it('draws its own randomness: fresh enc every time, never through the vendored random source', () => {
		// The vendored subset has no CSPRNG: its randomBytes throws, so ML-KEM without `m` fails.
		assert.throws(
			() => noble.ml_kem768.encapsulate(Uint8Array.from(pk.subarray(0, 1184))),
			/randomBytes is not available/,
		);
		const a = H3.sealRequestV3(pk, 1000001, { text: 'x' });
		const b = H3.sealRequestV3(pk, 1000001, { text: 'x' });
		assert.notEqual(
			a.body.subarray(13, 1133).toString('hex'),
			b.body.subarray(13, 1133).toString('hex'),
		);
		const now = Math.floor(Date.now() / 1000);
		const recipient = makeRecipientV3([
			{ keyId: 1000001, seed: hex(KEY_BY_ID.get(1000001).seed), notAfter: now + 3600 },
		]);
		const opened = recipient.open(a.body, { now });
		assert.deepEqual(opened.payload, { text: 'x' });
		assert.deepEqual(a.openResponse(opened.seal({ entities: [] })), { entities: [] });
	});

	it('layout: 0x03 || key_id || timestamp || enc(1120) || ct, padded to the v2 buckets', () => {
		const s = H3.sealRequestV3(pk, 1000001, { text: 'a' }, 1_800_000_000);
		assert.equal(s.body[0], 3);
		assert.equal(s.body.readUInt32BE(1), 1000001);
		assert.equal(Number(s.body.readBigUInt64BE(5)), 1_800_000_000);
		assert.equal(s.body.length, 13 + 1120 + 256 + 16);
		const long = H3.sealRequestV3(pk, 1000001, { text: 'a'.repeat(300) }, 1_800_000_000);
		assert.equal(long.body.length, 13 + 1120 + 1024 + 16);
	});

	it('refuses a wrong key length, key id or test eseed (hpke_seal_failed)', () => {
		assert.throws(() => H3.sealRequestV3(pk.subarray(0, 1215), 1, {}), /^Error: hpke_seal_failed$/);
		assert.throws(() => H3.sealRequestV3(pk.subarray(0, 32), 1, {}), /^Error: hpke_seal_failed$/);
		for (const id of [0, -1, 2 ** 32, 1.5, NaN]) {
			assert.throws(() => H3.sealRequestV3(pk, id, {}), /^Error: hpke_seal_failed$/);
		}
		assert.throws(
			() => H3.sealRequestV3(pk, 1, {}, 1, Buffer.alloc(63)),
			/^Error: hpke_seal_failed$/,
		);
	});

	it('errors carry fixed codes only, never key material or plaintext (leak rule)', () => {
		const bad = Buffer.from(pk);
		bad[1200] ^= 0xff;
		let message = '';
		try {
			H3.sealRequestV3(bad.subarray(0, 1000), 1, { text: 'Ana Kovač' });
		} catch (e) {
			message = `${e.message} ${e.stack}`;
		}
		assert.match(message, /hpke_seal_failed/);
		assert.doesNotMatch(message, /Kova|[0-9a-f]{32}/);
	});

	it('the largest part at the body clamp seals to at most max_body_bytes (section 11)', () => {
		const { effectiveMaxTextChars } = require('../dist/nodes/Anonymizator/shared/limits.js');
		const maxBodyBytes = 1048576;
		const cap = effectiveMaxTextChars({ maxTextChars: 1000000, maxBodyBytes });
		assert.equal(cap, 173397);
		// Parts are 2000 below the cap; every character escaped as \u0001 (6 bytes) is the worst case.
		const text = '\u0001'.repeat(cap - 2000);
		const s = H3.sealRequestV3(
			pk,
			1000001,
			{ text, entities: ['PERSON'], possible: true },
			1_800_000_000,
		);
		assert.ok(s.body.length <= maxBodyBytes, `${s.body.length}`);
	});
});
