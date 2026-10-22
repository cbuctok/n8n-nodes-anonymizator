// HPKE (RFC 9180) and protocol v2 wire-frame tests against the compiled dist/ output.
// The RFC 9180 vector is the official CFRG one for exactly our suite (X25519 / HKDF-SHA256 /
// AES-256-GCM, Base mode). The v2 frames are checked byte for byte against the gateway's own
// vectors (test/fixtures/pgw-v2.json, copied from the gateway repository). Interop runs against the
// extension's real lib/hpke.js when that checkout is present; otherwise those cases are skipped.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import {
	EXT_SKIP,
	VECTORS,
	hex,
	loadExtHpke,
	makeRecipient,
	x25519Public,
	x25519Raw,
} from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const H = require('../dist/nodes/Anonymizator/shared/hpke.js');

// CFRG HPKE test-vectors.json entry for mode 0, kem 0x20, kdf 0x01, aead 0x02. Copied from the
// extension's tests/fixtures/hpke-vector.json; only sequence 0 applies to a single-shot seal.
const V = {
	info: '4f6465206f6e2061204772656369616e2055726e',
	pkEm: '6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256',
	skEm: '179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11',
	pkRm: '430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c',
	skRm: '497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d',
	enc: '6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256',
	aad: '436f756e742d30',
	pt: '4265617574792069732074727574682c20747275746820626561757479',
	ct: 'e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a',
	exports: [
		['', 32, 'ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a'],
		['00', 32, '04d3cb6cc116b28ffd22ad5bc276c60d31fec71ceb87ae24db811c64b7507339'],
		[
			'54657374436f6e74657874',
			32,
			'7c5ded445732c14fe09727d29b4251c0fd38455fe8440571e687f0886aac94d2',
		],
	],
};

describe('RFC 9180 test vector', () => {
	it('seal with the vector ephemeral reproduces enc and ct (seq 0)', () => {
		const s = H.seal(hex(V.pkRm), hex(V.pt), hex(V.aad), hex(V.info), {
			sk: hex(V.skEm),
			pkE: hex(V.pkEm),
		});
		assert.equal(s.enc.toString('hex'), V.enc);
		assert.equal(s.ct.toString('hex'), V.ct);
	});

	it('exporter secrets match the vector', () => {
		const s = H.seal(hex(V.pkRm), Buffer.alloc(0), Buffer.alloc(0), hex(V.info), {
			sk: hex(V.skEm),
			pkE: hex(V.pkEm),
		});
		for (const [context, length, expected] of V.exports) {
			assert.equal(s.exportSecret(hex(context), length).toString('hex'), expected);
		}
	});

	it('a different AAD gives a different ciphertext', () => {
		const s = H.seal(hex(V.pkRm), hex(V.pt), hex('deadbeef'), hex(V.info), {
			sk: hex(V.skEm),
			pkE: hex(V.pkEm),
		});
		assert.notEqual(s.ct.toString('hex'), V.ct);
	});

	it('rejects a recipient key that is not 32 bytes', () => {
		assert.throws(() => H.seal(Buffer.alloc(31), Buffer.from('x'), Buffer.alloc(0)));
	});
});

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const vectorKey = (id) => VECTORS.hpke_keys.find((k) => k.key_id === id);
const ephemeral = (request) => {
	const sk = hex(request.ephemeral_private_key_hex);
	return { sk, pkE: x25519Public(sk) };
};

describe('protocol v2 vectors (pgw-v2.json)', () => {
	const exchanges = [
		{ name: 'request', request: VECTORS.request, responses: VECTORS.responses },
		...VECTORS.exchanges.map((e) => ({ name: e.name, request: e.request, responses: e.responses })),
	];

	for (const { name, request, responses } of exchanges) {
		describe(name, () => {
			const key = vectorKey(request.key_id);
			const pkR = x25519Public(hex(key.private_key_hex));
			const seal = () =>
				H.sealRequestV2(
					pkR,
					request.key_id,
					JSON.parse(request.payload_json),
					request.timestamp,
					ephemeral(request),
				);

			it('the vector key decodes to its public key', () => {
				assert.equal(pkR.toString('base64url'), key.public_key);
			});

			it('JSON.stringify gives the vector payload bytes and padding', () => {
				const payload = JSON.parse(request.payload_json);
				assert.equal(JSON.stringify(payload), request.payload_json);
				assert.equal(
					Buffer.from(H.padToBucket(request.payload_json), 'utf8').toString('hex'),
					request.plaintext_hex,
				);
			});

			it('the request frame is byte-identical (AAD, enc, ciphertext)', () => {
				const { body } = seal();
				assert.ok(Buffer.isBuffer(body));
				assert.equal(body.subarray(0, 13).toString('hex'), request.aad_hex);
				assert.equal(body.subarray(13, 45).toString('hex'), request.enc_hex);
				assert.equal(body.toString('hex'), request.frame_hex);
				assert.equal(
					H.framePrefix(request.key_id, request.timestamp).toString('hex'),
					request.aad_hex,
				);
				assert.equal(Buffer.from(H.REQUEST_INFO).toString('hex'), request.info_hex);
			});

			for (const response of responses) {
				it(`opens the ${response.name} response and derives the vector keys`, () => {
					const sealed = seal();
					const body = hex(response.body_hex);
					assert.deepEqual(sealed.openResponse(body), JSON.parse(response.payload_json));
					const keys = H.deriveResponseKeys(
						hex(response.export_secret_hex),
						hex(request.enc_hex),
						hex(response.response_nonce_hex),
					);
					assert.equal(keys.prk.toString('hex'), response.prk_hex);
					assert.equal(keys.key.toString('hex'), response.aead_key_hex);
					assert.equal(keys.nonce.toString('hex'), response.aead_nonce_hex);
					assert.equal(
						Buffer.concat([hex(request.enc_hex), hex(response.response_nonce_hex)]).toString('hex'),
						response.salt_hex,
					);
				});

				it(`the independent recipient reproduces the ${response.name} body`, () => {
					const recipient = makeRecipient(hex(key.private_key_hex));
					const opened = recipient.open(hex(request.frame_hex));
					assert.equal(opened.payloadJson, request.payload_json);
					assert.equal(opened.exportSecret.toString('hex'), response.export_secret_hex);
					const body = opened.seal(response.payload_json, hex(response.response_nonce_hex));
					assert.equal(body.toString('hex'), response.body_hex);
				});
			}
		});
	}

	it('reference values of docs/HPKE.md', () => {
		assert.equal(VECTORS.request.aad_hex, '0200000065000000006955b900');
		assert.equal(hex(VECTORS.request.frame_hex).length, 317);
		assert.equal(
			sha256(hex(VECTORS.request.frame_hex)),
			'3e4f7f94f4cf99c87b97a2be2419a2d8a7ee0651c821bd572b4dd6e64ff12d0b',
		);
		const success = VECTORS.responses.find((r) => r.name === 'success');
		assert.equal(hex(success.body_hex).length, 305);
		assert.equal(
			sha256(hex(success.body_hex)),
			'29e0c430d4fb4a481605c3353be78e983e6ccfd79c63d2d453de6b95dfbf6811',
		);
		const sealedError = VECTORS.responses.find((r) => r.name === 'sealed_error');
		assert.equal(
			sha256(hex(sealedError.body_hex)),
			'7a282cd5624f6869c7e1367e13e704b9362cb053f639682dad6dbed382944fe4',
		);
	});
});

describe('v2 wire frame', () => {
	it('layout: 0x02 || key_id || timestamp || enc || ct, padded to 256', () => {
		const { pk } = x25519Raw();
		const { body } = H.sealRequestV2(pk, 7, { text: 'hi' }, 1_700_000_000);
		assert.ok(Buffer.isBuffer(body));
		assert.equal(body[0], 2);
		assert.equal(body.readUInt32BE(1), 7);
		assert.equal(body.readBigUInt64BE(5), BigInt(1_700_000_000));
		assert.equal(body.length, 13 + 32 + 256 + 16);
	});

	it('defaults the timestamp to now, and every seal has a fresh enc', () => {
		const { pk } = x25519Raw();
		const before = Math.floor(Date.now() / 1000);
		const a = H.sealRequestV2(pk, 1, { text: 'hi' });
		const b = H.sealRequestV2(pk, 1, { text: 'hi' });
		const ts = Number(a.body.readBigUInt64BE(5));
		assert.ok(ts >= before && ts <= before + 2);
		assert.notDeepEqual(a.body.subarray(13, 45), b.body.subarray(13, 45));
	});

	it('key_id must be an integer in [1, 2^32-1]; the key 32 bytes', () => {
		const { pk } = x25519Raw();
		assert.equal(
			H.sealRequestV2(pk, 0xffffffff, { text: 'hi' }, 1).body.readUInt32BE(1),
			0xffffffff,
		);
		for (const bad of [0, -1, 0x100000000, 1.5, NaN]) {
			assert.throws(() => H.sealRequestV2(pk, bad, { text: 'hi' }, 1), /hpke_seal_failed/);
		}
		assert.throws(
			() => H.sealRequestV2(Buffer.alloc(31), 1, { text: 'hi' }, 1),
			/hpke_seal_failed/,
		);
		assert.throws(
			() => H.sealRequestV2(new Uint8Array(32), 1, { text: 'hi' }, 1),
			/hpke_seal_failed/,
		);
	});

	it('pads to the extension size buckets (UTF-8 bytes)', () => {
		const len = (s) => Buffer.byteLength(H.padToBucket(s), 'utf8');
		assert.equal(len('{"text":"a"}'), 256);
		assert.equal(len('a'.repeat(256)), 256);
		assert.equal(len('a'.repeat(257)), 1024);
		assert.equal(len('a'.repeat(3000)), 4096);
		assert.equal(len('a'.repeat(70000)), 73728);
		assert.equal(len('č'.repeat(200)), 1024); // 400 bytes
		assert.deepEqual(H.PAD_BUCKETS, [256, 1024, 4096, 16384, 65536]);
	});

	it('the body never contains the plaintext', () => {
		const { pk } = x25519Raw();
		const { body } = H.sealRequestV2(pk, 7, { text: 'Janez Novak' }, 1);
		assert.equal(body.toString('latin1').includes('Janez'), false);
		assert.equal(body.toString('latin1').includes('text'), false);
	});

	it('round trip through the independent recipient, random response nonce', () => {
		const recipient = makeRecipient();
		const sealed = H.sealRequestV2(recipient.pkR, 9, { text: 'Ana', entities: ['PERSON'] }, 5);
		const opened = recipient.open(sealed.body);
		assert.equal(opened.keyId, 9);
		assert.equal(opened.timestamp, 5);
		assert.deepEqual(opened.payload, { text: 'Ana', entities: ['PERSON'] });
		const response = { entities: [{ entity_type: 'PERSON', start: 0, end: 3, score: 1 }] };
		assert.deepEqual(sealed.openResponse(opened.seal(response)), response);
	});

	it('openResponse refuses short, v1, tampered and foreign responses', () => {
		const recipient = makeRecipient();
		const sealed = H.sealRequestV2(recipient.pkR, 9, { text: 'hi' }, 5);
		const good = recipient.open(sealed.body).seal({ entities: [] });
		assert.throws(() => sealed.openResponse(good.subarray(0, 48)), /hpke_bad_response/);
		const v1 = Buffer.from(good);
		v1[0] = 1;
		assert.throws(() => sealed.openResponse(v1), /hpke_bad_response/);
		const flipped = Buffer.from(good);
		flipped[flipped.length - 1] ^= 1;
		assert.throws(() => sealed.openResponse(flipped), /hpke_bad_response/);
		const nonceFlipped = Buffer.from(good);
		nonceFlipped[5] ^= 1;
		assert.throws(() => sealed.openResponse(nonceFlipped), /hpke_bad_response/);
		const other = H.sealRequestV2(recipient.pkR, 9, { text: 'hi' }, 5);
		assert.throws(() => other.openResponse(good), /hpke_bad_response/);
		assert.throws(() => sealed.openResponse(new Uint8Array(good)), /hpke_bad_response/);
	});

	it('frozen labels', () => {
		assert.equal(H.WIRE_VERSION, 2);
		assert.equal(H.REQUEST_INFO, 'pgw request v2');
		assert.equal(H.RESPONSE_EXPORT_LABEL, 'pgw response v2');
		assert.equal(H.MIN_RESPONSE_LENGTH, 49);
		assert.equal(H.sealRequest, undefined, 'no v1 seal left');
	});
});

describe('base64url', () => {
	it('round-trips 32 bytes', () => {
		const bytes = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7) % 256));
		const encoded = H.b64urlEncode(bytes);
		assert.match(encoded, /^[A-Za-z0-9_-]+$/);
		assert.deepEqual(H.b64urlDecode(encoded), bytes);
	});

	it('accepts trailing padding, rejects foreign characters', () => {
		assert.deepEqual(H.b64urlDecode('AQID'), Buffer.from([1, 2, 3]));
		assert.deepEqual(H.b64urlDecode('AQI='), Buffer.from([1, 2]));
		assert.throws(() => H.b64urlDecode('AQ+D'));
		assert.throws(() => H.b64urlDecode('AQ D'));
		assert.throws(() => H.b64urlDecode('A'));
	});
});

describe('interop with the extension lib/hpke.js', { skip: EXT_SKIP }, () => {
	it('the extension opens our v2 request, we open its sealed response', async () => {
		const ext = loadExtHpke();
		const { pk, sk } = x25519Raw();
		const text = '😀 Ana Kovač, ana.kovac@example.com';
		const req = H.sealRequestV2(
			pk,
			7,
			{ text, entities: ['PERSON'], possible: true },
			1_700_000_000,
		);
		const opened = await ext.__test.openRequestForTestV2(
			new Uint8Array(sk),
			new Uint8Array(pk),
			new Uint8Array(req.body),
		);
		assert.equal(opened.keyId, 7);
		assert.equal(opened.timestamp, 1_700_000_000);
		assert.equal(opened.payload.text, text);
		assert.deepEqual([...opened.payload.entities], ['PERSON']);
		assert.equal(opened.payload.possible, true);
		const response = { entities: [{ entity_type: 'PERSON', start: 2, end: 11, score: 0.85 }] };
		const sealed = await opened.sealResponse(response);
		assert.deepEqual(req.openResponse(Buffer.from(sealed)), response);
	});

	it('the extension seal opens in the independent recipient and in our openResponse path', async () => {
		const ext = loadExtHpke();
		const recipient = makeRecipient();
		const theirs = await ext.sealRequestV2(new Uint8Array(recipient.pkR), 101, { text: 'Janez' });
		const opened = recipient.open(Buffer.from(theirs.body));
		assert.deepEqual(opened.payload, { text: 'Janez' });
		const response = { entities: [] };
		assert.deepEqual(await theirs.openResponse(new Uint8Array(opened.seal(response))), response);
	});

	it('same fixed ephemeral: our frame equals the extension frame', async () => {
		const ext = loadExtHpke();
		const r = VECTORS.request;
		const key = vectorKey(r.key_id);
		const pkR = x25519Public(hex(key.private_key_hex));
		const theirs = await ext.__test.sealRequestV2WithEphemeral(
			new Uint8Array(pkR),
			r.key_id,
			JSON.parse(r.payload_json),
			{ nowSeconds: r.timestamp, skE: new Uint8Array(hex(r.ephemeral_private_key_hex)) },
		);
		const ours = H.sealRequestV2(
			pkR,
			r.key_id,
			JSON.parse(r.payload_json),
			r.timestamp,
			ephemeral(r),
		);
		assert.equal(Buffer.from(theirs.body).toString('hex'), ours.body.toString('hex'));
		assert.equal(ours.body.toString('hex'), r.frame_hex);
	});

	it('our seal matches the extension seal for the RFC vector ephemeral', async () => {
		const ext = loadExtHpke();
		const theirs = await ext.seal(
			new Uint8Array(hex(V.pkRm)),
			new Uint8Array(hex(V.pt)),
			new Uint8Array(hex(V.aad)),
			new Uint8Array(hex(V.info)),
			{ sk: new Uint8Array(hex(V.skEm)), pkE: new Uint8Array(hex(V.pkEm)) },
		);
		assert.equal(Buffer.from(theirs.ct).toString('hex'), V.ct);
	});

	it('padding and response key derivation agree with the extension', async () => {
		const ext = loadExtHpke();
		for (const n of [0, 1, 255, 256, 257, 1500, 70000]) {
			const s = 'é'.repeat(n);
			assert.equal(H.padToBucket(s), ext.padToBucket(s));
		}
		const secret = Buffer.alloc(32, 7);
		const enc = Buffer.alloc(32, 8);
		const nonce = Buffer.alloc(32, 9);
		const theirs = await ext.__test.deriveResponseV2(
			new Uint8Array(secret),
			new Uint8Array(enc),
			new Uint8Array(nonce),
		);
		const ours = H.deriveResponseKeys(secret, enc, nonce);
		assert.equal(Buffer.from(theirs.key).toString('hex'), ours.key.toString('hex'));
		assert.equal(Buffer.from(theirs.nonce).toString('hex'), ours.nonce.toString('hex'));
	});

	it('a frame for key A does not open with key B; a flipped key_id byte fails', async () => {
		const ext = loadExtHpke();
		const a = x25519Raw();
		const b = x25519Raw();
		const req = H.sealRequestV2(a.pk, 7, { text: 'hi' }, 1);
		await assert.rejects(
			ext.__test.openRequestForTestV2(
				new Uint8Array(b.sk),
				new Uint8Array(b.pk),
				new Uint8Array(req.body),
			),
		);
		const tampered = Buffer.from(req.body);
		tampered[4] ^= 1;
		await assert.rejects(
			ext.__test.openRequestForTestV2(
				new Uint8Array(a.sk),
				new Uint8Array(a.pk),
				new Uint8Array(tampered),
			),
		);
	});
});
