// HPKE (RFC 9180) and wire-frame tests against the compiled dist/ output.
// The RFC 9180 vector is the official CFRG one for exactly our suite (X25519 / HKDF-SHA256 /
// AES-256-GCM, Base mode). Interop runs against the extension's real lib/hpke.js when that
// checkout is present next to this repo; otherwise those cases are skipped.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const H = require('../dist/nodes/Anonymizator/shared/hpke.js');

const EXT = '/Users/greg/Repos/projects/prosecco37/anonymizator-chrome';
const EXT_HPKE = `${EXT}/anonymizator-chrome-ext/lib/hpke.js`;
const HAVE_EXT = existsSync(EXT_HPKE);

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
const hex = (s) => Buffer.from(s, 'hex');

function loadExtHpke() {
	const sandbox = {
		crypto: globalThis.crypto,
		TextEncoder,
		TextDecoder,
		atob,
		btoa,
		Uint8Array,
		ArrayBuffer,
		DataView,
		BigInt,
		JSON,
		Math,
		Date,
		Error,
		Promise,
	};
	sandbox.self = sandbox;
	vm.createContext(sandbox);
	vm.runInContext(readFileSync(EXT_HPKE, 'utf8'), sandbox);
	return sandbox.anonHpke;
}

function x25519Raw() {
	const pair = generateKeyPairSync('x25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	const pkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
	return {
		pk: Buffer.from(spki.subarray(spki.length - 32)),
		sk: Buffer.from(pkcs8.subarray(pkcs8.length - 32)),
	};
}

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

describe('wire frame', () => {
	it('layout: version || key_id || timestamp || enc || ct, padded to 256', () => {
		const { pk } = x25519Raw();
		const { body } = H.sealRequest(pk, 7, { text: 'hi' }, 1_700_000_000);
		assert.ok(Buffer.isBuffer(body));
		assert.equal(body[0], 1);
		assert.equal(body.readUInt32BE(1), 7);
		assert.equal(body.readBigUInt64BE(5), BigInt(1_700_000_000));
		assert.equal(body.length, 13 + 32 + 256 + 16);
	});

	it('defaults the timestamp to now', () => {
		const { pk } = x25519Raw();
		const before = Math.floor(Date.now() / 1000);
		const { body } = H.sealRequest(pk, 1, { text: 'hi' });
		const ts = Number(body.readBigUInt64BE(5));
		assert.ok(ts >= before && ts <= before + 2);
	});

	it('key_id up to 2^32-1 is encoded unsigned', () => {
		const { pk } = x25519Raw();
		const { body } = H.sealRequest(pk, 0xffffffff, { text: 'hi' }, 1);
		assert.equal(body.readUInt32BE(1), 0xffffffff);
	});

	it('pads to the extension size buckets (UTF-8 bytes)', () => {
		const len = (s) => Buffer.byteLength(H.padToBucket(s), 'utf8');
		assert.equal(len('{"text":"a"}'), 256);
		assert.equal(len('a'.repeat(256)), 256);
		assert.equal(len('a'.repeat(257)), 1024);
		assert.equal(len('a'.repeat(300)), 1024);
		assert.equal(len('a'.repeat(3000)), 4096);
		assert.equal(len('a'.repeat(70000)), 73728);
		assert.equal(len('č'.repeat(200)), 1024); // 400 bytes
		const padded = H.padToBucket(JSON.stringify({ text: 'Janez' }));
		assert.deepEqual(JSON.parse(padded), { text: 'Janez' });
		assert.deepEqual(H.PAD_BUCKETS, [256, 1024, 4096, 16384, 65536]);
	});

	it('the body never contains the plaintext', () => {
		const { pk } = x25519Raw();
		const { body } = H.sealRequest(pk, 7, { text: 'Janez Novak' }, 1);
		assert.equal(body.toString('latin1').includes('Janez'), false);
		assert.equal(body.toString('latin1').includes('text'), false);
	});

	it('openResponse rejects garbage, wrong version and short frames', () => {
		const { pk } = x25519Raw();
		const req = H.sealRequest(pk, 7, { text: 'hi' }, 1);
		assert.throws(() => req.openResponse(Buffer.from([1])));
		assert.throws(() => req.openResponse(Buffer.concat([Buffer.from([2]), Buffer.alloc(40)])));
		assert.throws(() => req.openResponse(Buffer.concat([Buffer.from([1]), Buffer.alloc(40)])));
	});

	it('frozen labels', () => {
		assert.equal(H.RESPONSE_EXPORT_LABEL, 'pgw response v1');
		assert.equal(H.WIRE_VERSION, 1);
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

describe(
	'interop with the extension lib/hpke.js',
	{ skip: !HAVE_EXT && 'extension checkout not found' },
	() => {
		it('the extension opens our request, we open its sealed response', async () => {
			const ext = loadExtHpke();
			const { pk, sk } = x25519Raw();
			const text = '😀 Ana Kovač, ana.kovac@example.com';
			const req = H.sealRequest(pk, 7, { text, entities: ['PERSON'] }, 1_700_000_000);
			const opened = await ext.openRequestForTest(
				new Uint8Array(sk),
				new Uint8Array(pk),
				new Uint8Array(req.body),
			);
			assert.equal(opened.keyId, 7);
			assert.equal(opened.payload.text, text);
			assert.deepEqual([...opened.payload.entities], ['PERSON']);
			const response = { entities: [{ entity_type: 'PERSON', start: 6, end: 16, score: 0.85 }] };
			const sealed = await opened.sealResponse(response);
			assert.deepEqual(req.openResponse(Buffer.from(sealed)), response);
		});

		it('our seal matches the extension seal for the vector ephemeral', async () => {
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

		it('padding agrees with the extension', () => {
			const ext = loadExtHpke();
			for (const n of [0, 1, 255, 256, 257, 1500, 70000]) {
				const s = 'é'.repeat(n);
				assert.equal(H.padToBucket(s), ext.padToBucket(s));
			}
		});

		it('a frame sealed for key A does not open with key B; a flipped key_id byte fails', async () => {
			const ext = loadExtHpke();
			const a = x25519Raw();
			const b = x25519Raw();
			const req = H.sealRequest(a.pk, 7, { text: 'hi' }, 1);
			await assert.rejects(
				ext.openRequestForTest(
					new Uint8Array(b.sk),
					new Uint8Array(b.pk),
					new Uint8Array(req.body),
				),
			);
			const tampered = Buffer.from(req.body);
			tampered[4] ^= 1;
			await assert.rejects(
				ext.openRequestForTest(
					new Uint8Array(a.sk),
					new Uint8Array(a.pk),
					new Uint8Array(tampered),
				),
			);
		});

		it('a tampered response does not open', async () => {
			const ext = loadExtHpke();
			const { pk, sk } = x25519Raw();
			const req = H.sealRequest(pk, 7, { text: 'hi' }, 1);
			const opened = await ext.openRequestForTest(
				new Uint8Array(sk),
				new Uint8Array(pk),
				new Uint8Array(req.body),
			);
			const sealed = Buffer.from(await opened.sealResponse({ entities: [] }));
			sealed[sealed.length - 1] ^= 1;
			assert.throws(() => req.openResponse(sealed));
		});
	},
);
