// Keyconfig signature verification and structural validation, against dist/.
// A fresh Ed25519 root is generated in-test; the production root must reject its signatures.
import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

const require = createRequire(import.meta.url);
const K = require('../dist/nodes/Anonymizator/shared/keyconfig.js');
const { GatewayError } = require('../dist/nodes/Anonymizator/shared/errors.js');

const EXT = '/Users/greg/Repos/projects/prosecco37/anonymizator-chrome';

function ed25519Root() {
	const pair = generateKeyPairSync('ed25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	return {
		root: Buffer.from(spki.subarray(spki.length - 32)).toString('base64url'),
		privateKey: pair.privateKey,
	};
}

function x25519PublicB64url() {
	const pair = generateKeyPairSync('x25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	return Buffer.from(spki.subarray(spki.length - 32)).toString('base64url');
}

function canonical(keys) {
	const sorted = [...keys].sort((a, b) => a.key_id - b.key_id);
	return 'pgw-keyconfig-v1\n' + sorted.map((k) => `${k.key_id}:${k.public_key}\n`).join('');
}

function signedConfig(privateKey, keys) {
	return {
		version: 1,
		keys,
		sig_alg: 'ed25519-v1',
		signature: sign(null, Buffer.from(canonical(keys), 'utf8'), privateKey).toString('base64url'),
	};
}

const SUITE = { kem: 32, kdf: 1, aead: 2 };
const entry = (key_id, public_key = x25519PublicB64url()) => ({
	key_id,
	public_key,
	suite: { ...SUITE },
	not_after: '2030-01-01T00:00:00Z',
});

describe('constants', () => {
	it('frozen label, algorithm and suite', () => {
		assert.equal(K.KEYCONFIG_LABEL, 'pgw-keyconfig-v1\n');
		assert.equal(K.SIG_ALG, 'ed25519-v1');
		assert.deepEqual({ ...K.EXPECTED_SUITE }, SUITE);
		assert.equal(K.TRUST_ROOT_B64URL, 'LuE5xR_dLWJhv1BAULCmpijiAV08ceZTeCSkBYLg-bc');
	});

	it(
		'trust root matches the extension',
		{ skip: !existsSync(`${EXT}/anonymizator-chrome-ext/lib/constants.js`) },
		() => {
			const src = readFileSync(`${EXT}/anonymizator-chrome-ext/lib/constants.js`, 'utf8');
			assert.ok(src.includes(`'${K.TRUST_ROOT_B64URL}'`));
		},
	);
});

describe('buildKeyconfigMessage', () => {
	it('sorts by numeric key_id and keeps public_key verbatim', () => {
		const msg = K.buildKeyconfigMessage([
			{ key_id: 10, public_key: 'b' },
			{ key_id: 9, public_key: 'a_-' },
			{ key_id: 100, public_key: 'c' },
		]);
		assert.ok(Buffer.isBuffer(msg));
		assert.equal(msg.toString('utf8'), 'pgw-keyconfig-v1\n9:a_-\n10:b\n100:c\n');
	});

	it('does not reorder the caller array', () => {
		const keys = [
			{ key_id: 2, public_key: 'x' },
			{ key_id: 1, public_key: 'y' },
		];
		K.buildKeyconfigMessage(keys);
		assert.deepEqual(
			keys.map((k) => k.key_id),
			[2, 1],
		);
	});
});

describe('verifyKeyconfig', () => {
	const { root, privateKey } = ed25519Root();
	const keys = [entry(8), entry(3)];
	const good = signedConfig(privateKey, keys);

	it('accepts a config signed by the injected root', () => {
		assert.equal(K.verifyKeyconfig(good, root), true);
	});

	it('the production root rejects a test-root signature', () => {
		assert.equal(K.verifyKeyconfig(good), false);
	});

	it('rejects a public_key swapped after signing', () => {
		const tampered = structuredClone(good);
		tampered.keys[0].public_key = x25519PublicB64url();
		assert.equal(K.verifyKeyconfig(tampered, root), false);
	});

	it('rejects a key_id changed after signing', () => {
		const tampered = structuredClone(good);
		tampered.keys[1].key_id = 4;
		assert.equal(K.verifyKeyconfig(tampered, root), false);
	});

	it('rejects an added key', () => {
		const tampered = structuredClone(good);
		tampered.keys.push(entry(99));
		assert.equal(K.verifyKeyconfig(tampered, root), false);
	});

	it('rejects a wrong or missing sig_alg', () => {
		assert.equal(K.verifyKeyconfig({ ...good, sig_alg: 'ed25519' }, root), false);
		const { sig_alg: _unused, ...noAlg } = good;
		assert.equal(K.verifyKeyconfig(noAlg, root), false);
	});

	it('rejects a missing, empty or malformed signature', () => {
		const { signature: _unused, ...noSig } = good;
		assert.equal(K.verifyKeyconfig(noSig, root), false);
		assert.equal(K.verifyKeyconfig({ ...good, signature: '' }, root), false);
		assert.equal(K.verifyKeyconfig({ ...good, signature: 'not base64!' }, root), false);
		assert.equal(
			K.verifyKeyconfig({ ...good, signature: good.signature.slice(0, 40) }, root),
			false,
		);
		const flipped = Buffer.from(good.signature, 'base64url');
		flipped[0] ^= 1;
		assert.equal(
			K.verifyKeyconfig({ ...good, signature: flipped.toString('base64url') }, root),
			false,
		);
	});

	it('never throws on malformed input', () => {
		for (const bad of [
			null,
			undefined,
			1,
			'x',
			[],
			{},
			{ keys: 'x' },
			{ ...good, keys: [] },
			{ ...good, keys: [null] },
			{ ...good, keys: [{ key_id: '1', public_key: 'x' }] },
		]) {
			assert.equal(K.verifyKeyconfig(bad, root), false);
		}
		assert.equal(K.verifyKeyconfig(good, 'not a root'), false);
		assert.equal(K.verifyKeyconfig(good, root.slice(0, 20)), false);
	});

	it('accepts the extension DEV root signature (shared H4 spec test keypair)', () => {
		const pub = 'ZOyMjidjtZglDJYT5m3qoi1aaUMvXRm-gG6pzHDse4w';
		const priv = createPrivateKey({
			key: { kty: 'OKP', crv: 'Ed25519', d: 'H3WGgPhdAYS7Z1G8EtfWSPjzcGFLInWwhKvWCdAufBw', x: pub },
			format: 'jwk',
		});
		const cfg = signedConfig(priv, [entry(7)]);
		assert.equal(K.verifyKeyconfig(cfg, pub), true);
		assert.equal(K.verifyKeyconfig(cfg, root), false);
	});
});

describe('validateKeyconfig', () => {
	const expectBad = (cfg) =>
		assert.throws(
			() => K.validateKeyconfig(cfg),
			(error) => error instanceof GatewayError && error.code === 'hpke_bad_keyconfig',
		);

	it('returns keys[0] with the decoded 32-byte public key', () => {
		const first = entry(1);
		const result = K.validateKeyconfig({ keys: [first, entry(2)] });
		assert.equal(result.keyId, 1);
		assert.ok(Buffer.isBuffer(result.publicKey));
		assert.equal(result.publicKey.length, 32);
		assert.equal(result.publicKey.toString('base64url'), first.public_key);
	});

	it('accepts key_id 0 and 2^32-1', () => {
		assert.equal(K.validateKeyconfig({ keys: [entry(0)] }).keyId, 0);
		assert.equal(K.validateKeyconfig({ keys: [entry(0xffffffff)] }).keyId, 0xffffffff);
	});

	it('rejects empty keys', () => {
		expectBad({ keys: [] });
		expectBad({});
	});

	it('rejects key_id out of range or not an integer', () => {
		expectBad({ keys: [entry(-1)] });
		expectBad({ keys: [entry(2 ** 32)] });
		expectBad({ keys: [entry(1.5)] });
		expectBad({ keys: [{ ...entry(1), key_id: '1' }] });
	});

	it('rejects a wrong or missing suite', () => {
		expectBad({ keys: [{ ...entry(1), suite: { kem: 32, kdf: 1, aead: 1 } }] });
		expectBad({ keys: [{ ...entry(1), suite: { kem: 16, kdf: 1, aead: 2 } }] });
		const { suite: _unused, ...noSuite } = entry(1);
		expectBad({ keys: [noSuite] });
	});

	it('rejects a public key that is not 32 bytes or not base64url', () => {
		expectBad({ keys: [entry(1, Buffer.alloc(31).toString('base64url'))] });
		expectBad({ keys: [entry(1, Buffer.alloc(33).toString('base64url'))] });
		expectBad({ keys: [entry(1, 'not+base64/url')] });
		expectBad({ keys: [{ ...entry(1), public_key: 5 }] });
	});
});
