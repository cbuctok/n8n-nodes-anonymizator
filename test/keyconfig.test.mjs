// Keyconfig v2 tests against the compiled dist/ output: every keyconfig case of the gateway's
// vectors (test/fixtures/pgw-v2.json), the pinned roots, and a differential run against the
// extension's real lib/hpke.js verifyKeyconfigV2 when its checkout is present.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import {
	EXT_SKIP,
	VECTORS,
	ascii,
	b64url,
	ed25519Signer,
	extPinnedRoots,
	hex,
	loadExtHpke,
	makeTrustChain,
	x25519Raw,
} from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const K = require('../dist/nodes/Anonymizator/shared/keyconfig.js');

const NOW = VECTORS.now;
const PRIMARY = VECTORS.roots.primary.public_key;
const BACKUP = VECTORS.roots.backup.public_key;
const V1_ROOT = 'LuE5xR_dLWJhv1BAULCmpijiAV08ceZTeCSkBYLg-bc';
const AUD = 'anon.prosecco37.com';

function strip(result) {
	if (!result.ok) return { ok: false, error: result.error };
	return { ok: true, keyId: result.keyId };
}

describe('pinned roots', () => {
	it('two roots, never the v1 root, never a test-vector root', () => {
		assert.equal(K.TRUST_ROOTS_B64URL.length, 2);
		for (const root of K.TRUST_ROOTS_B64URL) {
			assert.match(root, /^[A-Za-z0-9_-]{43}$/);
			assert.notEqual(root, V1_ROOT);
			assert.notEqual(root, PRIMARY);
			assert.notEqual(root, BACKUP);
		}
		assert.deepEqual(K.TRUST_ROOTS_B64URL, [
			'lgcsJYcJVj99IW2N5rg73nkRmL0YkuU5uLkR1FsHfhc',
			'ZeXBFyWu8WB0cvyjNIC4LKJymDe5HDb6H08JkcmwdpE',
		]);
	});

	it('the vector keyconfig does not verify against the production roots', () => {
		assert.deepEqual(K.verifyKeyconfigV2(VECTORS.keyconfig_json, K.TRUST_ROOTS_B64URL, NOW, AUD), {
			ok: false,
			error: 'hpke_unverified_keyconfig',
		});
	});

	it('frozen headers and limits match the vectors', () => {
		assert.equal(K.DELEGATION_HEADER, 'pgw-keyconfig-delegation-v2');
		assert.equal(K.KC_DOCUMENT_HEADER, 'pgw-keyconfig-v2');
		const c = VECTORS.constants;
		assert.equal(K.V2_LIMITS.CLIENT_SKEW_S, c.client_skew_s);
		assert.equal(K.V2_LIMITS.KEYCONFIG_MAX_AGE_S, c.keyconfig_max_age_s);
		assert.equal(K.V2_LIMITS.MAX_DELEGATION_LIFETIME_S, c.max_delegation_lifetime_s);
		assert.equal(K.V2_LIMITS.DELEGATION_SERIAL_SLACK_S, c.delegation_serial_slack_s);
		assert.equal(K.V2_LIMITS.KEY_EXPIRY_MARGIN_S, c.key_expiry_margin_s);
		assert.equal(K.V2_LIMITS.MAX_AUDIENCE_HOSTS, c.max_audience_hosts);
	});

	it('equal to the extension lib/constants.js ROOT_KEYCONFIG_PUBKEYS', { skip: EXT_SKIP }, () => {
		assert.deepEqual([...K.TRUST_ROOTS_B64URL], extPinnedRoots());
	});
});

describe('keyconfig_cases (pgw-v2.json)', () => {
	it('has 52 cases', () => {
		assert.equal(VECTORS.keyconfig_cases.length, 52);
	});

	for (const c of VECTORS.keyconfig_cases) {
		it(c.name, () => {
			const result = K.verifyKeyconfigV2(
				c.keyconfig_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			if (c.expect.key_id !== undefined) {
				assert.equal(result.ok, true, JSON.stringify(result));
				assert.equal(result.keyId, c.expect.key_id);
				assert.ok(Buffer.isBuffer(result.publicKey) && result.publicKey.length === 32);
			} else {
				assert.deepEqual(result, { ok: false, error: c.expect.error });
			}
		});
	}

	it('the valid case selects key 101 with its public key, serial and expiry', () => {
		const result = K.verifyKeyconfigV2(
			VECTORS.keyconfig_json,
			[PRIMARY],
			NOW,
			VECTORS.expected_audience,
		);
		const key = VECTORS.hpke_keys.find((k) => k.key_id === 101);
		assert.equal(result.ok, true);
		assert.equal(result.keyId, VECTORS.expected_selection.key_id);
		assert.equal(result.publicKey.toString('base64url'), key.public_key);
		assert.equal(result.notAfter, key.not_after);
		assert.equal(result.serial, 1767139200);
		assert.equal(result.issuedAt, 1767225540);
	});

	it('the documents are the b64 of their text and the signatures reproduce from the seeds', () => {
		const root = ed25519Signer(VECTORS.roots.primary.seed_hex);
		const delegated = ed25519Signer(VECTORS.delegated.seed_hex);
		assert.equal(root.publicKey, PRIMARY);
		assert.equal(delegated.publicKey, VECTORS.delegated.public_key);
		assert.equal(b64url(ascii(VECTORS.delegation.text)), VECTORS.delegation.b64);
		assert.equal(b64url(root.sign(ascii(VECTORS.delegation.text))), VECTORS.delegation.signature);
		assert.equal(b64url(ascii(VECTORS.keyconfig_v2.text)), VECTORS.keyconfig_v2.b64);
		assert.equal(
			b64url(delegated.sign(ascii(VECTORS.keyconfig_v2.text))),
			VECTORS.keyconfig_v2.signature,
		);
	});

	it('an empty root list trusts nothing; a non-finite clock or a non-object fails', () => {
		assert.equal(K.verifyKeyconfigV2(VECTORS.keyconfig_json, [], NOW, AUD).ok, false);
		assert.equal(K.verifyKeyconfigV2(VECTORS.keyconfig_json, [PRIMARY], NaN, AUD).ok, false);
		assert.equal(K.verifyKeyconfigV2(null, [PRIMARY], NOW, AUD).ok, false);
		assert.equal(K.verifyKeyconfigV2('x', [PRIMARY], NOW, AUD).ok, false);
	});

	it('a v2 member on the prototype is not read', () => {
		const config = Object.create({ v2: VECTORS.keyconfig_json.v2 });
		assert.deepEqual(K.verifyKeyconfigV2(config, [PRIMARY], NOW, AUD), {
			ok: false,
			error: 'hpke_unverified_keyconfig',
		});
	});
});

describe('generated chains', () => {
	const now = 1_800_000_000;

	it('selects the highest key id that is valid past now + 300', () => {
		const chain = makeTrustChain();
		const pk = () => x25519Raw().pk;
		const config = chain.keyconfig({
			now,
			keys: [
				{ keyId: 5, pkR: pk(), notAfter: now + 10_000 },
				{ keyId: 9, pkR: pk(), notAfter: now + 301 },
				{ keyId: 12, pkR: pk(), notAfter: now + 300 },
			],
		});
		assert.equal(K.verifyKeyconfigV2(config, chain.roots, now, AUD).keyId, 9);
	});

	it('the second audience host verifies; another host does not', () => {
		const chain = makeTrustChain();
		const config = chain.keyconfig({
			now,
			keys: [{ keyId: 1, pkR: x25519Raw().pk, notAfter: now + 9999 }],
		});
		assert.equal(K.verifyKeyconfigV2(config, chain.roots, now, 'app.anonymizator.com').ok, true);
		assert.equal(K.verifyKeyconfigV2(config, chain.roots, now, 'evil.example.com').ok, false);
	});

	it('S + L malleation of a valid signature is refused', () => {
		const chain = makeTrustChain();
		const config = chain.keyconfig({
			now,
			keys: [{ keyId: 1, pkR: x25519Raw().pk, notAfter: now + 9999 }],
		});
		assert.equal(K.verifyKeyconfigV2(config, chain.roots, now, AUD).ok, true);
		const sig = Buffer.from(config.v2.keyconfig_sig, 'base64url');
		let s = 0n;
		for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
		s += (1n << 252n) + 27742317777372353535851937790883648493n;
		for (let i = 32; i < 64; i++) {
			sig[i] = Number(s & 0xffn);
			s >>= 8n;
		}
		const tampered = { v2: { ...config.v2, keyconfig_sig: sig.toString('base64url') } };
		assert.deepEqual(K.verifyKeyconfigV2(tampered, chain.roots, now, AUD), {
			ok: false,
			error: 'hpke_unverified_keyconfig',
		});
	});

	it('ed25519Verify never throws on garbage', () => {
		const pub = Buffer.from(ed25519Signer().publicKey, 'base64url');
		assert.equal(K.ed25519Verify(pub, Buffer.alloc(64), Buffer.from('x')), false);
		assert.equal(
			K.ed25519Verify(Buffer.alloc(32, 0xff), Buffer.alloc(64, 1), Buffer.from('x')),
			false,
		);
		assert.equal(K.ed25519Verify(Buffer.alloc(31), Buffer.alloc(64), Buffer.from('x')), false);
	});

	it('strict decoders: padding, trailing bits, uint grammar, raw bytes', () => {
		const key = x25519Raw().pk;
		const good = key.toString('base64url');
		assert.deepEqual(K.strictB64.key(good), key);
		assert.equal(K.strictB64.key(`${good}=`), null);
		// 32 bytes = 43 characters: the last one carries 2 unused low bits.
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		const last = alphabet.indexOf(good[good.length - 1]);
		const nonCanonical = good.slice(0, -1) + alphabet[last | 1];
		if (nonCanonical !== good) assert.equal(K.strictB64.key(nonCanonical), null);
		assert.equal(K.parseUint('007'), null);
		assert.equal(K.parseUint('9007199254740992'), null);
		assert.equal(K.parseUint('9007199254740991'), 9007199254740991);
		assert.equal(K.parseUint('١٢'), null);
		assert.equal(K.parseUint(' 7'), null);
		assert.equal(K.documentLines(hex('efbbbf410a')), null);
		assert.equal(K.documentLines(ascii('a=1\r\n')), null);
		assert.equal(K.documentLines(ascii('a=1\n\nb=2\n')), null);
		assert.deepEqual(K.documentLines(ascii('a=1\nb=2\n')), ['a=1', 'b=2']);
	});
});

describe('differential: the extension verifyKeyconfigV2', { skip: EXT_SKIP }, () => {
	it('agrees on every vector case', async () => {
		const ext = loadExtHpke();
		for (const c of VECTORS.keyconfig_cases) {
			const ours = strip(
				K.verifyKeyconfigV2(c.keyconfig_json, c.pinned_roots, c.now, c.expected_audience),
			);
			const theirs = await ext.verifyKeyconfigV2(
				c.keyconfig_json,
				c.pinned_roots,
				c.now,
				c.expected_audience,
			);
			assert.deepEqual(ours, strip(theirs), c.name);
		}
	});

	it('agrees on generated chains around every time boundary', async () => {
		const ext = loadExtHpke();
		const chain = makeTrustChain();
		const base = 1_800_000_000;
		const config = chain.keyconfig({
			now: base,
			issuedAt: base,
			serial: base - 1000,
			keys: [{ keyId: 3, pkR: x25519Raw().pk, notAfter: base + 3000 }],
		});
		for (const delta of [-1301, -1300, -301, -300, -299, 0, 1199, 1200, 1201, 2699, 2700, 2701]) {
			const now = base + delta;
			const ours = strip(K.verifyKeyconfigV2(config, chain.roots, now, AUD));
			const theirs = await ext.verifyKeyconfigV2(config, chain.roots, now, AUD);
			assert.deepEqual(ours, strip(theirs), `delta ${delta}`);
		}
	});
});
