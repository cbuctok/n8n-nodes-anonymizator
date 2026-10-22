// Shared test helpers for protocol v2: the gateway's vectors, Ed25519 signers built from seeds, an
// independent v2 HPKE recipient written with node:crypto (it shares no code with dist/), signed
// keyconfig / capabilities documents, a fake gateway behind httpRequestWithAuthentication, and the
// extension's real lib/hpke.js loaded with node:vm when its checkout is present.
import assert from 'node:assert/strict';
import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	randomBytes,
	sign,
} from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import vm from 'node:vm';

// ---------------------------------------------------------------------------------------------
// Fixtures (copied byte-for-byte from the gateway repository's tests/vectors/)

export const VECTORS = JSON.parse(
	readFileSync(new URL('../fixtures/pgw-v2.json', import.meta.url), 'utf8'),
);
export const CAPS_VECTORS = JSON.parse(
	readFileSync(new URL('../fixtures/pgw-capabilities-v1.json', import.meta.url), 'utf8'),
);

export const hex = (s) => Buffer.from(s, 'hex');
export const ascii = (s) => Buffer.from(s, 'latin1');
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

// ---------------------------------------------------------------------------------------------
// The extension checkout (differential and interop tests skip when it is absent)

const EXT_CANDIDATES = [
	process.env.ANON_EXT_DIR,
	'/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
	'/Users/greg/Repos/projects/prosecco37/anonymizator-chrome/anonymizator-chrome-ext',
].filter(Boolean);

export const EXT_DIR = EXT_CANDIDATES.find((dir) => existsSync(`${dir}/lib/hpke.js`)) ?? null;
export const EXT_SKIP = EXT_DIR ? false : 'extension checkout not found';

/** The extension's real lib/hpke.js in a vm sandbox, with its test hooks enabled. */
export function loadExtHpke() {
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
		Number,
		Object,
		Array,
		Map,
		Set,
		String,
		__ANON_HPKE_TEST__: true,
	};
	sandbox.self = sandbox;
	vm.createContext(sandbox);
	vm.runInContext(readFileSync(`${EXT_DIR}/lib/hpke.js`, 'utf8'), sandbox);
	return sandbox.anonHpke;
}

/** The extension's pinned roots from lib/constants.js. */
export function extPinnedRoots() {
	const sandbox = {};
	sandbox.window = sandbox;
	vm.createContext(sandbox);
	vm.runInContext(readFileSync(`${EXT_DIR}/lib/constants.js`, 'utf8'), sandbox);
	return [...sandbox.ANON.ROOT_KEYCONFIG_PUBKEYS];
}

// ---------------------------------------------------------------------------------------------
// Ed25519 and X25519 from raw bytes

const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

/** An Ed25519 signer from a 32-byte seed (hex or Buffer), or a random one. */
export function ed25519Signer(seed) {
	const privateKey = seed
		? createPrivateKey({
				key: Buffer.concat([ED25519_PKCS8, Buffer.isBuffer(seed) ? seed : hex(seed)]),
				format: 'der',
				type: 'pkcs8',
			})
		: generateKeyPairSync('ed25519').privateKey;
	const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
	return {
		publicKey: b64url(spki.subarray(spki.length - 32)),
		sign: (bytes) => sign(null, Buffer.from(bytes), privateKey),
	};
}

/** The X25519 public key of a raw scalar. */
export function x25519Public(sk) {
	const privateKey = createPrivateKey({
		key: Buffer.concat([X25519_PKCS8, sk]),
		format: 'der',
		type: 'pkcs8',
	});
	const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
	return Buffer.from(spki.subarray(spki.length - 32));
}

/** A fresh raw X25519 key pair. */
export function x25519Raw() {
	const pair = generateKeyPairSync('x25519');
	const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
	const pkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
	return {
		pk: Buffer.from(spki.subarray(spki.length - 32)),
		sk: Buffer.from(pkcs8.subarray(pkcs8.length - 32)),
	};
}

// ---------------------------------------------------------------------------------------------
// Independent HPKE v2 recipient (RFC 9180 base mode + the RFC 9458 response)

const SUITE_ID = Buffer.from('HPKE\x00\x20\x00\x01\x00\x02', 'latin1');
const KEM_ID = Buffer.from('KEM\x00\x20', 'latin1');
const HPKE_V1 = Buffer.from('HPKE-v1');
const hmac = (key, data) =>
	createHmac('sha256', key.length ? key : Buffer.alloc(32))
		.update(data)
		.digest();
function expand(prk, info, length) {
	const out = [];
	let t = Buffer.alloc(0);
	for (let i = 1; Buffer.concat(out).length < length; i++) {
		t = hmac(prk, Buffer.concat([t, info, Buffer.from([i])]));
		out.push(t);
	}
	return Buffer.concat(out).subarray(0, length);
}
const lExtract = (sid, salt, label, ikm) =>
	hmac(salt, Buffer.concat([HPKE_V1, sid, Buffer.from(label), ikm]));
const lExpand = (sid, prk, label, info, length) =>
	expand(
		prk,
		Buffer.concat([
			Buffer.from([length >> 8, length & 255]),
			HPKE_V1,
			sid,
			Buffer.from(label),
			info,
		]),
		length,
	);

/** Pads like the gateway: spaces up to 256/1024/4096/16384/65536, then multiples of 4096. */
export function pad(json) {
	const length = Buffer.byteLength(json);
	const bucket =
		[256, 1024, 4096, 16384, 65536].find((b) => length <= b) ?? Math.ceil(length / 4096) * 4096;
	return json + ' '.repeat(bucket - length);
}

/**
 * A v2 recipient for the raw scalar `sk` (random when omitted). `open(frame)` checks the frame,
 * opens it and returns the payload plus `seal(objOrJson, nonce?)` for the response.
 */
export function makeRecipient(sk) {
	const scalar = sk ?? x25519Raw().sk;
	const pkR = x25519Public(scalar);
	const privateKey = createPrivateKey({
		key: Buffer.concat([X25519_PKCS8, scalar]),
		format: 'der',
		type: 'pkcs8',
	});
	return {
		pkR,
		open(frame) {
			assert.ok(Buffer.isBuffer(frame), 'the request body must be a Buffer');
			assert.equal(frame[0], 2, 'protocol v2 frame');
			assert.ok(frame.length >= 61);
			const prefix = frame.subarray(0, 13);
			const keyId = frame.readUInt32BE(1);
			const timestamp = Number(frame.readBigUInt64BE(5));
			const enc = Buffer.from(frame.subarray(13, 45));
			const ct = frame.subarray(45);
			const pkE = createPublicKey({
				key: Buffer.concat([X25519_SPKI, enc]),
				format: 'der',
				type: 'spki',
			});
			const dh = diffieHellman({ privateKey, publicKey: pkE });
			const eae = lExtract(KEM_ID, Buffer.alloc(0), 'eae_prk', dh);
			const shared = lExpand(KEM_ID, eae, 'shared_secret', Buffer.concat([enc, pkR]), 32);
			const empty = Buffer.alloc(0);
			const ksContext = Buffer.concat([
				Buffer.from([0]),
				lExtract(SUITE_ID, empty, 'psk_id_hash', empty),
				lExtract(SUITE_ID, empty, 'info_hash', Buffer.from('pgw request v2')),
			]);
			const secret = lExtract(SUITE_ID, shared, 'secret', empty);
			const key = lExpand(SUITE_ID, secret, 'key', ksContext, 32);
			const nonce = lExpand(SUITE_ID, secret, 'base_nonce', ksContext, 12);
			const exporter = lExpand(SUITE_ID, secret, 'exp', ksContext, 32);
			const decipher = createDecipheriv('aes-256-gcm', key, nonce);
			decipher.setAAD(prefix);
			decipher.setAuthTag(ct.subarray(ct.length - 16));
			const pt = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
			const exportSecret = lExpand(SUITE_ID, exporter, 'sec', Buffer.from('pgw response v2'), 32);
			let sealed = false;
			return {
				keyId,
				timestamp,
				enc,
				plaintext: pt,
				paddedLength: pt.length,
				payloadJson: pt.toString('utf8').trimEnd(),
				payload: JSON.parse(pt.toString('utf8').trimEnd()),
				exportSecret,
				/** Seals a response (an object, or a string sealed as-is); a fresh nonce unless given. */
				seal(objOrJson, responseNonce) {
					assert.equal(sealed, false, 'one response per request');
					sealed = true;
					const nonce32 = responseNonce ?? randomBytes(32);
					const prk = hmac(Buffer.concat([enc, nonce32]), exportSecret);
					const aeadKey = expand(prk, Buffer.from('key'), 32);
					const aeadNonce = expand(prk, Buffer.from('nonce'), 12);
					const json = typeof objOrJson === 'string' ? objOrJson : JSON.stringify(objOrJson);
					const cipher = createCipheriv('aes-256-gcm', aeadKey, aeadNonce);
					const body = Buffer.from(pad(json), 'utf8');
					return Buffer.concat([
						Buffer.from([2]),
						nonce32,
						cipher.update(body),
						cipher.final(),
						cipher.getAuthTag(),
					]);
				},
			};
		},
	};
}

// ---------------------------------------------------------------------------------------------
// Signed documents

export const AUDIENCE = 'anon.prosecco37.com,app.anonymizator.com';

/**
 * A root + delegated signer pair that mints keyconfig v2 and capabilities responses.
 * `now` is the reference clock; every field can be overridden per document.
 */
export function makeTrustChain({ root = ed25519Signer(), delegated = ed25519Signer() } = {}) {
	function delegation({ serial, notBefore, notAfter, audience = AUDIENCE, signer = root } = {}) {
		const text =
			'pgw-keyconfig-delegation-v2\n' +
			`root=${signer.publicKey}\n` +
			`signing_key=${delegated.publicKey}\n` +
			`audience=${audience}\n` +
			`serial=${serial}\n` +
			`not_before=${notBefore}\n` +
			`not_after=${notAfter}\n`;
		return { b64: b64url(ascii(text)), sig: b64url(signer.sign(ascii(text))) };
	}
	return {
		root,
		delegated,
		roots: [root.publicKey],
		/**
		 * A /v1/keyconfig JSON (v2-only shape). `keys`: [{keyId, pkR, notAfter}].
		 * `serial` defaults to now - 86400 (also not_before), lifetime 30 days.
		 */
		keyconfig({ now, keys, issuedAt = now - 30, serial, notBefore, notAfter, audience } = {}) {
			const s = serial ?? now - 86400;
			const d = delegation({
				serial: s,
				notBefore: notBefore ?? s,
				notAfter: notAfter ?? s + 30 * 86400,
				audience,
			});
			let text = `pgw-keyconfig-v2\nversion=2\nsuite=32,1,2\nissued_at=${issuedAt}\n`;
			for (const k of keys) text += `key=${k.keyId},${b64url(k.pkR)},${k.notAfter}\n`;
			return {
				version: 2,
				v2: {
					delegation: d.b64,
					delegation_sig: d.sig,
					keyconfig: b64url(ascii(text)),
					keyconfig_sig: b64url(delegated.sign(ascii(text))),
				},
			};
		},
		/** A /v1/capabilities JSON over `text` (defaults: the vector document's lines). */
		capabilities({ now, text, serial, notBefore, notAfter, audience } = {}) {
			const s = serial ?? now - 86400;
			const d = delegation({
				serial: s,
				notBefore: notBefore ?? s,
				notAfter: notAfter ?? s + 30 * 86400,
				audience,
			});
			return {
				v1: {
					delegation: d.b64,
					delegation_sig: d.sig,
					capabilities: b64url(ascii(text)),
					capabilities_sig: b64url(delegated.sign(ascii(text))),
				},
			};
		},
	};
}

/** The vector capabilities document re-stamped with another issued_at. */
export function capabilitiesText(issuedAt) {
	return CAPS_VECTORS.document.text.replace(/^issued_at=\d+$/m, `issued_at=${issuedAt}`);
}

// ---------------------------------------------------------------------------------------------
// Fake n8n context and gateway

export const json = (statusCode, object, headers = {}) => ({
	statusCode,
	headers: { 'content-type': 'application/json', ...headers },
	body: Buffer.from(JSON.stringify(object)),
});

export const octet = (statusCode, body) => ({
	statusCode,
	headers: { 'content-type': 'application/octet-stream' },
	body,
});

/**
 * A fake v2 gateway behind httpRequestWithAuthentication. Handlers return full responses:
 *   keyconfig(request) default: the current signed keyconfig;
 *   analyze(opened, request, attempt) default: a sealed {entities: []};
 *   capabilities(request) default: 404.
 * `opened` is the independent recipient's view of the frame (payload, keyId, seal...).
 */
export function makeFakeGateway({
	now,
	chain = makeTrustChain(),
	keyId = 101,
	keyNotAfter,
	keyconfig,
	analyze,
	capabilities,
} = {}) {
	const recipients = new Map();
	const recipient = makeRecipient();
	recipients.set(keyId, recipient);
	const state = {
		chain,
		recipient,
		recipients,
		keyId,
		requests: [],
		opened: [],
		config: chain.keyconfig({
			now,
			keys: [{ keyId, pkR: recipient.pkR, notAfter: keyNotAfter ?? now + 72 * 3600 }],
		}),
	};
	const ctx = {
		getNode: () => ({
			name: 'Anonymizator',
			type: 'test',
			typeVersion: 1,
			position: [0, 0],
			parameters: {},
		}),
		helpers: {
			async httpRequestWithAuthentication(credentialName, options) {
				assert.equal(this, ctx, 'helper must be called with the context as this');
				assert.equal(credentialName, 'anonymizatorApi');
				assert.equal(options.disableFollowRedirect, true);
				assert.equal(options.ignoreHttpStatusErrors, true);
				assert.equal(options.returnFullResponse, true);
				assert.equal(options.encoding, 'arraybuffer');
				state.requests.push(options);
				const url = options.url;
				if (options.method === 'GET' && url === 'https://anon.prosecco37.com/v1/keyconfig') {
					return keyconfig ? keyconfig(options, state) : json(200, state.config);
				}
				if (options.method === 'GET' && url === 'https://anon.prosecco37.com/v1/capabilities') {
					return capabilities ? capabilities(options, state) : json(404, { detail: 'Not Found' });
				}
				if (options.method === 'POST' && url === 'https://anon.prosecco37.com/v1/analyze') {
					assert.ok(Buffer.isBuffer(options.body), 'the body must be a Buffer');
					assert.equal(options.headers['Content-Type'], 'application/octet-stream');
					const frameKeyId = options.body.readUInt32BE(1);
					const r = recipients.get(frameKeyId);
					const opened = r ? r.open(options.body) : null;
					state.opened.push(opened);
					const attempt = state.opened.length;
					if (analyze) return analyze(opened, options, attempt, state);
					return octet(200, opened.seal({ entities: [] }));
				}
				return json(404, { error: 'not_found' });
			},
		},
	};
	state.ctx = ctx;
	/** Rotates to a new key id (the old one stays openable unless `drop`). */
	state.rotate = (newKeyId, { drop = false } = {}) => {
		const r = makeRecipient();
		recipients.set(newKeyId, r);
		if (drop) recipients.delete(state.keyId);
		state.keyId = newKeyId;
		state.config = chain.keyconfig({
			now,
			keys: [{ keyId: newKeyId, pkR: r.pkR, notAfter: now + 72 * 3600 }],
		});
		return r;
	};
	state.posts = () => state.requests.filter((r) => r.method === 'POST');
	state.gets = (path) => state.requests.filter((r) => r.method === 'GET' && r.url.endsWith(path));
	return state;
}
