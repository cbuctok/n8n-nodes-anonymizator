// Shared test helpers for the EXPERIMENTAL protocol v3 (X-Wing; gateway repository
// docs/HPKE-V3-EXPERIMENTAL.md): the gateway's v3 and official X-Wing vectors, an independent v3
// recipient (X-Wing key expansion and decapsulation, the RFC 9180 key schedule and the response
// seal written here with node:crypto; only ML-KEM-768 itself comes from the vendored code, since
// node 22 has none), the gateway's pre-open order for the frame cases (`openRequestForTestV3`),
// signed keyconfig v3 members, and a fake gateway that serves v2 and v3 behind
// httpRequestWithAuthentication.
import assert from 'node:assert/strict';
import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	randomBytes,
} from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';

import { ascii, b64url, hex, json, makeFakeGateway, octet, pad, x25519Public } from './pgw.mjs';

const require = createRequire(import.meta.url);
const { ml_kem768 } = require('../../dist/nodes/Anonymizator/shared/vendor/noblePq.js');

// ---------------------------------------------------------------------------------------------
// Fixtures, copied byte for byte from the gateway repository (branch experimental-pq-v3, commit
// bd97c6f, tests/vectors/). test/vendorNoble.test.mjs pins their SHA-256.

export const V3 = JSON.parse(
	readFileSync(new URL('../fixtures/pgw-v3.json', import.meta.url), 'utf8'),
);
export const XWING = JSON.parse(
	readFileSync(new URL('../fixtures/xwing-official.json', import.meta.url), 'utf8'),
);

// ---------------------------------------------------------------------------------------------
// The extension's vendored bundle of the same pinned noble tarballs (esbuild, unmodified upstream),
// when its experimental-pq-v3 checkout has it: a second opinion for the differential test.

const EXT_BUNDLE_CANDIDATES = [
	process.env.ANON_EXT_DIR && `${process.env.ANON_EXT_DIR}/lib/vendor/noble-pq.js`,
	'/home/ubuntu/repos/prosecco37/anonymizator-chrome/.claude/worktrees/experimental-pq-v3/anonymizator-chrome-ext/lib/vendor/noble-pq.js',
	'/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext/lib/vendor/noble-pq.js',
].filter(Boolean);
export const EXT_BUNDLE = EXT_BUNDLE_CANDIDATES.find((path) => existsSync(path)) ?? null;
export const EXT_BUNDLE_SKIP = EXT_BUNDLE ? false : 'extension noble-pq.js bundle not found';

/** The extension's `self.anonNoblePq`, evaluated in this realm (its option checks are realm-bound). */
export function loadExtNoblePq() {
	const scope = {};
	vm.runInThisContext(`(function (self) {${readFileSync(EXT_BUNDLE, 'utf8')}\n})`)(scope);
	return scope.anonNoblePq;
}

// ---------------------------------------------------------------------------------------------
// X-Wing (draft-connolly-cfrg-xwing-kem-11 section 5), recipient side

const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
export const XWING_LABEL = Buffer.from('5c2e2f2f5e5c', 'hex');
const sha3 = (data) => createHash('sha3-256').update(data).digest();
const shake256 = (data, length) =>
	createHash('shake256', { outputLength: length }).update(data).digest();

/** expandDecapsulationKey(sk): the 32-byte seed to the ML-KEM and X25519 halves and pk. */
export function xwingExpand(seed) {
	assert.equal(seed.length, 32);
	const e = shake256(seed, 96);
	const { publicKey: pkM, secretKey: skM } = ml_kem768.keygen(Uint8Array.from(e.subarray(0, 64)));
	const skX = Buffer.from(e.subarray(64, 96));
	const pkX = x25519Public(skX);
	return { skM: Buffer.from(skM), skX, pkM: Buffer.from(pkM), pkX, pk: Buffer.concat([pkM, pkX]) };
}

/** X-Wing Decapsulate(ct, sk); throws on an all-zero X25519 output (node refuses it). */
export function xwingDecapsulate(enc, expanded) {
	assert.equal(enc.length, 1120);
	const ssM = Buffer.from(
		ml_kem768.decapsulate(Uint8Array.from(enc.subarray(0, 1088)), expanded.skM),
	);
	const ctX = Buffer.from(enc.subarray(1088));
	const ssX = diffieHellman({
		privateKey: createPrivateKey({
			key: Buffer.concat([X25519_PKCS8, expanded.skX]),
			format: 'der',
			type: 'pkcs8',
		}),
		publicKey: createPublicKey({
			key: Buffer.concat([X25519_SPKI, ctX]),
			format: 'der',
			type: 'spki',
		}),
	});
	if (ssX.every((b) => b === 0)) throw new Error('all-zero X25519');
	return sha3(Buffer.concat([ssM, ssX, ctX, expanded.pkX, XWING_LABEL]));
}

// ---------------------------------------------------------------------------------------------
// RFC 9180 key schedule for the suite (0x647a, 1, 2) and the RFC 9458 response

export const SUITE_ID_V3 = Buffer.from('48504b45647a00010002', 'hex');
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

/** The base-mode schedule for `ss` (X-Wing's output is the shared secret as is). */
export function keySchedule(ss, info, sid = SUITE_ID_V3) {
	const empty = Buffer.alloc(0);
	const pskIdHash = lExtract(sid, empty, 'psk_id_hash', empty);
	const infoHash = lExtract(sid, empty, 'info_hash', info);
	const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
	const secret = lExtract(sid, ss, 'secret', empty);
	return {
		pskIdHash,
		infoHash,
		secret,
		key: lExpand(sid, secret, 'key', context, 32),
		baseNonce: lExpand(sid, secret, 'base_nonce', context, 12),
		exporterSecret: lExpand(sid, secret, 'exp', context, 32),
		exportValue: (ctx, length) =>
			lExpand(sid, lExpand(sid, secret, 'exp', context, 32), 'sec', ctx, length),
	};
}

/** Seals a v3 response body: 0x03 || nonce || AES-256-GCM(pad(json)). */
export function sealResponseV3(exportSecret, enc, objOrJson, responseNonce = randomBytes(32)) {
	const prk = hmac(Buffer.concat([enc, responseNonce]), exportSecret);
	const cipher = createCipheriv(
		'aes-256-gcm',
		expand(prk, Buffer.from('key'), 32),
		expand(prk, Buffer.from('nonce'), 12),
	);
	const jsonText = typeof objOrJson === 'string' ? objOrJson : JSON.stringify(objOrJson);
	const body = Buffer.from(pad(jsonText), 'utf8');
	return Buffer.concat([
		Buffer.from([3]),
		responseNonce,
		cipher.update(body),
		cipher.final(),
		cipher.getAuthTag(),
	]);
}

// ---------------------------------------------------------------------------------------------
// The gateway's v3 open path, for the frame cases and the fake gateway

/**
 * A v3 key set `[{keyId, seed, notAfter}]` and a replay cache. `open(frame, {now, v3Enabled})`
 * applies the gateway's pre-open order (section 6.3): length >= 61 -> version (3 only while v3 is
 * enabled) -> v3 length >= 1149 -> stale (60 s) -> v3 key lookup -> key expiry (+300 s) -> open ->
 * replay (key 0x03 || SHA-256(enc), inserted only after a successful open). Returns `{code}` on a
 * refusal or the opened request.
 */
export function makeRecipientV3(keys) {
	const table = new Map(keys.map((k) => [k.keyId, { ...k, expanded: xwingExpand(k.seed) }]));
	const replay = new Set();
	return {
		replay,
		keys: table,
		open(frame, { now, v3Enabled = true }) {
			assert.ok(Buffer.isBuffer(frame), 'the request body must be a Buffer');
			if (frame.length < 61) return { code: 'hpke_bad_frame' };
			if (frame[0] !== 3 || !v3Enabled) return { code: 'hpke_bad_version' };
			if (frame.length < 1149) return { code: 'hpke_bad_frame' };
			const keyId = frame.readUInt32BE(1);
			const timestamp = Number(frame.readBigUInt64BE(5));
			if (Math.abs(timestamp - now) > 60) return { code: 'hpke_stale' };
			const key = table.get(keyId);
			if (!key) return { code: 'hpke_unknown_key' };
			if (now > key.notAfter + 300) return { code: 'hpke_key_expired' };
			const prefix = frame.subarray(0, 13);
			const enc = Buffer.from(frame.subarray(13, 1133));
			const ct = frame.subarray(1133);
			let pt;
			let schedule;
			try {
				const ss = xwingDecapsulate(enc, key.expanded);
				schedule = keySchedule(ss, Buffer.from('pgw request v3'));
				const decipher = createDecipheriv('aes-256-gcm', schedule.key, schedule.baseNonce);
				decipher.setAAD(prefix);
				decipher.setAuthTag(ct.subarray(ct.length - 16));
				pt = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
			} catch {
				return { code: 'hpke_open_failed' };
			}
			const replayKey = Buffer.concat([
				Buffer.from([3]),
				createHash('sha256').update(enc).digest(),
			]).toString('hex');
			if (replay.has(replayKey)) return { code: 'hpke_replay' };
			replay.add(replayKey);
			const exportSecret = lExpand(
				SUITE_ID_V3,
				schedule.exporterSecret,
				'sec',
				Buffer.from('pgw response v3'),
				32,
			);
			let sealed = false;
			return {
				version: 3,
				keyId,
				timestamp,
				enc,
				exportSecret,
				plaintext: pt,
				payloadJson: pt.toString('utf8').trimEnd(),
				payload: JSON.parse(pt.toString('utf8').trimEnd()),
				seal(objOrJson, responseNonce) {
					assert.equal(sealed, false, 'one response per request');
					sealed = true;
					return sealResponseV3(exportSecret, enc, objOrJson, responseNonce);
				},
			};
		},
	};
}

/** The test-only open path over the vector keys (spec section 12.1 `frame_cases`). */
export function openRequestForTestV3(frame, { v3Enabled, now = V3.now, recipient } = {}) {
	const r =
		recipient ??
		makeRecipientV3(
			V3.keys.map((k) => ({ keyId: k.key_id, seed: hex(k.seed), notAfter: k.not_after })),
		);
	return { result: r.open(frame, { now, v3Enabled }), replay: r.replay };
}

// ---------------------------------------------------------------------------------------------
// Signed keyconfig v3 members (same delegation as the v2 member of `chain`)

function delegation(
	chain,
	{ serial, notBefore, notAfter, audience = 'anon.prosecco37.com,app.anonymizator.com' },
) {
	const text =
		'pgw-keyconfig-delegation-v2\n' +
		`root=${chain.root.publicKey}\n` +
		`signing_key=${chain.delegated.publicKey}\n` +
		`audience=${audience}\n` +
		`serial=${serial}\n` +
		`not_before=${notBefore}\n` +
		`not_after=${notAfter}\n`;
	return { b64: b64url(ascii(text)), sig: b64url(chain.root.sign(ascii(text))) };
}

/**
 * A `v3` member signed by `chain`'s delegated key. `keys`: [{keyId, pk (1216 bytes), notAfter}].
 * The delegation defaults match `chain.keyconfig` (serial = not_before = now - 86400, 30 days), so
 * its strings equal the v2 member's.
 */
export function keyconfigV3Member(
	chain,
	{
		now,
		keys,
		issuedAt = now - 30,
		serial,
		notBefore,
		notAfter,
		audience,
		header = 'pgw-keyconfig-v3',
	} = {},
) {
	const s = serial ?? now - 86400;
	const d = delegation(chain, {
		serial: s,
		notBefore: notBefore ?? s,
		notAfter: notAfter ?? s + 30 * 86400,
		audience,
	});
	let text = `${header}\nversion=3\nsuite=25722,1,2\nissued_at=${issuedAt}\n`;
	for (const k of keys) text += `key=${k.keyId},${b64url(k.pk)},${k.notAfter}\n`;
	return {
		delegation: d.b64,
		delegation_sig: d.sig,
		keyconfig: b64url(ascii(text)),
		keyconfig_sig: b64url(chain.delegated.sign(ascii(text))),
	};
}

// ---------------------------------------------------------------------------------------------
// A fake gateway serving v2 and v3

/**
 * The v2 fake gateway (`makeFakeGateway`) plus a v3 key set and member. Options:
 *   v3Enabled (default true): false answers every v3 frame with a plain 400 hpke_bad_version;
 *   offerV3 (default true): false serves /v1/keyconfig without the `v3` member;
 *   v3KeyId (default 1000001), v3Seed (default random);
 *   v3Member(state, base) builds the `v3` member (default: signed for the current v3 key);
 *   analyzeV3(opened, request, state) answers an opened v3 frame (default sealed {entities: []});
 *   analyzeV2 as makeFakeGateway's `analyze`.
 * `state.v3` keeps the recipient, every v3 frame (`frames`) and every open result (`results`).
 */
export function makeFakeGatewayV3({
	now,
	v3Enabled = true,
	offerV3 = true,
	v3KeyId = 1000001,
	v3Seed = randomBytes(32),
	v3Member,
	analyzeV3,
	analyzeV2,
	keyconfig,
	...rest
} = {}) {
	const recipient = makeRecipientV3([{ keyId: v3KeyId, seed: v3Seed, notAfter: now + 72 * 3600 }]);
	const v3 = {
		recipient,
		keyId: v3KeyId,
		enabled: v3Enabled,
		offer: offerV3,
		frames: [],
		results: [],
	};
	const member = (state) =>
		v3Member
			? v3Member(state)
			: keyconfigV3Member(state.chain, {
					now,
					keys: [
						{
							keyId: v3.keyId,
							pk: recipient.keys.get(v3.keyId).expanded.pk,
							notAfter: now + 72 * 3600,
						},
					],
				});
	const gw = makeFakeGateway({
		now,
		...rest,
		keyconfig: (request, state) => {
			if (keyconfig) return keyconfig(request, state);
			return json(200, v3.offer ? { ...state.config, v3: member(state) } : state.config);
		},
		analyze: (opened, request, attempt, state) => {
			const body = request.body;
			if (body[0] === 3) {
				v3.frames.push(body);
				const result = recipient.open(body, { now, v3Enabled: v3.enabled });
				v3.results.push(result);
				if (result.code)
					return json(result.code === 'hpke_replay' ? 409 : 400, { error: result.code });
				if (analyzeV3) return analyzeV3(result, request, state);
				return octet(200, result.seal({ entities: [] }));
			}
			if (analyzeV2) return analyzeV2(opened, request, attempt, state);
			return octet(200, opened.seal({ entities: [] }));
		},
	});
	gw.v3 = v3;
	gw.member = () => member(gw);
	/** Every POSTed frame's version byte, in order. */
	gw.versions = () => gw.posts().map((r) => r.body[0]);
	return gw;
}
