// gateway.ts (protocol v2) against the compiled dist/ output: the gateway's vectors end to end
// through `analyze` (fixed ephemeral key, the vector keyconfig and responses), the offsets vectors,
// and a fake v2 gateway (an independent node:crypto recipient behind httpRequestWithAuthentication)
// for every status, retry, allowlist, keyconfig cache and serial-floor path.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { beforeEach, describe, it } from 'node:test';

import {
	EXT_DIR,
	EXT_SKIP,
	VECTORS,
	hex,
	json,
	makeFakeGateway,
	makeTrustChain,
	octet,
	x25519Public,
} from './helpers/pgw.mjs';

const require = createRequire(import.meta.url);
const G = require('../dist/nodes/Anonymizator/shared/gateway.js');
const { GatewayError } = require('../dist/nodes/Anonymizator/shared/errors.js');
const { gatewayFailure } = require('../dist/nodes/Anonymizator/actions/protect.js');
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

const NODE = {
	name: 'Anonymizator',
	type: 'test',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

const NOW = 1_800_000_000;

beforeEach(() => G.clearGatewayCaches());

async function rejects(promise, code) {
	let error;
	try {
		await promise;
	} catch (e) {
		error = e;
	}
	assert.ok(error instanceof GatewayError, `expected GatewayError(${code}), got ${error}`);
	assert.equal(error.code, code, error.message);
	return error;
}

/** A fake gateway plus the analyze options pointing at its roots and clock. */
function setup(overrides = {}) {
	const gw = makeFakeGateway({ now: NOW, ...overrides });
	const options = {
		trustRootsB64url: gw.chain.roots,
		nowSeconds: NOW,
		retryDelayMs: 1,
		keyconfigRetryDelayMs: 1,
	};
	return { gw, options };
}

const spansOf = (text) => {
	const out = [];
	for (const [type, re] of [
		['PERSON', /Janez Novak|Ana Kovač/gu],
		['EMAIL_ADDRESS', /[a-z.]+@example\.(com|si)/g],
	]) {
		for (const m of text.matchAll(re)) {
			// Code-point offsets, as the gateway reports them.
			const start = [...text.slice(0, m.index)].length;
			out.push({ entity_type: type, start, end: start + [...m[0]].length, score: 0.85 });
		}
	}
	return out;
};

// ---------------------------------------------------------------------------------------------

describe('vectors end to end through analyze (pgw-v2.json)', () => {
	const root = [VECTORS.roots.primary.public_key];
	const request = VECTORS.request;
	const text = JSON.parse(request.payload_json).text;

	function vectorCtx(responseFor, expectedFrameHex) {
		const posts = [];
		const ctx = {
			helpers: {
				async httpRequestWithAuthentication(name, options) {
					if (options.method === 'GET') return json(200, VECTORS.keyconfig_json);
					posts.push(options.body);
					assert.equal(options.body.toString('hex'), expectedFrameHex);
					return responseFor(posts.length);
				},
			},
		};
		return { ctx, posts };
	}
	const eph = (r) => {
		const sk = hex(r.ephemeral_private_key_hex);
		return { sk, pkE: x25519Public(sk) };
	};
	const opts = (r, extra = {}) => ({
		trustRootsB64url: root,
		nowSeconds: r.timestamp,
		testEphemeral: eph(r),
		retryDelayMs: 1,
		...extra,
	});

	it('success: the frame is byte-identical and the spans come back', async () => {
		const success = VECTORS.responses.find((r) => r.name === 'success');
		const { ctx } = vectorCtx(() => octet(200, hex(success.body_hex)), request.frame_hex);
		const result = await G.analyze(ctx, text, undefined, opts(request));
		assert.deepEqual(result, {
			spans: [
				{ entity_type: 'PERSON', start: 11, end: 20, score: 0.85 },
				{ entity_type: 'EMAIL_ADDRESS', start: 22, end: 42, score: 1 },
			],
			possible: [],
			entityFilterIgnored: false,
		});
		assert.deepEqual(
			result.spans.map((s) => text.slice(s.start, s.end)),
			['Ana Kovač', 'ana.kovac@example.si'],
		);
	});

	it('sealed error: invalid_entities without a filter is reported, not retried', async () => {
		const sealedError = VECTORS.responses.find((r) => r.name === 'sealed_error');
		const { ctx, posts } = vectorCtx(
			() => octet(200, hex(sealedError.body_hex)),
			request.frame_hex,
		);
		const error = await rejects(G.analyze(ctx, text, undefined, opts(request)), 'invalid_entities');
		assert.equal(error.httpCode, 200);
		assert.equal(error.detail, undefined);
		assert.equal(posts.length, 1);
	});

	for (const exchange of VECTORS.exchanges) {
		it(`exchange ${exchange.name}: UTF-16 entities and possible spans`, async () => {
			const r = exchange.request;
			const payload = JSON.parse(r.payload_json);
			const response = exchange.responses[0];
			const { ctx } = vectorCtx(() => octet(200, hex(response.body_hex)), r.frame_hex);
			const result = await G.analyze(
				ctx,
				payload.text,
				undefined,
				opts(r, { possible: payload.possible === true }),
			);
			assert.deepEqual(result.spans, exchange.expect.entities_utf16);
			assert.deepEqual(result.possible, exchange.expect.possible_utf16);
			assert.deepEqual(
				result.spans.map((s) => payload.text.slice(s.start, s.end)),
				exchange.expect.entity_values,
			);
			assert.deepEqual(
				result.possible.map((s) => payload.text.slice(s.start, s.end)),
				exchange.expect.possible_values,
			);
		});
	}

	describe('offsets cases', () => {
		assert.equal(VECTORS.offsets.unit, 'unicode_code_point');
		assert.equal(VECTORS.offsets.interval, 'half_open');
		for (const c of VECTORS.offsets.cases) {
			it(c.name, () => {
				assert.equal(c.text.length, c.utf16_units);
				assert.equal([...c.text].length, c.code_points);
				const converted = G.codePointSpansToUtf16(c.text, c.entities);
				assert.deepEqual(converted, c.utf16);
				assert.deepEqual(
					converted.map((s) => c.text.slice(s.start, s.end)),
					c.values,
				);
			});
		}

		it('every case through analyze and the fake gateway', async () => {
			for (const c of VECTORS.offsets.cases) {
				G.clearGatewayCaches();
				const { gw, options } = setup({
					analyze: (opened) => octet(200, opened.seal({ entities: c.entities })),
				});
				const { spans } = await G.analyze(gw.ctx, c.text, undefined, options);
				assert.deepEqual(
					spans.map((s) => c.text.slice(s.start, s.end)),
					c.values,
					c.name,
				);
				assert.equal(gw.opened[0].payload.text, c.text, 'the text is sent unchanged');
			}
		});
	});
});

// ---------------------------------------------------------------------------------------------

describe('analyze: request', () => {
	it('seals {text} only, as a Buffer with the right headers; spans sorted', async () => {
		const text = 'Janez Novak, janez.novak@example.com and Ana Kovač';
		const { gw, options } = setup({
			analyze: (opened) =>
				octet(200, opened.seal({ entities: spansOf(opened.payload.text).reverse() })),
		});
		const result = await G.analyze(gw.ctx, text, undefined, options);
		assert.deepEqual(gw.opened[0].payload, { text });
		assert.equal(gw.opened[0].payloadJson, JSON.stringify({ text }));
		assert.equal(gw.opened[0].keyId, 101);
		assert.equal(gw.opened[0].timestamp, NOW);
		assert.equal(gw.opened[0].paddedLength, 256);
		assert.deepEqual(
			result.spans.map((s) => [s.entity_type, text.slice(s.start, s.end)]),
			[
				['PERSON', 'Janez Novak'],
				['EMAIL_ADDRESS', 'janez.novak@example.com'],
				['PERSON', 'Ana Kovač'],
			],
		);
		const [post] = gw.posts();
		assert.equal(post.headers.Accept, 'application/octet-stream, application/json');
		assert.equal(post.timeout, 30000);
		assert.equal(post.json, false);
		const [get] = gw.gets('/v1/keyconfig');
		assert.equal(get.headers.Accept, 'application/json');
		assert.equal(get.timeout, 15000);
		assert.equal(post.body.toString('latin1').includes('Janez'), false);
	});

	it('entities only for a non-empty filter; possible only when requested', async () => {
		const { gw, options } = setup();
		await G.analyze(gw.ctx, 'x', ['PERSON', 'IBAN'], options);
		await G.analyze(gw.ctx, 'x', [], options);
		await G.analyze(gw.ctx, 'x', undefined, { ...options, possible: true });
		await G.analyze(gw.ctx, 'x', ['PERSON'], { ...options, possible: false });
		assert.deepEqual(
			gw.opened.map((o) => o.payloadJson),
			[
				'{"text":"x","entities":["PERSON","IBAN"]}',
				'{"text":"x"}',
				'{"text":"x","possible":true}',
				'{"text":"x","entities":["PERSON"]}',
			],
		);
	});

	it('works with a context that has no getNode (load options, AI tool)', async () => {
		const { gw, options } = setup();
		delete gw.ctx.getNode;
		const result = await G.analyze(gw.ctx, 'hello', undefined, options);
		assert.deepEqual(result, { spans: [], possible: [], entityFilterIgnored: false });
	});

	it('text over the cap: payload_too_large before anything is sent', async () => {
		const { gw, options } = setup();
		const error = await rejects(
			G.analyze(gw.ctx, 'a'.repeat(120001), undefined, options),
			'payload_too_large',
		);
		assert.equal(error.httpCode, undefined);
		assert.match(error.message, /too long/);
		await rejects(
			G.analyze(gw.ctx, 'a'.repeat(50001), undefined, { ...options, maxTextChars: 50000 }),
			'payload_too_large',
		);
		assert.equal(gw.requests.length, 0);
		await G.analyze(gw.ctx, 'a'.repeat(120000), undefined, options);
		assert.equal(gw.posts().length, 1);
	});

	it('a payload_too_large from the BFF or the gateway names no limit the text already passed', async () => {
		for (const response of [
			() => json(413, { error: 'payload_too_large' }),
			(opened) => octet(200, opened.seal({ error: 'payload_too_large' })),
		]) {
			G.clearGatewayCaches();
			const { gw, options } = setup({ analyze: response });
			const error = await rejects(
				G.analyze(gw.ctx, 'x', undefined, { ...options, maxTextChars: 50000 }),
				'payload_too_large',
			);
			assert.ok(error.httpCode);
			assert.match(error.message, /too long/);
			// What the node shows (protect.ts gatewayFailure gets the local cap as well).
			const shown = gatewayFailure(gw.ctx, error, 0, 50000);
			assert.match(shown.message, /too long/);
			assert.doesNotMatch(`${shown.message} ${shown.description}`, /50,000|120,000/);
		}
		// The local refusal names the limit that applied.
		const { gw, options } = setup();
		const local = await rejects(
			G.analyze(gw.ctx, 'a'.repeat(50001), undefined, { ...options, maxTextChars: 50000 }),
			'payload_too_large',
		);
		assert.match(gatewayFailure(gw.ctx, local, 0, 50000).description, /50,000 characters/);
	});

	it('concurrent analyses share one keyconfig fetch', async () => {
		const { gw, options } = setup();
		await Promise.all([1, 2, 3].map((i) => G.analyze(gw.ctx, `t${i}`, undefined, options)));
		assert.equal(gw.gets('/v1/keyconfig').length, 1);
		assert.equal(gw.posts().length, 3);
	});
});

describe('analyze: response validation (fail closed)', () => {
	const cases = [
		[
			'a span past the end of the text',
			{ entities: [{ entity_type: 'PERSON', start: 0, end: 99 }] },
		],
		['an empty span', { entities: [{ entity_type: 'PERSON', start: 2, end: 2 }] }],
		['a negative start', { entities: [{ entity_type: 'PERSON', start: -1, end: 2 }] }],
		['a fractional offset', { entities: [{ entity_type: 'PERSON', start: 0.5, end: 2 }] }],
		['a string offset', { entities: [{ entity_type: 'PERSON', start: '0', end: 2 }] }],
		['a non-object entity', { entities: [7] }],
		['both entities and error', { entities: [], error: 'internal_error' }],
		['neither', { result: [] }],
		['entities not an array', { entities: {} }],
		['an error that is not a code', { error: 'Bad Thing' }],
		['an array', [1, 2]],
	];
	for (const [name, payload] of cases) {
		it(`${name} -> hpke_bad_response`, async () => {
			const { gw, options } = setup({ analyze: (opened) => octet(200, opened.seal(payload)) });
			await rejects(G.analyze(gw.ctx, 'Janez Novak', undefined, options), 'hpke_bad_response');
			assert.equal(gw.posts().length, 1);
		});
	}

	it('non-JSON plaintext, a foreign seal, a v1 body, a plain 200 -> hpke_bad_response', async () => {
		for (const handler of [
			(opened) => octet(200, opened.seal('not json')),
			() => octet(200, Buffer.alloc(120, 2)),
			() => octet(200, Buffer.concat([Buffer.from([1]), Buffer.alloc(100)])),
			() => json(200, { entities: [] }),
		]) {
			G.clearGatewayCaches();
			const { gw, options } = setup({ analyze: handler });
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_bad_response');
		}
	});

	it('a malformed entity type is kept as PII; a missing score is omitted; other members ignored', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				octet(
					200,
					opened.seal({
						entities: [
							{ entity_type: 'person', start: 0, end: 5 },
							{ entity_type: 'EMAIL_ADDRESS', start: 6, end: 7, score: 'high' },
						],
						extra: true,
						possible: 'ignored when not requested',
					}),
				),
		});
		const { spans, possible } = await G.analyze(gw.ctx, 'Janez x', undefined, options);
		assert.deepEqual(spans, [
			{ entity_type: 'PII', start: 0, end: 5 },
			{ entity_type: 'EMAIL_ADDRESS', start: 6, end: 7 },
		]);
		assert.deepEqual(possible, []);
	});

	it('possible: absent -> [], overlapping spans dropped, malformed -> hpke_bad_response', async () => {
		const text = 'Ana dela pri Modra Vila';
		const entities = [{ entity_type: 'PERSON', start: 0, end: 3 }];
		const run = async (possible) => {
			G.clearGatewayCaches();
			const body = possible === undefined ? { entities } : { entities, possible };
			const { gw, options } = setup({ analyze: (opened) => octet(200, opened.seal(body)) });
			return G.analyze(gw.ctx, text, undefined, { ...options, possible: true });
		};
		assert.deepEqual((await run(undefined)).possible, []);
		assert.deepEqual(
			(
				await run([
					{ start: 13, end: 23, entity_type: 'ORGANIZATION', extra: 1 },
					{ start: 1, end: 5, entity_type: 'ORGANIZATION' },
				])
			).possible,
			[{ start: 13, end: 23, entity_type: 'ORGANIZATION' }],
		);
		for (const bad of [
			{},
			[{ start: 13, end: 99, entity_type: 'ORGANIZATION' }],
			[{ start: 13, end: 23, entity_type: 'organization' }],
			[{ start: 13, end: 23 }],
			[null],
			new Array(10001).fill({ start: 13, end: 23, entity_type: 'ORGANIZATION' }),
		]) {
			await rejects(run(bad), 'hpke_bad_response');
		}
	});

	it('a span ending one past the text fails closed (ASCII and astral text)', async () => {
		const astral = '\u{1F600} Ana'; // 5 code points, 6 UTF-16 units
		assert.equal([...astral].length, 5);
		assert.equal(astral.length, 6);
		for (const [text, payload, possible] of [
			['Call Ana', { entities: [{ entity_type: 'PERSON', start: 5, end: 9 }] }, false],
			[astral, { entities: [{ entity_type: 'PERSON', start: 2, end: 6 }] }, false],
			[astral, { entities: [], possible: [{ entity_type: 'PERSON', start: 2, end: 6 }] }, true],
			['Call Ana', { entities: [], possible: [{ entity_type: 'PERSON', start: 5, end: 9 }] }, true],
		]) {
			G.clearGatewayCaches();
			const { gw, options } = setup({ analyze: (opened) => octet(200, opened.seal(payload)) });
			await rejects(
				G.analyze(gw.ctx, text, undefined, { ...options, possible }),
				'hpke_bad_response',
			);
		}
		// The last code point itself is accepted.
		G.clearGatewayCaches();
		const { gw, options } = setup({
			analyze: (opened) =>
				octet(200, opened.seal({ entities: [{ entity_type: 'PERSON', start: 2, end: 5 }] })),
		});
		const { spans } = await G.analyze(gw.ctx, astral, undefined, options);
		assert.deepEqual(
			spans.map((s) => astral.slice(s.start, s.end)),
			['Ana'],
		);
	});

	it('codePointSpansToUtf16: the end bound is the code-point length', () => {
		const astral = '\u{1F600} Ana';
		const span = (start, end) => [{ entity_type: 'PERSON', start, end }];
		assert.equal(G.codePointSpansToUtf16(astral, span(2, 6)), null);
		assert.deepEqual(G.codePointSpansToUtf16(astral, span(2, 5)), [
			{ entity_type: 'PERSON', start: 3, end: 6 },
		]);
		assert.equal(G.codePointSpansToUtf16('Call Ana', span(5, 9)), null);
		assert.deepEqual(G.codePointSpansToUtf16('Call Ana', span(5, 8)), [
			{ entity_type: 'PERSON', start: 5, end: 8 },
		]);
		// A lone surrogate counts as one code point.
		assert.equal(G.codePointSpansToUtf16('\uD83D x', span(0, 4)), null);
		assert.deepEqual(G.codePointSpansToUtf16('\uD83D x', span(2, 3)), [
			{ entity_type: 'PERSON', start: 2, end: 3 },
		]);
	});
});

// ---------------------------------------------------------------------------------------------

describe('analyze: retries (fresh seal on every attempt)', () => {
	it('hpke_unknown_key: keyconfig refetched, resealed to the new key once', async () => {
		const { gw, options } = setup({
			analyze: (opened, request, attempt, state) => {
				if (attempt === 1) {
					state.rotate(102, { drop: true });
					return json(400, { error: 'hpke_unknown_key' });
				}
				return octet(200, opened.seal({ entities: [] }));
			},
		});
		await G.analyze(gw.ctx, 'x', undefined, options);
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
		assert.deepEqual(
			gw.posts().map((p) => p.body.readUInt32BE(1)),
			[101, 102],
		);
	});

	it('hpke_key_expired the same way; twice in a row is reported', async () => {
		const { gw, options } = setup({ analyze: () => json(400, { error: 'hpke_key_expired' }) });
		const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_key_expired');
		assert.equal(error.httpCode, 400);
		assert.equal(gw.posts().length, 2);
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
	});

	for (const [name, response, code] of [
		[
			'plain 502 upstream_unavailable',
			() => json(502, { error: 'upstream_unavailable' }),
			'upstream_unavailable',
		],
		[
			'plain 504 upstream_timeout',
			() => json(504, { error: 'upstream_timeout' }),
			'upstream_timeout',
		],
		[
			'plain 500 with an unknown code',
			() => json(500, { error: 'kaboom', detail: 'trace' }),
			'server_error',
		],
		['a 503 busy', () => json(503, { error: 'busy' }, { 'retry-after': '2' }), 'busy'],
		[
			'an HTML 502',
			() => ({
				statusCode: 502,
				headers: { 'content-type': 'text/html' },
				body: Buffer.from('<h1>'),
			}),
			'server_error',
		],
	]) {
		it(`${name}: one retry after the pause, then ${code}`, async () => {
			const { gw, options } = setup({ analyze: response });
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
			const posts = gw.posts();
			assert.equal(posts.length, 2);
			assert.notDeepEqual(
				posts[0].body.subarray(13, 45),
				posts[1].body.subarray(13, 45),
				'fresh enc',
			);
			assert.equal(gw.gets('/v1/keyconfig').length, 1);
		});
	}

	it('a sealed internal_error (HTTP 200) is retried; the second attempt can succeed', async () => {
		const { gw, options } = setup({
			analyze: (opened, request, attempt) =>
				octet(200, opened.seal(attempt === 1 ? { error: 'internal_error' } : { entities: [] })),
		});
		const result = await G.analyze(gw.ctx, 'x', undefined, options);
		assert.deepEqual(result.spans, []);
		assert.equal(gw.posts().length, 2);
	});

	it('a 5xx answered with a sealed body is opened (the sealed content decides)', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				octet(500, opened.seal({ entities: [{ entity_type: 'PERSON', start: 0, end: 1 }] })),
		});
		const { spans } = await G.analyze(gw.ctx, 'x', undefined, options);
		assert.equal(spans.length, 1);
		assert.equal(gw.posts().length, 1);
	});

	for (const [name, response, code] of [
		[
			'a sealed invalid_payload with HTTP 503',
			(opened) => octet(503, opened.seal({ error: 'invalid_payload' })),
			'invalid_payload',
		],
		[
			'a sealed payload_too_large with HTTP 500',
			(opened) => octet(500, opened.seal({ error: 'payload_too_large' })),
			'payload_too_large',
		],
		[
			'an octet-stream 502 that does not open',
			() => octet(502, Buffer.alloc(120, 2)),
			'hpke_bad_response',
		],
	]) {
		it(`${name}: the sealed content decides, no retry (${code})`, async () => {
			const { gw, options } = setup({ analyze: response });
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
			assert.equal(gw.posts().length, 1);
		});
	}

	it('a sealed invalid_entities with HTTP 500: one filtered analysis, then the fail-open', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				opened.payload.entities
					? octet(500, opened.seal({ error: 'invalid_entities' }))
					: octet(200, opened.seal({ entities: [] })),
		});
		const result = await G.analyze(gw.ctx, 'x', ['PERSON'], options);
		assert.equal(result.entityFilterIgnored, true);
		assert.equal(gw.posts().length, 2);
	});

	for (const [name, response, code, httpCode] of [
		['409 hpke_replay', () => json(409, { error: 'hpke_replay' }), 'hpke_replay', 409],
		['400 hpke_stale', () => json(400, { error: 'hpke_stale' }), 'hpke_stale', 400],
		[
			'413 payload_too_large',
			() => json(413, { error: 'payload_too_large' }),
			'payload_too_large',
			413,
		],
		[
			'sealed payload_too_large',
			(opened) => octet(200, opened.seal({ error: 'payload_too_large' })),
			'payload_too_large',
			200,
		],
		[
			'sealed hpke_bad_payload',
			(opened) => octet(200, opened.seal({ error: 'hpke_bad_payload' })),
			'hpke_bad_payload',
			200,
		],
		[
			'sealed unknown code',
			(opened) => octet(200, opened.seal({ error: 'brand_new_code' })),
			'http_200',
			200,
		],
		[
			'400 hpke_open_failed',
			() => json(400, { error: 'hpke_open_failed' }),
			'hpke_open_failed',
			400,
		],
		['415 hpke_required', () => json(415, { error: 'hpke_required' }), 'hpke_required', 415],
		[
			'400 unknown code with detail',
			() => json(400, { error: 'secret_code', detail: 'Janez Novak' }),
			'http_400',
			400,
		],
		[
			'404 not JSON',
			() => ({ statusCode: 404, headers: {}, body: Buffer.from('nope') }),
			'http_404',
			404,
		],
	]) {
		it(`${name}: no retry, ${code}`, async () => {
			const { gw, options } = setup({ analyze: response });
			const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
			assert.equal(error.httpCode, httpCode);
			assert.equal(error.detail, undefined, 'server text is never kept');
			assert.ok(!error.message.includes('Janez'));
			assert.equal(gw.posts().length, 1);
		});
	}

	it('429: rate_limited with Retry-After in [1, 300], never retried', async () => {
		for (const [header, expected] of [
			['7', 7],
			['300', 300],
			['0', undefined],
			['301', undefined],
			['Wed, 21 Oct 2026 07:28:00 GMT', undefined],
			[undefined, undefined],
		]) {
			G.clearGatewayCaches();
			const { gw, options } = setup({
				analyze: () => ({
					statusCode: 429,
					headers:
						header === undefined ? { 'content-type': 'text/plain' } : { 'Retry-After': header },
					body: Buffer.from('Too Many Requests'),
				}),
			});
			const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'rate_limited');
			assert.equal(error.retryAfter, expected, String(header));
			assert.equal(error.httpCode, 429);
			assert.equal(gw.posts().length, 1);
		}
	});
});

describe('analyze: entity filter fail-open', () => {
	it('sealed invalid_entities with a filter: one more analysis without it, flagged', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				octet(
					200,
					opened.seal(opened.payload.entities ? { error: 'invalid_entities' } : { entities: [] }),
				),
		});
		const result = await G.analyze(gw.ctx, 'x', ['NOPE'], options);
		assert.equal(result.entityFilterIgnored, true);
		assert.deepEqual(
			gw.opened.map((o) => o.payload),
			[{ text: 'x', entities: ['NOPE'] }, { text: 'x' }],
		);
	});

	it('plain-JSON invalid_entities is handled the same way; possible is kept on the retry', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				opened.payload.entities
					? json(400, { error: 'invalid_entities' })
					: octet(200, opened.seal({ entities: [] })),
		});
		const result = await G.analyze(gw.ctx, 'x', ['NOPE'], { ...options, possible: true });
		assert.equal(result.entityFilterIgnored, true);
		assert.deepEqual(gw.opened[1].payload, { text: 'x', possible: true });
	});

	it('invalid_entities without a filter is reported', async () => {
		const { gw, options } = setup({
			analyze: (opened) => octet(200, opened.seal({ error: 'invalid_entities' })),
		});
		await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'invalid_entities');
		assert.equal(gw.posts().length, 1);
	});

	for (const [name, response, code] of [
		[
			'429 rate_limited',
			() => json(429, { error: 'rate_limited' }, { 'retry-after': '7' }),
			'rate_limited',
		],
		['409 hpke_replay', () => json(409, { error: 'hpke_replay' }), 'hpke_replay'],
		['400 hpke_stale', () => json(400, { error: 'hpke_stale' }), 'hpke_stale'],
		[
			'a sealed invalid_payload',
			(opened) => octet(200, opened.seal({ error: 'invalid_payload' })),
			'invalid_payload',
		],
	]) {
		it(`${name} with a filter: no fail-open, no retry`, async () => {
			const { gw, options } = setup({
				analyze: (opened, request) =>
					opened.payload.entities
						? response(opened, request)
						: octet(200, opened.seal({ entities: [] })),
			});
			await rejects(G.analyze(gw.ctx, 'x', ['PERSON'], options), code);
			assert.equal(gw.posts().length, 1);
			assert.deepEqual(gw.opened[0].payload, { text: 'x', entities: ['PERSON'] });
		});
	}

	it('503 busy with a filter: one retry, both attempts still filtered', async () => {
		const { gw, options } = setup({
			analyze: (opened) =>
				opened.payload.entities
					? json(503, { error: 'busy' })
					: octet(200, opened.seal({ entities: [] })),
		});
		await rejects(G.analyze(gw.ctx, 'x', ['PERSON'], options), 'busy');
		assert.equal(gw.posts().length, 2);
		assert.deepEqual(
			gw.opened.map((o) => o.payload),
			[
				{ text: 'x', entities: ['PERSON'] },
				{ text: 'x', entities: ['PERSON'] },
			],
		);
	});
});

describe('analyze: credential and transport', () => {
	for (const [name, response, code, status] of [
		[
			'302 to the login page',
			() => ({ statusCode: 302, headers: { location: '/auth/login' }, body: Buffer.alloc(0) }),
			'auth_required',
			302,
		],
		['307', () => ({ statusCode: 307, headers: {}, body: Buffer.alloc(0) }), 'auth_required', 307],
		[
			'401 unauthenticated',
			() => json(401, { error: 'unauthenticated', error_description: 'no valid session' }),
			'auth_required',
			401,
		],
		['403 missing_role', () => json(403, { error: 'missing_role' }), 'no_access', 403],
		['403 other', () => json(403, { error: 'forbidden' }), 'http_403', 403],
	]) {
		it(`${name} on analyze -> ${code}`, async () => {
			const { gw, options } = setup({ analyze: response });
			const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
			assert.equal(error.httpCode, status);
			assert.equal(gw.posts().length, 1);
		});

		it(`${name} on keyconfig -> ${code}, nothing sealed`, async () => {
			const { gw, options } = setup({ keyconfig: response });
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
			assert.equal(gw.posts().length, 0);
		});
	}

	it('no response: offline or timeout; n8n errors pass through unchanged', async () => {
		const cases = [
			[Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }), 'offline'],
			[
				Object.assign(new Error('timeout of 30000ms exceeded'), { code: 'ECONNABORTED' }),
				'timeout',
			],
			[new Error('socket hang up'), 'offline'],
		];
		for (const [thrown, code] of cases) {
			G.clearGatewayCaches();
			const ctx = {
				helpers: {
					async httpRequestWithAuthentication() {
						throw thrown;
					},
				},
			};
			await rejects(
				G.analyze(ctx, 'x', undefined, { trustRootsB64url: ['x'], nowSeconds: NOW }),
				code,
			);
		}
		const n8nError = Object.assign(new Error('Node does not have any credentials set'), {
			name: 'NodeOperationError',
		});
		const ctx = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw n8nError;
				},
			},
		};
		await assert.rejects(G.analyze(ctx, 'x'), (e) => e === n8nError);
	});

	it('n8n-core wraps transport failures in a NodeApiError: still offline or timeout', async () => {
		// httpRequestWithAuthentication rethrows every axios failure as
		// `new NodeApiError(this.getNode(), error)`.
		const cases = [
			[
				Object.assign(new Error('connect ECONNREFUSED 10.0.0.1:443'), { code: 'ECONNREFUSED' }),
				'offline',
			],
			[
				Object.assign(new Error('getaddrinfo ENOTFOUND anon.prosecco37.com'), {
					code: 'ENOTFOUND',
				}),
				'offline',
			],
			[
				Object.assign(new Error('timeout of 30000ms exceeded'), { code: 'ECONNABORTED' }),
				'timeout',
			],
			[Object.assign(new Error('connect ETIMEDOUT'), { code: 'ETIMEDOUT' }), 'timeout'],
			[Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }), 'offline'],
		];
		for (const [inner, code] of cases) {
			for (const where of ['keyconfig', 'analyze']) {
				G.clearGatewayCaches();
				const thrower = () => {
					throw new NodeApiError(NODE, inner);
				};
				const { gw, options } = setup(
					where === 'keyconfig' ? { keyconfig: thrower } : { analyze: thrower },
				);
				const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), code);
				assert.equal(error.httpCode, undefined, `${inner.code} on ${where}`);
				assert.equal(gw.posts().length, where === 'keyconfig' ? 0 : 1);
			}
		}
	});

	it('a NodeApiError around an n8n error (missing credential) passes through unchanged', async () => {
		const wrapped = new NodeApiError(
			NODE,
			new NodeOperationError(NODE, 'Node does not have any credentials set'),
		);
		const ctx = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw wrapped;
				},
			},
		};
		await assert.rejects(G.analyze(ctx, 'x'), (e) => e === wrapped);
		const operation = new NodeOperationError(NODE, 'Node does not have any credentials set');
		const ctx2 = {
			helpers: {
				async httpRequestWithAuthentication() {
					throw operation;
				},
			},
		};
		await assert.rejects(G.analyze(ctx2, 'x'), (e) => e === operation);
	});
});

// ---------------------------------------------------------------------------------------------

describe('keyconfig: trust chain (fail closed, nothing sent)', () => {
	const keyFor = (gw, notAfter = NOW + 9999) => [
		{ keyId: gw.keyId, pkR: gw.recipient.pkR, notAfter },
	];

	it('a v1-only keyconfig is not downgraded to: hpke_unverified_keyconfig', async () => {
		const { gw, options } = setup({
			keyconfig: () =>
				json(200, {
					version: 1,
					keys: [{ key_id: 1, public_key: 'A'.repeat(43), suite: { kem: 32, kdf: 1, aead: 2 } }],
					sig_alg: 'ed25519-v1',
					signature: 'A'.repeat(86),
				}),
		});
		const error = await rejects(
			G.analyze(gw.ctx, 'x', undefined, options),
			'hpke_unverified_keyconfig',
		);
		assert.equal(error.httpCode, 200);
		assert.equal(gw.posts().length, 0);
	});

	it('signed by an unpinned root, an HTML login page, a sealed body: unverified', async () => {
		for (const keyconfig of [
			(request, state) => json(200, makeTrustChain().keyconfig({ now: NOW, keys: keyFor(state) })),
			() => ({
				statusCode: 200,
				headers: { 'content-type': 'text/html' },
				body: Buffer.from('<html>login</html>'),
			}),
			() => octet(200, Buffer.alloc(80)),
		]) {
			G.clearGatewayCaches();
			const { gw, options } = setup({ keyconfig });
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_unverified_keyconfig');
			assert.equal(gw.posts().length, 0);
		}
	});

	it('the production roots refuse a test chain', async () => {
		const { gw } = setup();
		await rejects(
			G.analyze(gw.ctx, 'x', undefined, { nowSeconds: NOW }),
			'hpke_unverified_keyconfig',
		);
		assert.equal(gw.posts().length, 0);
	});

	it('a stale keyconfig: hpke_stale_keyconfig; no usable key: hpke_no_usable_key', async () => {
		const stale = setup({
			keyconfig: (request, state) =>
				json(200, state.chain.keyconfig({ now: NOW, issuedAt: NOW - 1201, keys: keyFor(state) })),
		});
		await rejects(G.analyze(stale.gw.ctx, 'x', undefined, stale.options), 'hpke_stale_keyconfig');
		G.clearGatewayCaches();
		const expiring = setup({
			keyconfig: (request, state) =>
				json(200, state.chain.keyconfig({ now: NOW, keys: keyFor(state, NOW + 300) })),
		});
		await rejects(
			G.analyze(expiring.gw.ctx, 'x', undefined, expiring.options),
			'hpke_no_usable_key',
		);
		assert.equal(stale.gw.posts().length + expiring.gw.posts().length, 0);
	});

	it('a keyconfig 5xx is retried once at once, then reported; 429 is not retried', async () => {
		const { gw, options } = setup({ keyconfig: () => json(503, { error: 'hpke_not_configured' }) });
		await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_not_configured');
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
		G.clearGatewayCaches();
		let calls = 0;
		const flaky = setup({
			keyconfig: (request, state) => (++calls === 1 ? json(502, {}) : json(200, state.config)),
		});
		await G.analyze(flaky.gw.ctx, 'x', undefined, flaky.options);
		assert.equal(flaky.gw.gets('/v1/keyconfig').length, 2);
		G.clearGatewayCaches();
		const limited = setup({
			keyconfig: () => json(429, { error: 'rate_limited' }, { 'retry-after': '5' }),
		});
		const error = await rejects(
			G.analyze(limited.gw.ctx, 'x', undefined, limited.options),
			'rate_limited',
		);
		assert.equal(error.retryAfter, 5);
		assert.equal(limited.gw.gets('/v1/keyconfig').length, 1);
	});

	it('acquireKeyconfig returns the selected key', async () => {
		const { gw, options } = setup();
		const kc = await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(kc.ok, true);
		assert.equal(kc.keyId, 101);
		assert.deepEqual(kc.publicKey, gw.recipient.pkR);
	});
});

describe('keyconfig: audience binding (the expected audience is this deployment)', () => {
	for (const audience of ['app.anonymizator.com', 'staging.example.net']) {
		it(`a delegation for ${audience} only: hpke_unverified_keyconfig, nothing sent`, async () => {
			const { gw, options } = setup({
				keyconfig: (request, state) =>
					json(
						200,
						state.chain.keyconfig({
							now: NOW,
							audience,
							keys: [{ keyId: state.keyId, pkR: state.recipient.pkR, notAfter: NOW + 9999 }],
						}),
					),
			});
			await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_unverified_keyconfig');
			assert.equal(gw.posts().length, 0);
			assert.equal(G.delegationFloor(options), 0);
		});
	}

	it('a delegation for anon.prosecco37.com alone verifies', async () => {
		const { gw, options } = setup({
			keyconfig: (request, state) =>
				json(
					200,
					state.chain.keyconfig({
						now: NOW,
						audience: 'anon.prosecco37.com',
						keys: [{ keyId: state.keyId, pkR: state.recipient.pkR, notAfter: NOW + 9999 }],
					}),
				),
		});
		await G.analyze(gw.ctx, 'x', undefined, options);
		assert.equal(gw.posts().length, 1);
	});
});

describe('keyconfig: cache (10 min, re-verified on every use)', () => {
	it('reused within 10 minutes, refetched after', async () => {
		const { gw, options } = setup();
		await G.analyze(gw.ctx, 'x', undefined, options);
		await G.analyze(gw.ctx, 'x', undefined, { ...options, nowSeconds: NOW + 599 });
		assert.equal(gw.gets('/v1/keyconfig').length, 1);
		await G.analyze(gw.ctx, 'x', undefined, { ...options, nowSeconds: NOW + 601 });
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
	});

	it('a cached keyconfig that no longer verifies (stale) is dropped and refetched', async () => {
		let issuedAt = NOW - 1100;
		const { gw, options } = setup({
			keyconfig: (request, state) =>
				json(
					200,
					state.chain.keyconfig({
						now: NOW,
						issuedAt,
						keys: [{ keyId: state.keyId, pkR: state.recipient.pkR, notAfter: NOW + 9999 }],
					}),
				),
		});
		await G.analyze(gw.ctx, 'x', undefined, options);
		issuedAt = NOW + 150;
		await G.analyze(gw.ctx, 'x', undefined, { ...options, nowSeconds: NOW + 200 });
		assert.equal(gw.gets('/v1/keyconfig').length, 2);
	});

	it('the production and a test root never share a cache entry', async () => {
		const { gw, options } = setup();
		await G.analyze(gw.ctx, 'x', undefined, options);
		await rejects(
			G.analyze(gw.ctx, 'x', undefined, { nowSeconds: NOW }),
			'hpke_unverified_keyconfig',
		);
	});
});

describe('keyconfig: delegation serial floor', () => {
	const OLD = NOW - 10 * 86400;
	const NEW = NOW - 3600;

	/** A gateway whose keyconfig answers walk through `serials`, signed at `clock.now - 30`. */
	function chainSetup(serials) {
		const chain = makeTrustChain();
		const clock = { now: NOW };
		let calls = 0;
		const gw = makeFakeGateway({
			now: NOW,
			chain,
			keyconfig: (request, state) => {
				const serial = serials[Math.min(calls++, serials.length - 1)];
				return json(
					200,
					chain.keyconfig({
						now: clock.now,
						serial,
						issuedAt: clock.now - 30,
						keys: [{ keyId: state.keyId, pkR: state.recipient.pkR, notAfter: NOW + 5 * 86400 }],
					}),
				);
			},
		});
		const options = {
			trustRootsB64url: chain.roots,
			nowSeconds: NOW,
			retryDelayMs: 1,
			keyconfigRetryDelayMs: 1,
		};
		return { gw, options, clock };
	}

	it('rises to the highest verified serial and is never lowered', async () => {
		const { gw, options } = chainSetup([OLD, NEW, OLD]);
		await G.acquireKeyconfig(gw.ctx, options);
		assert.equal(G.delegationFloor(options), OLD);
		await G.acquireKeyconfig(gw.ctx, { ...options, force: true });
		assert.equal(G.delegationFloor(options), NEW);
		// The older delegation again: the cached newer config still verifies and is kept.
		const kc = await G.acquireKeyconfig(gw.ctx, { ...options, force: true });
		assert.equal(kc.serial, NEW);
		assert.equal(G.delegationFloor(options), NEW);
		assert.equal(gw.gets('/v1/keyconfig').length, 3);
	});

	it('renewal race without a usable cached config: one refetch after the pause', async () => {
		const { gw, options, clock } = chainSetup([NEW, OLD, NEW]);
		await G.acquireKeyconfig(gw.ctx, options);
		// 1300 s later the cached config is stale; the first replica still serves OLD.
		clock.now = NOW + 1300;
		const kc = await G.acquireKeyconfig(gw.ctx, { ...options, nowSeconds: clock.now });
		assert.equal(kc.serial, NEW);
		assert.equal(gw.gets('/v1/keyconfig').length, 3);
	});

	it('below the floor twice: hpke_unverified_keyconfig, nothing sent', async () => {
		const { gw, options, clock } = chainSetup([NEW, OLD]);
		await G.acquireKeyconfig(gw.ctx, options);
		clock.now = NOW + 1300;
		await rejects(
			G.analyze(gw.ctx, 'x', undefined, { ...options, nowSeconds: clock.now }),
			'hpke_unverified_keyconfig',
		);
		assert.equal(gw.gets('/v1/keyconfig').length, 3);
		assert.equal(gw.posts().length, 0);
		assert.equal(G.delegationFloor(options), NEW);
	});
});

describe('messages', () => {
	it('every GatewayError message is a fixed sentence (no server text)', async () => {
		const { gw, options } = setup({
			analyze: () => json(400, { error: 'hpke_stale', detail: 'Janez Novak' }),
		});
		const error = await rejects(G.analyze(gw.ctx, 'x', undefined, options), 'hpke_stale');
		assert.match(error.message, /clock/);
		assert.ok(!JSON.stringify(error).includes('Janez'));
	});

	it('the allowlists match the extension lib/gateway.js', () => {
		assert.deepEqual([...G.KNOWN_ERROR_CODES].sort(), [
			'busy',
			'hpke_bad_frame',
			'hpke_bad_key_material',
			'hpke_bad_payload',
			'hpke_bad_version',
			'hpke_key_expired',
			'hpke_not_configured',
			'hpke_open_failed',
			'hpke_replay',
			'hpke_required',
			'hpke_stale',
			'hpke_unknown_key',
			'internal_error',
			'invalid_entities',
			'invalid_payload',
			'missing_role',
			'payload_too_large',
			'rate_limited',
			'unauthenticated',
			'upstream_timeout',
			'upstream_unavailable',
		]);
		assert.deepEqual([...G.SEALED_ERROR_CODES].sort(), [
			'hpke_bad_payload',
			'internal_error',
			'invalid_entities',
			'invalid_payload',
			'payload_too_large',
		]);
	});

	it('the allowlists equal the extension lib/gateway.js sets', { skip: EXT_SKIP }, () => {
		const source = readFileSync(`${EXT_DIR}/lib/gateway.js`, 'utf8');
		const set = (name) => {
			const match = source.match(new RegExp(`const ${name} = new Set\\(\\[([^\\]]*)\\]\\)`));
			assert.ok(match, name);
			return [...match[1].matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1]).sort();
		};
		assert.deepEqual([...G.KNOWN_ERROR_CODES].sort(), set('KNOWN_ERROR_CODES'));
		assert.deepEqual([...G.SEALED_ERROR_CODES].sort(), set('SEALED_ERROR_CODES'));
	});
});

describe('gatewayMessages', () => {
	const M = require('../dist/nodes/Anonymizator/shared/gatewayMessages.js');
	const LOCAL = [
		'auth_required',
		'no_access',
		'hpke_unverified_keyconfig',
		'hpke_stale_keyconfig',
		'hpke_no_usable_key',
		'hpke_seal_failed',
		'hpke_bad_response',
		'server_error',
		'timeout',
		'offline',
		'text_too_large',
		'hpke_bad_keyconfig',
	];

	it('covers every allowlisted, sealed and client-side code', () => {
		for (const code of [...G.KNOWN_ERROR_CODES, ...G.SEALED_ERROR_CODES, ...LOCAL]) {
			const entry = M.GATEWAY_MESSAGES[code];
			assert.ok(entry, code);
			assert.ok(entry.message.length > 10 && entry.description.length > 10, code);
		}
	});

	it('follows the wording rules: no "error", "problem" or "failure"', () => {
		for (const [code, { message, description }] of Object.entries(M.GATEWAY_MESSAGES)) {
			assert.doesNotMatch(`${message} ${description}`, /\b(error|problem|failure)s?\b/i, code);
		}
	});

	it('local failures are the client-side codes', () => {
		assert.deepEqual([...M.LOCAL_FAILURES].sort(), [
			'hpke_bad_keyconfig',
			'hpke_bad_response',
			'hpke_no_usable_key',
			'hpke_seal_failed',
			'hpke_stale_keyconfig',
			'hpke_unverified_keyconfig',
			'offline',
			'timeout',
		]);
	});

	it('a server payload_too_large does not claim the local limit', () => {
		for (const httpCode of [413, 200]) {
			const text = M.gatewayErrorText('payload_too_large', { maxTextChars: 120000, httpCode });
			assert.match(text.message, /too long/);
			assert.doesNotMatch(text.description, /[0-9]/, String(httpCode));
		}
		assert.match(
			M.gatewayErrorText('payload_too_large', { maxTextChars: 80000 }).description,
			/80,000 characters/,
		);
	});

	it('gatewayErrorText adds Retry-After, the limit, and a fixed sentence for http_<status>', () => {
		assert.match(
			M.gatewayErrorText('rate_limited', { retryAfter: 12 }).description,
			/Try again in 12 s\.$/,
		);
		assert.doesNotMatch(
			M.gatewayErrorText('rate_limited', { retryAfter: 900 }).description,
			/in 900 s/,
		);
		assert.match(M.gatewayErrorText('payload_too_large').description, /120,000 characters/);
		assert.match(
			M.gatewayErrorText('payload_too_large', { maxTextChars: 50000 }).description,
			/50,000 characters/,
		);
		assert.deepEqual(M.gatewayErrorText('http_404', { httpCode: 404 }), {
			message: 'The Anonymizator gateway answered with an unexpected status (HTTP 404)',
			description: 'Try again later.',
		});
		assert.equal(M.gatewayErrorText('hpke_stale').message, "The n8n host's clock is off");
		assert.equal(M.gatewayErrorText('constructor').description, 'Try again later.');
	});
});
