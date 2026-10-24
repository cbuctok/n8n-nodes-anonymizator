/**
 * Drives the COMPILED node against the live Anonymizator gateway (https://anon.prosecco37.com)
 * with a fake n8n `this` context.
 *
 * The fake `httpRequestWithAuthentication` performs a real `fetch`, adds the Bearer header the
 * credential's `authenticate` block would add, and honours the request options the node relies on
 * the way n8n's helper does: `disableFollowRedirect` (a 302 comes back as 302), `ignoreHttpStatusErrors`
 * (no throw on 4xx/5xx), `returnFullResponse` ({ body, headers, statusCode }), `encoding: 'arraybuffer'`
 * (body is a Buffer), `json: false` and `timeout`.
 *
 * Only synthetic text is sent. The API key is never printed.
 *
 * Usage: npm run build && npm run smoke
 *        (key from ANON_API_KEY, or ANON_API_KEY=... in .env.dev next to package.json)
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const DIST = resolve(here, '../dist/nodes/Anonymizator');

const { Anonymizator } = require(`${DIST}/Anonymizator.node.js`);
const gateway = require(`${DIST}/shared/gateway.js`);
const chunker = require(`${DIST}/shared/chunker.js`);
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

function loadApiKey() {
	if (process.env.ANON_API_KEY) return process.env.ANON_API_KEY.trim();
	try {
		const line = readFileSync(resolve(here, '../.env.dev'), 'utf8')
			.split('\n')
			.find((entry) => entry.startsWith('ANON_API_KEY='));
		if (!line) return undefined;
		return line
			.slice('ANON_API_KEY='.length)
			.trim()
			.replace(/^(['"])(.*)\1$/, '$2');
	} catch {
		return undefined;
	}
}

const apiKey = loadApiKey();
if (!apiKey) {
	console.error('Set ANON_API_KEY, or put ANON_API_KEY=... in .env.dev');
	process.exit(1);
}

/** Never let the key reach the console, whatever a failure message contains. */
function redact(value) {
	const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
	return text === undefined ? String(value) : text.split(apiKey).join('<redacted>');
}

let requestCount = 0;
let analyzeCount = 0;

/** Stand-in for n8n's `httpRequestWithAuthentication`, mirroring its option handling. */
function makeHttp(key) {
	return async function httpRequestWithAuthentication(credentialsType, options) {
		assert.equal(credentialsType, 'anonymizatorApi');
		assert.ok(
			options.body === undefined || Buffer.isBuffer(options.body),
			'request bodies must be Buffers',
		);
		requestCount++;
		if (options.method === 'POST') analyzeCount++;
		const controller = new AbortController();
		const timer = options.timeout ? setTimeout(() => controller.abort(), options.timeout) : null;
		let response;
		try {
			response = await fetch(options.url, {
				method: options.method ?? 'GET',
				headers: { ...options.headers, Authorization: `Bearer ${key.trim()}` },
				body: options.body,
				redirect: options.disableFollowRedirect ? 'manual' : 'follow',
				signal: controller.signal,
			});
		} catch (error) {
			if (controller.signal.aborted) {
				const timeout = new Error(`timeout of ${options.timeout}ms exceeded`);
				timeout.code = 'ECONNABORTED';
				throw timeout;
			}
			throw error;
		} finally {
			if (timer) clearTimeout(timer);
		}

		const raw = Buffer.from(await response.arrayBuffer());
		let body = raw;
		if (options.encoding !== 'arraybuffer') {
			body = raw.toString('utf8');
			if (options.json !== false) {
				try {
					body = JSON.parse(body);
				} catch {}
			}
		}
		const headers = Object.fromEntries(response.headers.entries());

		if (!options.ignoreHttpStatusErrors && (response.status < 200 || response.status >= 300)) {
			const error = new Error(`Request failed with status code ${response.status}`);
			error.response = { status: response.status, headers, data: body };
			throw error;
		}
		if (options.returnFullResponse) {
			return { body, headers, statusCode: response.status, statusMessage: response.statusText };
		}
		return body;
	};
}

const NODE = {
	id: 'smoke',
	name: 'Anonymizator',
	type: 'n8n-nodes-anonymizator.anonymizator',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

function getPath(object, path) {
	let value = object;
	for (const part of path.split('.')) {
		if (value === null || typeof value !== 'object' || !(part in value)) return undefined;
		value = value[part];
	}
	return value;
}

/**
 * @param {object | ((itemIndex: number) => object)} params node parameters, per item via a function
 * @param {object} [setup]
 */
function makeContext(params, { items = [{}], key = apiKey, helpers = true } = {}) {
	return {
		getNode: () => NODE,
		getInputData: () => items.map((json) => ({ json })),
		getNodeParameter(name, itemIndex, fallback) {
			const source = typeof params === 'function' ? params(itemIndex) : params;
			const value = getPath(source, name);
			if (value === undefined) {
				if (arguments.length >= 3) return fallback;
				throw new Error(`Could not get parameter "${name}"`);
			}
			return structuredClone(value);
		},
		getCredentials: async () => ({ apiKey: key }),
		continueOnFail: () => false,
		helpers: helpers ? { httpRequestWithAuthentication: makeHttp(key) } : {},
	};
}

async function execute(params, setup) {
	const [out] = await new Anonymizator().execute.call(makeContext(params, setup));
	return out.map((item) => item.json);
}

function protect(text, extra = {}) {
	return {
		operation: 'protect',
		text,
		detect: 'all',
		placeholderStyle: 'random',
		options: {},
		...extra,
	};
}

function reveal(text, placeholderMap, options = {}) {
	return { operation: 'reveal', text, placeholderMap, options };
}

/** Every entity's offsets must slice its placeholder out of protectedText. */
function assertOffsets(out) {
	for (const entity of out.entities) {
		assert.equal(
			out.protectedText.slice(entity.start, entity.end),
			entity.placeholder,
			`offsets of ${entity.placeholder}`,
		);
	}
}

const PERSON = 'Janez Novak';
const EMAIL = 'ana.kovac@example.com';
const IBAN = 'SI56 1910 0000 0123 438';
const TEXT = `Dear support, my name is ${PERSON} and my email is ${EMAIL}. Please refund the invoice to IBAN ${IBAN}. Thank you!`;

const results = [];

async function scenario(label, fn) {
	const started = Date.now();
	process.stdout.write(`\n=== ${label}\n`);
	try {
		await fn();
		results.push({ label, ok: true, ms: Date.now() - started });
		console.log(`--- PASS (${Date.now() - started} ms)`);
	} catch (error) {
		results.push({ label, ok: false, ms: Date.now() - started });
		console.log(`--- FAIL: ${redact(error?.stack ?? String(error))}`);
		if (error?.description) console.log(`    description: ${redact(error.description)}`);
	}
}

function show(out) {
	console.log(redact(out));
}

let randomRun;
let idFileRun;

await scenario('Keyconfig v2 verifies against the pinned roots', async () => {
	const kc = await gateway.acquireKeyconfig(makeContext({}), { force: true });
	console.log(
		`key_id ${kc.keyId}, delegation serial ${kc.serial}, issued_at ${kc.issuedAt}, key not_after ${kc.notAfter}`,
	);
	assert.ok(Number.isInteger(kc.keyId) && kc.keyId >= 1);
	assert.equal(kc.publicKey.length, 32);
	assert.equal(gateway.delegationFloor(), kc.serial, 'the serial floor was raised');
});

await scenario('Capabilities v1 verify (signed by the same delegation)', async () => {
	const caps = await gateway.fetchCapabilities(makeContext({}));
	assert.ok(caps, 'a verified capabilities document');
	console.log(
		redact({
			serverVersion: caps.serverVersion,
			issuedAt: caps.issuedAt,
			languages: caps.languages,
			features: caps.features,
			maxTextChars: caps.maxTextChars,
			effectiveMaxTextChars: gateway.effectiveMaxTextChars(caps),
			entities: caps.entities.map((e) => `${e.type}:${e.default}`),
			possible: caps.possible.map((p) => p.type),
		}),
	);
	assert.ok(caps.entities.some((e) => e.type === 'PERSON'));
	assert.ok(caps.labels.get('type:PERSON').has('en'));
});

await scenario('Analyze directly: spans (and possible spans when asked)', async () => {
	const text = 'my name is Janez Novak, janez.novak@example.com';
	const result = await gateway.analyze(makeContext({}), text, undefined, { possible: true });
	const found = result.spans.map((s) => [s.entity_type, text.slice(s.start, s.end)]);
	console.log(
		redact({
			spans: found,
			possible: result.possible,
			entityFilterIgnored: result.entityFilterIgnored,
		}),
	);
	assert.ok(found.some(([type, value]) => type === 'PERSON' && value === 'Janez Novak'));
	assert.ok(
		found.some(([type, value]) => type === 'EMAIL_ADDRESS' && value === 'janez.novak@example.com'),
	);
	assert.ok(Array.isArray(result.possible));
});

await scenario(
	'Protect a long text (~40 000 characters) in parts: merged, one placeholder per value',
	async () => {
		const caps = await gateway.fetchCapabilities(makeContext({}));
		const cap = gateway.effectiveMaxTextChars(caps);
		const lines = [];
		for (let i = 0; lines.join('').length < 40000; i++) {
			lines.push(
				i % 7 === 3
					? `Line ${i}: ${TEXT} 😀\n`
					: `Line ${i}: the weather report for the coast says sunny spells and light wind. 🌤\n`,
			);
		}
		const text = lines.join('');
		const parts = chunker.split(text, chunker.partTargetFor(cap));
		const before = analyzeCount;
		const started = Date.now();
		const [out] = await execute(protect(text));
		const sent = analyzeCount - before;
		console.log(
			`${text.length} characters, cap ${cap}, ${parts.length} parts of at most ${chunker.partTargetFor(cap)} code points, ${sent} analyze requests, ${Date.now() - started} ms`,
		);
		assert.ok(parts.length >= 3, 'a multi-part text');
		assert.equal(sent, parts.length, 'one request per part');
		assert.ok(!out.protectedText.includes(PERSON), 'name replaced everywhere');
		assert.ok(!out.protectedText.includes(EMAIL), 'email replaced everywhere');
		const persons = Object.keys(out.placeholderMap).filter((k) => out.placeholderMap[k] === PERSON);
		const emails = Object.keys(out.placeholderMap).filter((k) => out.placeholderMap[k] === EMAIL);
		assert.equal(persons.length, 1, 'one placeholder for the name across every part');
		assert.equal(emails.length, 1, 'one placeholder for the email across every part');
		assertOffsets(out);
		const [revealed] = await execute(reveal(out.protectedText, out.placeholderMap));
		assert.equal(revealed.revealedText, text, 'Reveal restores the whole text');
	},
);

await scenario('Detect a long text in parts: offsets index the original text', async () => {
	const text = Array.from({ length: 300 }, (_, i) =>
		i % 50 === 49
			? `Line ${i}: ${TEXT}\n`
			: `Line ${i}: nothing personal here, only filler text. 😀\n`,
	).join('');
	const before = analyzeCount;
	const [out] = await execute({
		operation: 'detect',
		text,
		detect: 'all',
		options: { includeValues: true },
	});
	console.log(
		`${text.length} characters, ${analyzeCount - before} analyze requests, ${out.entityCount} entities`,
	);
	assert.ok(analyzeCount - before >= 2, 'a multi-part text');
	for (const e of out.entities) assert.equal(text.slice(e.start, e.end), e.value);
	assert.ok(out.entities.some((e) => e.value === EMAIL));
	assert.ok(out.entities.filter((e) => e.value === EMAIL).length >= 5, 'found in every part');
});

await scenario('Protect, all types, random placeholders', async () => {
	const [out] = await execute(protect(TEXT));
	show(out);
	randomRun = out;
	assert.ok(!out.protectedText.includes(PERSON), 'name replaced');
	assert.ok(!out.protectedText.includes(EMAIL), 'email replaced');
	assert.match(out.protectedText, /\[PERSON_[a-z0-9]{5}\]/);
	// Placeholders use the extension's prefixes: EMAIL_ADDRESS -> [EMAIL_...].
	assert.match(out.protectedText, /\[EMAIL_[a-z0-9]{5}\]/);
	assert.ok(out.entities.some((e) => e.entityType === 'EMAIL_ADDRESS'));
	for (const entity of out.entities) {
		assert.deepEqual(Object.keys(entity), ['entityType', 'placeholder', 'start', 'end', 'score']);
	}
	assert.ok(Object.values(out.placeholderMap).includes(PERSON));
	assert.ok(Object.values(out.placeholderMap).includes(EMAIL));
	assert.ok(Object.values(out.placeholderMap).includes('Janez'), 'PERSON _NAME sub-key');
	assert.ok(Object.values(out.placeholderMap).includes('Novak'), 'PERSON _SURNAME sub-key');
	assert.equal(out.entityFilterIgnored, undefined);
	assertOffsets(out);
});

await scenario('Reveal round trip of the random run (no network)', async () => {
	const before = requestCount;
	const [out] = await execute(reveal(randomRun.protectedText, randomRun.placeholderMap), {
		helpers: false,
	});
	show(out);
	assert.equal(out.revealedText, TEXT);
	assert.deepEqual(out.unresolvedPlaceholders, []);
	assert.equal(requestCount, before, 'reveal made no request');
});

await scenario('Protect, selected types (EMAIL_ADDRESS only)', async () => {
	const [out] = await execute(
		protect(TEXT, { detect: 'selected', entityTypes: ['EMAIL_ADDRESS'] }),
	);
	show(out);
	assert.ok(out.protectedText.includes(PERSON), 'name kept');
	assert.ok(!out.protectedText.includes(EMAIL), 'email replaced');
	assert.ok(out.entities.length > 0);
	for (const entity of out.entities) assert.equal(entity.entityType, 'EMAIL_ADDRESS');
	assert.deepEqual(Object.values(out.placeholderMap), [EMAIL]);
	assertOffsets(out);
});

await scenario('Protect, sequential, continuing an existing map', async () => {
	const existing = {
		'[PERSON_1]': PERSON,
		'[PERSON_1_NAME]': 'Janez',
		'[PERSON_1_SURNAME]': 'Novak',
		'[EMAIL_ADDRESS_1]': EMAIL,
		'[PERSON_2]': '',
	};
	const text = `${PERSON} forwarded the case to Ana Kovač (marko.horvat@example.com). ${PERSON} is on holiday.`;
	const [out] = await execute(
		protect(text, {
			placeholderStyle: 'sequential',
			options: { existingPlaceholderMap: JSON.stringify(existing) },
		}),
	);
	show(out);
	assert.ok(out.protectedText.startsWith('[PERSON_1] forwarded'), 'known value reuses [PERSON_1]');
	assert.ok(out.protectedText.includes('[PERSON_3]'), 'new person continues after the tombstone');
	assert.ok(!out.protectedText.includes('[PERSON_2]'), 'tombstoned key never reused');
	assert.match(out.protectedText, /\[EMAIL_1\]/, 'a new email gets the EMAIL prefix');
	assert.equal(out.placeholderMap.PERSON_1, PERSON);
	assert.equal(out.placeholderMap.EMAIL_ADDRESS_1, EMAIL, 'map keeps existing entries');
	// The gateway decides the exact range: in this sentence it currently tags only "Kovač".
	assert.match(out.placeholderMap.PERSON_3 ?? '', /Kovač$/);
	assertOffsets(out);
	const [back] = await execute(reveal(out.protectedText, out.placeholderMap));
	assert.equal(back.revealedText, text);
});

await scenario('Protect, type-only masking', async () => {
	const [out] = await execute(protect(TEXT, { placeholderStyle: 'typed' }));
	show(out);
	assert.ok(out.protectedText.includes('[PERSON]'));
	assert.ok(out.protectedText.includes('[EMAIL]'));
	assert.ok(!out.protectedText.includes(PERSON) && !out.protectedText.includes(EMAIL));
	assert.deepEqual(out.placeholderMap, {});
	assertOffsets(out);
});

await scenario('Protect, redacted', async () => {
	const [out] = await execute(protect(TEXT, { placeholderStyle: 'redacted' }));
	show(out);
	assert.ok(out.protectedText.includes('[REDACTED]'));
	assert.ok(!/\[PERSON|\[EMAIL/.test(out.protectedText));
	assert.ok(!out.protectedText.includes(PERSON) && !out.protectedText.includes(EMAIL));
	assert.deepEqual(out.placeholderMap, {});
	assertOffsets(out);
});

await scenario('Protect, Share Map Across Items with 2 items', async () => {
	const texts = [
		`Meeting notes: ${PERSON} will call back tomorrow.`,
		`Reminder for ${PERSON}: send the contract to ${EMAIL}.`,
	];
	const outs = await execute(
		(i) =>
			protect(texts[i], {
				placeholderStyle: 'random',
				options: { shareMapAcrossItems: true, includeInputFields: true },
			}),
		{ items: texts.map((body, i) => ({ body, n: i })) },
	);
	show(outs);
	assert.equal(outs.length, 2);
	const key = Object.keys(outs[0].placeholderMap).find((k) => outs[0].placeholderMap[k] === PERSON);
	assert.ok(key, 'item 1 has the person');
	assert.ok(outs[0].protectedText.includes(`[${key}]`));
	assert.ok(outs[1].protectedText.includes(`[${key}]`), 'item 2 reuses the same placeholder');
	for (const [k, v] of Object.entries(outs[0].placeholderMap)) {
		assert.equal(outs[1].placeholderMap[k], v, 'item 2 map is a superset of item 1 map');
	}
	assert.equal(outs[1].n, 1, 'input fields included');
	for (let i = 0; i < 2; i++) {
		const [back] = await execute(reveal(outs[i].protectedText, outs[1].placeholderMap));
		assert.equal(back.revealedText, texts[i]);
	}
});

await scenario('Protect with Include ID File, emoji before the name', async () => {
	const text = `😀😀 ${PERSON}, ${EMAIL} 👍`;
	const [out] = await execute(protect(text, { options: { includeIdFile: true } }));
	show(out);
	idFileRun = { text, out };
	assert.ok(!out.protectedText.includes(PERSON) && !out.protectedText.includes(EMAIL));
	assert.ok(out.protectedText.startsWith('😀😀 [PERSON_'), 'emoji kept, offsets in UTF-16');
	assert.equal(out.idFile.format, 'anonymizator-id-file');
	assert.equal(out.idFile.version, 2);
	assert.ok(out.idFile.ids.every((entry) => typeof entry.type === 'string'));
	assert.equal(out.idFile.numbering, 'random');
	assertOffsets(out);
});

await scenario('Reveal with an extension ID file as the map', async () => {
	const { text, out } = idFileRun;
	// As an object and as the JSON text a Read File / Extract From File node would hand over.
	for (const map of [out.idFile, JSON.stringify(out.idFile)]) {
		const [back] = await execute(reveal(`${out.protectedText} [PERSON_zzzzz]`, map), {
			helpers: false,
		});
		show(back);
		assert.equal(back.revealedText, `${text} [PERSON_zzzzz]`);
		assert.deepEqual(back.unresolvedPlaceholders, ['[PERSON_zzzzz]']);
	}
});

await scenario('Detect, all types, with values; offsets index the original text', async () => {
	const text = `😀😀 ${TEXT}`;
	const [out] = await execute({
		operation: 'detect',
		text,
		detect: 'all',
		options: { includeValues: true },
	});
	show(out);
	assert.equal(out.hasPersonalData, true);
	assert.equal(out.entityCount, out.entities.length);
	const total = Object.values(out.countsByType).reduce((a, b) => a + b, 0);
	assert.equal(total, out.entityCount);
	for (const entity of out.entities) {
		assert.equal(text.slice(entity.start, entity.end), entity.value, `offsets of ${entity.value}`);
	}
	const values = out.entities.map((e) => e.value);
	assert.ok(values.includes(PERSON), 'name detected');
	assert.ok(values.includes(EMAIL), 'email detected');
	assert.ok(out.countsByType.PERSON >= 1 && out.countsByType.EMAIL_ADDRESS >= 1);
});

await scenario('Detect, selected types, no values; nothing found in plain text', async () => {
	const [out] = await execute({
		operation: 'detect',
		text: TEXT,
		detect: 'selected',
		entityTypes: ['EMAIL_ADDRESS'],
		options: {},
	});
	show(out);
	assert.deepEqual(Object.keys(out.countsByType), ['EMAIL_ADDRESS']);
	assert.ok(!JSON.stringify(out).includes(EMAIL), 'no values without Include Values');
	const [none] = await execute({
		operation: 'detect',
		text: 'The weather is nice today.',
		detect: 'all',
		options: {},
	});
	show(none);
	assert.equal(none.hasPersonalData, false);
	assert.equal(none.entityCount, 0);
});

await scenario('Ignore Terms: Protect keeps the term, Detect drops it', async () => {
	const [out] = await execute(protect(TEXT, { options: { ignoreTerms: `janez novak, Other Co` } }));
	show(out);
	assert.ok(out.protectedText.includes(PERSON), 'ignored name kept');
	assert.ok(!out.protectedText.includes(EMAIL), 'email still replaced');
	assert.ok(!Object.values(out.placeholderMap).includes(PERSON));
	assertOffsets(out);
	const [detected] = await execute({
		operation: 'detect',
		text: TEXT,
		detect: 'all',
		options: { ignoreTerms: PERSON.toUpperCase(), includeValues: true },
	});
	show(detected);
	assert.ok(!detected.entities.some((e) => e.value === PERSON), 'ignored name not reported');
	assert.ok(detected.entities.some((e) => e.value === EMAIL));
});

await scenario('Include Placeholder Map off: no map in the output', async () => {
	const [out] = await execute(protect(TEXT, { options: { includePlaceholderMap: false } }));
	show(out);
	assert.equal(out.placeholderMap, undefined);
	assert.equal(out.idFile, undefined);
	assert.ok(!JSON.stringify(out).includes(PERSON), 'no real value anywhere in the output');
	assert.ok(!JSON.stringify(out).includes(EMAIL), 'no real value anywhere in the output');
	assert.match(out.protectedText, /\[PERSON_[a-z0-9]{5}\]/);
	assertOffsets(out);
});

await scenario('Entity Types list: bundled rows plus verified server types', async () => {
	const options = await new Anonymizator().methods.loadOptions.getEntityTypes.call(makeContext({}));
	console.log(redact(options.map((o) => `${o.value}: ${o.name}`)));
	for (const id of ['PERSON', 'EMAIL_ADDRESS', 'IBAN', 'EMSO', 'IP_ADDRESS']) {
		assert.ok(
			options.some((o) => o.value === id),
			id,
		);
	}
	assert.equal(options.find((o) => o.value === 'PERSON').name, 'Names');
});

await scenario('Protect, selected server-only type from the capabilities', async () => {
	const caps = await gateway.fetchCapabilities(makeContext({}));
	const serverOnly = caps.entities
		.map((e) => e.type)
		.filter((t) => !['PERSON', 'EMAIL_ADDRESS', 'IBAN', 'IBAN_CODE'].includes(t));
	const [out] = await execute(
		protect(TEXT, { detect: 'selected', entityTypes: ['EMAIL_ADDRESS', serverOnly[0]] }),
	);
	show({ selected: ['EMAIL_ADDRESS', serverOnly[0]], out });
	assert.equal(out.entityFilterIgnored, undefined, 'the gateway accepted the filter');
	assert.ok(out.protectedText.includes(PERSON), 'name kept');
	assert.ok(!out.protectedText.includes(EMAIL), 'email replaced');
});

await scenario('Protect, Additionally Protect (numbers, currency values, companies)', async () => {
	const text = `${PERSON} of Modra Vila d.o.o. paid 4.800,00 EUR for order K101.`;
	const before = requestCount;
	const [out] = await execute(
		protect(text, {
			placeholderStyle: 'sequential',
			options: { additionallyProtect: ['NUMBER', 'AMOUNT', 'COMPANY'] },
		}),
	);
	show(out);
	assert.match(out.protectedText, /\[COMPANY_1\]/);
	assert.match(out.protectedText, /\[AMOUNT_1\]/);
	assert.match(out.protectedText, /\[NUMBER_1\]/);
	assert.ok(!out.protectedText.includes('Modra Vila'));
	assert.ok(!out.protectedText.includes('4.800'));
	assert.ok(requestCount - before <= 2, 'one analyze request (plus a capabilities refresh)');
	assertOffsets(out);
	const [back] = await execute(reveal(out.protectedText, out.placeholderMap), { helpers: false });
	assert.equal(back.revealedText, text);
});

await scenario('Protect and Detect with Include Possible IDs', async () => {
	const caps = await gateway.fetchCapabilities(makeContext({}));
	console.log(`capabilities list possible types: ${redact(caps.possible.map((p) => p.type))}`);
	const text = `${PERSON} called. Later I wrote to Janezu at Modra Vila, from Modra Vila d.o.o.`;
	const [out] = await execute(
		protect(text, { options: { includePossibleIds: true, additionallyProtect: ['COMPANY'] } }),
	);
	show(out);
	assert.ok(Array.isArray(out.possibleIds));
	for (const p of out.possibleIds) {
		assert.equal(out.protectedText.slice(p.start, p.end), p.value, `offsets of ${p.value}`);
		assert.deepEqual(Object.keys(p), ['start', 'end', 'value', 'kind', 'type']);
	}
	// Server-side detection decides what is left in clear: production tagged "Janezu" as PERSON
	// on 2026-10-21. Only when it is left in clear must it be listed as a case form.
	if (!Object.values(out.placeholderMap).includes('Janezu')) {
		assert.ok(
			out.possibleIds.some((p) => p.value === 'Janezu' && p.kind === 'case-form'),
			'case form of a protected name',
		);
	}
	const [detected] = await execute({
		operation: 'detect',
		text,
		detect: 'all',
		options: { includePossibleIds: true, includeValues: true },
	});
	show(detected);
	assert.ok(Array.isArray(detected.possibleIds));
	for (const p of detected.possibleIds) assert.equal(text.slice(p.start, p.end), p.value);
});

await scenario('Bad API key: friendly rejected-key error, not success', async () => {
	gateway.clearGatewayCaches();
	let caught;
	try {
		await execute(protect(TEXT), { key: 'anon_not_a_real_key_0000000000' });
	} catch (error) {
		caught = error;
	}
	assert.ok(caught, 'the node must fail');
	console.log(
		`${caught.constructor.name}: ${redact(caught.message)}\n  httpCode: ${caught.httpCode}\n  description: ${redact(caught.description)}`,
	);
	assert.ok(caught instanceof NodeApiError || caught instanceof NodeOperationError);
	assert.equal(caught.message, 'The Anonymizator API key was rejected');
});

await scenario('Bad API key with a warm keyconfig cache (rejected on /v1/analyze)', async () => {
	await execute(protect('Hello Janez Novak'));
	let caught;
	try {
		await execute(protect(TEXT), { key: 'anon_not_a_real_key_0000000000' });
	} catch (error) {
		caught = error;
	}
	assert.ok(caught, 'the node must fail');
	console.log(`${caught.constructor.name}: ${caught.message} (httpCode ${caught.httpCode})`);
	assert.equal(caught.message, 'The Anonymizator API key was rejected');
});

console.log('\n=== Summary');
for (const { label, ok, ms } of results) {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${label} (${ms} ms)`);
}
console.log(`${requestCount} gateway requests`);
const failed = results.filter((r) => !r.ok).length;
console.log(failed === 0 ? 'Smoke passed' : `Smoke FAILED (${failed})`);
process.exit(failed === 0 ? 0 : 1);
