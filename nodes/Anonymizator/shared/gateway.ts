/**
 * Transport to the Anonymizator privacy gateway: keyconfig fetch + verification (cached 10 min per
 * base URL), HPKE-sealed `/v1/analyze`, status mapping, single retries.
 *
 * Every request goes through `ctx.helpers.httpRequestWithAuthentication.call(ctx, 'anonymizatorApi',
 * { disableFollowRedirect: true, ignoreHttpStatusErrors: true, returnFullResponse: true,
 * encoding: 'arraybuffer', json: false, timeout })` with Buffer bodies only.
 *
 * Behaviour (see critique "Recommended design decisions"):
 * - surrogate code units are replaced by spaces before sealing (R7), so spans index the original;
 * - payload is `{ text }`, plus `entities` only when `entityTypes` is a non-empty array;
 * - `hpke_unknown_key`: refetch keyconfig (force) and reseal once;
 * - sealed `invalid_entities` with a filter: retry once without it, `entityFilterIgnored: true`;
 * - 302/401 auth_required, 403 missing_role no_access, 5xx retry once (resealed), 429 rate_limited,
 *   413 text_too_large; a 5xx on a sealed body over LARGE_BODY_BYTES is not retried and is reported
 *   as text_too_large.
 *
 * Lint note: nothing is thrown lexically inside a `catch` (scanner rule require-node-api-error);
 * failures are recorded in a variable and thrown after the catch.
 */
import { sleep } from 'n8n-workflow';
import type { IExecuteFunctions, IHttpRequestMethods, IHttpRequestOptions } from 'n8n-workflow';

import { GatewayError, type GatewayErrorCode } from './errors';
import { sealRequest, type SealedRequest } from './hpke';
import {
	TRUST_ROOT_B64URL,
	validateKeyconfig,
	verifyKeyconfig,
	type ValidatedKey,
} from './keyconfig';
import {
	CREDENTIAL_NAME,
	GATEWAY_BASE_URL,
	GATEWAY_TIMEOUT_MS,
	type AnalyzeResult,
	type Keyconfig,
	type Span,
} from './types';

export { GatewayError };

/** Test seams. Production code passes nothing. */
export type AnalyzeOptions = {
	/** Trust root override (base64url Ed25519 public key); defaults to TRUST_ROOT_B64URL. */
	trustRootB64url?: string;
	/** Fixed frame timestamp in unix seconds; defaults to now. */
	nowSeconds?: number;
	/** Pause before the single 5xx retry, in milliseconds; defaults to RETRY_DELAY_MS. */
	retryDelayMs?: number;
};

/** Keyconfig cache TTL, matching the extension. */
export const KEYCONFIG_TTL_MS = 10 * 60 * 1000;

/** Pause before the single retry after a 5xx answer. */
export const RETRY_DELAY_MS = 500;

/**
 * Sealed bodies above this size are not retried after a 5xx. Measured on production
 * (2026-10-05): 100k characters (~100 KiB) analyse in ~5 s; 1M characters (~1 MiB) answer 502
 * "upstream error ... EOF" after ~13 s.
 */
export const LARGE_BODY_BYTES = 256 * 1024;

const KEYCONFIG_PATH = '/v1/keyconfig';
const ANALYZE_PATH = '/v1/analyze';
const OCTET_STREAM = 'application/octet-stream';

/** Server error codes passed through verbatim when they arrive in a JSON or sealed error body. */
const SERVER_CODES: ReadonlySet<string> = new Set([
	'hpke_required',
	'hpke_open_failed',
	'hpke_unknown_key',
	'hpke_stale',
	'invalid_entities',
	'text_too_large',
	'rate_limited',
]);

type CachedKeyconfig = {
	config: Keyconfig;
	key: ValidatedKey;
	fetchedAt: number;
};

/** Module-level keyconfig cache, keyed by base URL and trust root. */
const keyconfigCache = new Map<string, CachedKeyconfig>();

type GatewayResponse = {
	statusCode: number;
	contentType: string;
	body: Buffer;
	headers: Record<string, unknown>;
};

/**
 * Replaces every UTF-16 surrogate code unit with a space so that code-point and UTF-16 offsets
 * coincide and both index the original string (critique R7).
 */
export function sanitizeForOffsets(text: string): string {
	return text.replace(/[\uD800-\uDFFF]/g, ' ');
}

/** Empties the module-level keyconfig cache (tests). */
export function clearKeyconfigCache(): void {
	keyconfigCache.clear();
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function headerValue(headers: Record<string, unknown>, name: string): string {
	const wanted = name.toLowerCase();
	for (const [key, value] of Object.entries(headers)) {
		if (key.toLowerCase() !== wanted) continue;
		if (Array.isArray(value)) return value.map(String).join(', ');
		if (value === undefined || value === null) return '';
		return String(value);
	}
	return '';
}

function toBuffer(body: unknown): Buffer {
	if (Buffer.isBuffer(body)) return body;
	if (body instanceof ArrayBuffer) return Buffer.from(new Uint8Array(body));
	if (ArrayBuffer.isView(body)) {
		return Buffer.from(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
	}
	if (typeof body === 'string') return Buffer.from(body, 'utf8');
	if (body === undefined || body === null) return Buffer.alloc(0);
	return Buffer.from(JSON.stringify(body), 'utf8');
}

function parseJson(body: Buffer): unknown {
	try {
		return JSON.parse(body.toString('utf8')) as unknown;
	} catch {
		return undefined;
	}
}

function errorProperty(error: unknown, name: string): string {
	if (!isRecord(error) && !(error instanceof Error)) return '';
	const value = (error as unknown as Record<string, unknown>)[name];
	return typeof value === 'string' ? value : '';
}

const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'ECONNABORTED', 'ESOCKETTIMEDOUT']);

/**
 * Maps a failure thrown by the HTTP helper (no response at all) to `timeout` or `offline`.
 * n8n's own NodeOperationError (e.g. missing credentials) is passed through unchanged.
 */
function transportFailure(error: unknown): unknown {
	if (errorProperty(error, 'name') === 'NodeOperationError') return error;
	const cause: unknown = error instanceof Error ? error.cause : undefined;
	const code = errorProperty(error, 'code') || errorProperty(cause, 'code');
	const message = errorProperty(error, 'message') || String(error);
	if (TIMEOUT_CODES.has(code) || /time(d)? ?out/i.test(message)) {
		return new GatewayError(
			'timeout',
			'The Anonymizator gateway did not answer in time',
			undefined,
			message,
		);
	}
	return new GatewayError(
		'offline',
		'Could not reach the Anonymizator gateway (network unreachable)',
		undefined,
		message,
	);
}

async function send(
	ctx: IExecuteFunctions,
	method: IHttpRequestMethods,
	path: string,
	body?: Buffer,
): Promise<GatewayResponse> {
	const options: IHttpRequestOptions = {
		method,
		url: `${GATEWAY_BASE_URL}${path}`,
		headers:
			body === undefined
				? { Accept: 'application/json' }
				: { 'Content-Type': OCTET_STREAM, Accept: `${OCTET_STREAM}, application/json` },
		disableFollowRedirect: true,
		ignoreHttpStatusErrors: true,
		returnFullResponse: true,
		encoding: 'arraybuffer',
		json: false,
		timeout: GATEWAY_TIMEOUT_MS,
	};
	if (body !== undefined) options.body = body;

	let raw: unknown;
	let failure: unknown;
	try {
		raw = await ctx.helpers.httpRequestWithAuthentication.call(ctx, CREDENTIAL_NAME, options);
	} catch (error) {
		failure = transportFailure(error);
	}
	if (failure !== undefined) throw failure;

	const response = isRecord(raw) ? raw : {};
	const headers = isRecord(response.headers) ? response.headers : {};
	const statusCode = typeof response.statusCode === 'number' ? response.statusCode : 0;
	return {
		statusCode,
		headers,
		contentType: headerValue(headers, 'content-type').split(';')[0].trim().toLowerCase(),
		body: toBuffer(response.body),
	};
}

/** Errors every gateway response can produce before its body is interpreted. */
function statusError(response: GatewayResponse): GatewayError | undefined {
	const { statusCode } = response;
	if (statusCode === 302 || statusCode === 401 || (statusCode >= 300 && statusCode < 400)) {
		return new GatewayError(
			'auth_required',
			'The Anonymizator API key was rejected (invalid, expired or revoked)',
			statusCode,
		);
	}
	if (statusCode === 403) {
		const data = parseJson(response.body);
		const code = isRecord(data) && typeof data.error === 'string' ? data.error : '';
		if (code === 'missing_role') {
			return new GatewayError(
				'no_access',
				'The API key is valid but has no access to Anonymizator (missing role)',
				statusCode,
				code,
			);
		}
		return new GatewayError('http_403', 'The gateway refused the request (403)', statusCode, code);
	}
	if (statusCode === 413) {
		return new GatewayError('text_too_large', 'The text is too large for the gateway', statusCode);
	}
	if (statusCode === 429) {
		const retryAfter = headerValue(response.headers, 'retry-after');
		return new GatewayError(
			'rate_limited',
			retryAfter
				? `Too many requests to the gateway; retry after ${retryAfter} seconds`
				: 'Too many requests to the gateway; try again later',
			statusCode,
			retryAfter || undefined,
		);
	}
	return undefined;
}

function codeFromServer(statusCode: number, serverCode: string): GatewayErrorCode {
	if (SERVER_CODES.has(serverCode)) return serverCode as GatewayErrorCode;
	return `http_${statusCode}`;
}

function serverMessage(code: GatewayErrorCode, statusCode: number, serverCode: string): string {
	switch (code) {
		case 'hpke_required':
			return 'The gateway refused an unencrypted request';
		case 'hpke_open_failed':
			return 'The gateway could not decrypt the request';
		case 'hpke_unknown_key':
			return 'The gateway does not recognise the encryption key, even after refreshing it';
		case 'hpke_stale':
			return 'The gateway refused the request timestamp; the clock of the n8n host is probably off';
		case 'invalid_entities':
			return 'The gateway refused the entity type filter';
		case 'text_too_large':
			return 'The text is too large for the gateway';
		case 'rate_limited':
			return 'Too many requests to the gateway; try again later';
		default:
			return serverCode
				? `The gateway answered ${statusCode} (${serverCode})`
				: `The gateway answered with HTTP ${statusCode}`;
	}
}

/** A JSON (pre-open) error body: `{"error": code, "detail"?: string}`. */
function jsonError(response: GatewayResponse): GatewayError {
	const data = parseJson(response.body);
	const serverCode = isRecord(data) && typeof data.error === 'string' ? data.error : '';
	const detail = isRecord(data) && typeof data.detail === 'string' ? data.detail : undefined;
	const code = codeFromServer(response.statusCode, serverCode);
	return new GatewayError(
		code,
		serverMessage(code, response.statusCode, serverCode),
		response.statusCode,
		detail ?? (serverCode || undefined),
	);
}

/**
 * Fetches, verifies (fail closed) and caches the gateway keyconfig. `force` bypasses the cache.
 * Throws GatewayError ('hpke_unverified_keyconfig', 'hpke_bad_keyconfig', 'auth_required', ...).
 */
export async function fetchKeyconfig(
	ctx: IExecuteFunctions,
	force?: boolean,
	options?: AnalyzeOptions,
): Promise<Keyconfig> {
	return (await loadKeyconfig(ctx, force === true, options)).config;
}

async function loadKeyconfig(
	ctx: IExecuteFunctions,
	force: boolean,
	options: AnalyzeOptions | undefined,
): Promise<CachedKeyconfig> {
	const root = options?.trustRootB64url ?? TRUST_ROOT_B64URL;
	const cacheKey = `${GATEWAY_BASE_URL}|${root}`;
	const cached = keyconfigCache.get(cacheKey);
	if (!force && cached && Date.now() - cached.fetchedAt < KEYCONFIG_TTL_MS) return cached;

	let response = await send(ctx, 'GET', KEYCONFIG_PATH);
	if (response.statusCode >= 500) {
		await sleep(options?.retryDelayMs ?? RETRY_DELAY_MS);
		response = await send(ctx, 'GET', KEYCONFIG_PATH);
		if (response.statusCode >= 500) {
			throw new GatewayError(
				'server_error',
				'The Anonymizator gateway is unavailable (HTTP 5xx)',
				response.statusCode,
			);
		}
	}
	const early = statusError(response);
	if (early) throw early;
	if (response.statusCode >= 400) throw jsonError(response);
	if (response.statusCode !== 200) {
		throw new GatewayError(
			`http_${response.statusCode}`,
			`Unexpected answer from the gateway (HTTP ${response.statusCode})`,
			response.statusCode,
		);
	}

	const config = parseJson(response.body);
	if (!isRecord(config) || !Array.isArray(config.keys) || config.keys.length === 0) {
		throw new GatewayError(
			'hpke_bad_keyconfig',
			"The gateway's encryption key configuration is missing or malformed",
			response.statusCode,
		);
	}
	// Fail closed: never use or cache a keyconfig an intermediary could have substituted.
	if (!verifyKeyconfig(config, root)) {
		keyconfigCache.delete(cacheKey);
		throw new GatewayError(
			'hpke_unverified_keyconfig',
			"The gateway's encryption key is not signed by the Anonymizator trust root; the connection may be intercepted",
			response.statusCode,
		);
	}
	const keyconfig = config as Keyconfig;
	const entry: CachedKeyconfig = {
		config: keyconfig,
		key: validateKeyconfig(keyconfig),
		fetchedAt: Date.now(),
	};
	keyconfigCache.set(cacheKey, entry);
	return entry;
}

function sealFor(
	key: ValidatedKey,
	payload: Record<string, unknown>,
	options: AnalyzeOptions | undefined,
): SealedRequest {
	let sealed: SealedRequest | undefined;
	let reason = '';
	try {
		sealed = sealRequest(key.publicKey, key.keyId, payload, options?.nowSeconds);
	} catch (error) {
		reason = error instanceof Error ? error.message : String(error);
	}
	if (sealed === undefined) {
		throw new GatewayError(
			'hpke_seal_failed',
			'Could not encrypt the request',
			undefined,
			reason || undefined,
		);
	}
	return sealed;
}

/** Opens a sealed body; returns undefined when it cannot be opened or parsed. */
function tryOpen(sealed: SealedRequest, body: Buffer): unknown {
	try {
		return sealed.openResponse(body);
	} catch {
		return undefined;
	}
}

/** A 4xx sealed (post-open) error: opened with the request context. */
function sealedError(response: GatewayResponse, sealed: SealedRequest): GatewayError {
	const opened = tryOpen(sealed, response.body);
	const serverCode = isRecord(opened) && typeof opened.error === 'string' ? opened.error : '';
	const detail = isRecord(opened) && typeof opened.detail === 'string' ? opened.detail : undefined;
	const code = codeFromServer(response.statusCode, serverCode);
	return new GatewayError(
		code,
		serverMessage(code, response.statusCode, serverCode),
		response.statusCode,
		detail ?? (serverCode || undefined),
	);
}

/**
 * Validates the opened answer against `sent` (the sanitised text, same length as the original).
 * Edges are trimmed of whitespace in `sent`, which also covers the spaces standing in for
 * surrogates: a span can therefore never start or end in the middle of an emoji.
 */
function toSpans(data: unknown, sent: string): Span[] | undefined {
	if (!isRecord(data) || !Array.isArray(data.entities)) return undefined;
	const spans: Span[] = [];
	for (const item of data.entities as unknown[]) {
		if (!isRecord(item)) continue;
		const { entity_type: entityType, score } = item;
		let { start, end } = item;
		if (typeof entityType !== 'string' || entityType.length === 0) continue;
		if (typeof start !== 'number' || typeof end !== 'number') continue;
		if (!Number.isInteger(start) || !Number.isInteger(end)) continue;
		if (start < 0 || end <= start || end > sent.length) continue;
		while (start < end && /\s/.test(sent[start])) start++;
		while (end > start && /\s/.test(sent[end - 1])) end--;
		if (end <= start) continue;
		const span: Span = { entity_type: entityType, start, end };
		if (typeof score === 'number' && Number.isFinite(score)) span.score = score;
		spans.push(span);
	}
	spans.sort((a, b) => a.start - b.start || b.end - a.end);
	return spans;
}

/**
 * Sends `text` sealed to the gateway and returns the detected spans (offsets into `text`).
 * `entityTypes` undefined or empty means "all types" (the field is omitted).
 * Throws GatewayError on every failure.
 */
export async function analyze(
	ctx: IExecuteFunctions,
	text: string,
	entityTypes?: string[],
	options?: AnalyzeOptions,
): Promise<AnalyzeResult> {
	const sent = sanitizeForOffsets(text);
	let filter = Array.isArray(entityTypes) && entityTypes.length > 0 ? [...entityTypes] : undefined;
	let entityFilterIgnored = false;
	let resealed = false;
	let refetchKeyconfig = false;
	let serverRetried = false;

	for (;;) {
		const { key } = await loadKeyconfig(ctx, refetchKeyconfig, options);
		refetchKeyconfig = false;
		const payload: Record<string, unknown> =
			filter === undefined ? { text: sent } : { text: sent, entities: filter };
		const sealed = sealFor(key, payload, options);
		const response = await send(ctx, 'POST', ANALYZE_PATH, sealed.body);
		const { statusCode } = response;

		if (statusCode >= 500) {
			const large = sealed.body.length > LARGE_BODY_BYTES;
			// A very large text that broke the gateway would most likely break it again.
			if (!serverRetried && !large) {
				serverRetried = true;
				await sleep(options?.retryDelayMs ?? RETRY_DELAY_MS);
				continue;
			}
			// The large case is reported as text_too_large: it was tried once, and its advice (split the
			// text) is the only one that helps. The HTTP status is kept so it stays an API error.
			if (large) {
				throw new GatewayError(
					'text_too_large',
					`The Anonymizator gateway could not analyse a very large text (${text.length} characters); split it into smaller items`,
					statusCode,
				);
			}
			throw new GatewayError(
				'server_error',
				'The Anonymizator gateway could not analyse the text (HTTP 5xx twice)',
				statusCode,
			);
		}

		const early = statusError(response);
		if (early) throw early;

		if (statusCode >= 400) {
			const failure =
				response.contentType === OCTET_STREAM ? sealedError(response, sealed) : jsonError(response);
			if (failure.code === 'hpke_unknown_key' && !resealed) {
				// Key rotated under us: refetch the keyconfig and reseal exactly once.
				resealed = true;
				refetchKeyconfig = true;
				continue;
			}
			if (failure.code === 'invalid_entities' && filter !== undefined) {
				// Fail open on the filter only: retry once with all types.
				filter = undefined;
				entityFilterIgnored = true;
				continue;
			}
			throw failure;
		}

		const spans = statusCode === 200 ? toSpans(tryOpen(sealed, response.body), sent) : undefined;
		if (spans === undefined) {
			throw new GatewayError(
				'hpke_bad_response',
				"Could not decrypt or read the gateway's answer",
				statusCode,
				`HTTP ${statusCode}, ${response.contentType || 'no content type'}`,
			);
		}
		return { spans, entityFilterIgnored };
	}
}
