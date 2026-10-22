/**
 * Transport to the Anonymizator privacy gateway, protocol v2 only: keyconfig v2 fetch and
 * verification (pinned roots -> delegation -> keyconfig, delegation serial floor), the HPKE-sealed
 * `/v1/analyze`, the signed `/v1/capabilities`, status mapping through allowlists, single retries.
 * Port of the extension's `lib/gateway.js` (`gatewayFetch`, `acquireHpkeConfig`, `analyzeSealed`,
 * `codePointSpansToUtf16`, `possibleSpans`, `effectiveMaxTextChars`) and `lib/capabilities.js`.
 *
 * Every request goes through `ctx.helpers.httpRequestWithAuthentication.call(ctx, 'anonymizatorApi',
 * { disableFollowRedirect: true, ignoreHttpStatusErrors: true, returnFullResponse: true,
 * encoding: 'arraybuffer', json: false, timeout })` with Buffer bodies only, from an execute or a
 * load-options context alike.
 *
 * Behaviour:
 * - the text cap is checked before anything is sent (`payload_too_large`, no request);
 * - payload `{ text }`, plus `entities` only for a non-empty filter, plus `possible: true` only when
 *   asked for, so the request is otherwise byte-for-byte the same;
 * - offsets come back in Unicode code points and are converted to UTF-16 against the text that was
 *   sent; a span outside the text makes the whole answer `hpke_bad_response` (never protect less);
 * - at most two HTTP attempts per analysis, each with a FRESH seal: the second only after
 *   `hpke_unknown_key` / `hpke_key_expired` (keyconfig refetched) or a server error (a plain,
 *   unsealed 5xx, `busy`, sealed `internal_error`; after 1 s; a sealed answer's status is ignored).
 *   Never after `hpke_replay`, `rate_limited`, `hpke_stale`;
 * - `invalid_entities` with a filter: one more analysis without the filter, `entityFilterIgnored`;
 * - plain-JSON codes pass an allowlist (`KNOWN_ERROR_CODES`), sealed ones `SEALED_ERROR_CODES`;
 *   server text (`detail`, `error_description`) is never kept.
 *
 * Lint note: nothing is thrown lexically inside a `catch` (scanner rule require-node-api-error);
 * failures are recorded in a variable and thrown after the catch.
 */
import { sleep } from 'n8n-workflow';
import type { IHttpRequestMethods, IHttpRequestOptions, INode } from 'n8n-workflow';

import {
	capabilitiesInWindow,
	verifyCapabilitiesV1,
	type VerifiedCapabilities,
} from './capabilities';
import { GatewayError, type GatewayErrorCode } from './errors';
import { gatewayErrorText } from './gatewayMessages';
import { sealRequestV2, type SealedRequest, type TestEphemeral } from './hpke';
import { TRUST_ROOTS_B64URL, verifyKeyconfigV2, type KeyconfigVerification } from './keyconfig';
import { CREDENTIAL_NAME, GATEWAY_BASE_URL, GATEWAY_TIMEOUT_MS, type Span } from './types';

export { GatewayError };
export type { VerifiedCapabilities };

/**
 * The part of an n8n context the gateway needs. Both `IExecuteFunctions` and
 * `ILoadOptionsFunctions` satisfy it. The helper is always called with the context as `this`
 * (using `helpers` as `this` gives "this.getNode is not a function").
 */
export interface GatewayContext {
	helpers: {
		httpRequestWithAuthentication(
			this: unknown,
			credentialsType: string,
			requestOptions: IHttpRequestOptions,
		): Promise<unknown>;
	};
	getNode?: () => INode;
}

/** Test seams. Production code passes nothing. */
export type GatewayTestSeams = {
	/** Pinned roots override (base64url Ed25519 public keys); defaults to TRUST_ROOTS_B64URL. */
	trustRootsB64url?: readonly string[];
	/** Fixed clock in unix seconds (frame timestamp, verification windows, cache ages). */
	nowSeconds?: number;
	/** Pause before the second analyze attempt after a server error, in ms (default 1000). */
	retryDelayMs?: number;
	/** Pause before the renewal-race keyconfig refetch, in ms (default 2000). */
	keyconfigRetryDelayMs?: number;
	/** Fixed ephemeral key (test vectors only: reusing it reuses the AES-GCM key and nonce). */
	testEphemeral?: TestEphemeral;
};

export type AnalyzeOptions = {
	/** Ask for the review-only `possible` spans (`"possible": true` in the sealed payload). */
	possible?: boolean;
	/** Local text cap in UTF-16 units; defaults to MAX_TEXT_CHARS (see effectiveMaxTextChars). */
	maxTextChars?: number;
} & GatewayTestSeams;

/** One review-only span: never substituted, only listed. UTF-16 offsets into the original text. */
export type PossibleSpan = { start: number; end: number; entity_type: string };

/** Result of `analyze`. */
export type GatewayAnalyzeResult = {
	/** Detected spans, UTF-16 offsets into the ORIGINAL text, sorted by start (longest first). */
	spans: Span[];
	/** Review-only spans; always [] unless `possible` was requested. */
	possible: PossibleSpan[];
	/** True when the gateway refused the entity filter and the text was analysed with all types. */
	entityFilterIgnored: boolean;
};

/** The gateway's text cap (characters); text.length (UTF-16) is never below its code-point count. */
export const MAX_TEXT_CHARS = 120000;
/** Bounds for a cap taken from a verified capabilities document. */
export const MIN_TEXT_CHARS = 10000;
export const MAX_TEXT_CHARS_CEILING = 1000000;
// Body headroom for the frame, padding and JSON around the text, and the worst case of 6 body
// bytes per character (a JSON \uXXXX escape).
const BODY_OVERHEAD_BYTES = 8192;
const BODY_BYTES_PER_CHAR = 6;

/** Keyconfig cache TTL, matching the extension. The cached document is re-verified on every use. */
export const KEYCONFIG_TTL_MS = 10 * 60 * 1000;
/** Capabilities: refetch a verified document after this; after a failed attempt wait as long. */
export const CAPABILITIES_TTL_MS = 5 * 60 * 1000;
export const CAPABILITIES_RETRY_MS = 5 * 60 * 1000;
/** Pause before the second analyze attempt (server error). */
export const ANALYZE_RETRY_DELAY_MS = 1000;
/** Pause before the renewal-race keyconfig refetch. */
export const KEYCONFIG_RETRY_DELAY_MS = 2000;
/** Keyconfig and capabilities requests are abandoned after this ('timeout'). */
export const KEYCONFIG_TIMEOUT_MS = 15000;

/**
 * Error codes the gateway, the BFF and Traefik may answer in PLAIN JSON. That JSON is
 * unauthenticated (anything on the path could write it), so only these codes are passed on;
 * anything else becomes `server_error` (5xx) or `http_<status>`.
 */
export const KNOWN_ERROR_CODES: ReadonlySet<string> = new Set([
	'hpke_required',
	'hpke_bad_frame',
	'hpke_bad_version',
	'hpke_stale',
	'hpke_unknown_key',
	'hpke_key_expired',
	'hpke_open_failed',
	'hpke_bad_payload',
	'hpke_replay',
	'hpke_not_configured',
	'hpke_bad_key_material',
	'payload_too_large',
	'invalid_payload',
	'invalid_entities',
	'internal_error',
	'rate_limited',
	'busy',
	'upstream_unavailable',
	'upstream_timeout',
	'missing_role',
	'unauthenticated',
]);

/** Error codes accepted from a SEALED (authenticated) v2 error response. */
export const SEALED_ERROR_CODES: ReadonlySet<string> = new Set([
	'invalid_payload',
	'invalid_entities',
	'payload_too_large',
	'hpke_bad_payload',
	'internal_error',
]);

const SEALED_ERROR_RE = /^[a-z][a-z0-9_]{0,63}$/;
// Entity types: the capabilities TYPE grammar; a malformed type is protected as PII, like the
// extension's anonymizer does (pgwEntityType).
const ENTITY_TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const FALLBACK_ENTITY_TYPE = 'PII';
const MAX_POSSIBLE_SPANS = 10000;

const KEYCONFIG_PATH = '/v1/keyconfig';
const CAPABILITIES_PATH = '/v1/capabilities';
const ANALYZE_PATH = '/v1/analyze';
const OCTET_STREAM = 'application/octet-stream';
const EXPECTED_AUDIENCE = new URL(GATEWAY_BASE_URL).hostname.toLowerCase();

// ---------------------------------------------------------------------------------------------
// Module-level state (per n8n process). Keyed by base URL and pinned roots, so a test seam never
// shares state with the production roots.

type KeyconfigCacheEntry = { config: unknown; fetchedAt: number };
type CapabilitiesCacheEntry = {
	verified?: Extract<ReturnType<typeof verifyCapabilitiesV1>, { ok: true }>;
	fetchedAt?: number;
	attemptAt?: number;
};

const keyconfigCache = new Map<string, KeyconfigCacheEntry>();
const capabilitiesCache = new Map<string, CapabilitiesCacheEntry>();
/**
 * The highest delegation serial that ever verified: a delegation below it is refused, so a stolen
 * older delegated key cannot be replayed once the renewal was seen. Never lowered; only a
 * successful keyconfig acquisition raises it (capabilities only read it).
 */
const delegationFloors = new Map<string, number>();
// One keyconfig acquisition (and one capabilities refresh) at a time in this process.
let keyconfigQueue: Promise<unknown> = Promise.resolve();
let capabilitiesQueue: Promise<unknown> = Promise.resolve();

/** Empties every module-level cache and the serial floors (tests). */
export function clearGatewayCaches(): void {
	keyconfigCache.clear();
	capabilitiesCache.clear();
	delegationFloors.clear();
}

/** The current delegation serial floor (0 when none was seen); for tests and diagnostics. */
export function delegationFloor(options?: GatewayTestSeams): number {
	return delegationFloors.get(stateKey(options)) ?? 0;
}

function stateKey(options: GatewayTestSeams | undefined): string {
	return `${GATEWAY_BASE_URL}|${roots(options).join(',')}`;
}

function roots(options: GatewayTestSeams | undefined): readonly string[] {
	return options?.trustRootsB64url ?? TRUST_ROOTS_B64URL;
}

function nowSeconds(options: GatewayTestSeams | undefined): number {
	return Math.floor(options?.nowSeconds !== undefined ? options.nowSeconds : Date.now() / 1000);
}

function nowMs(options: GatewayTestSeams | undefined): number {
	return options?.nowSeconds !== undefined ? options.nowSeconds * 1000 : Date.now();
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Serialises `task` behind the previous one in `queue`'s chain. */
function enqueue<T>(queueRef: 'keyconfig' | 'capabilities', task: () => Promise<T>): Promise<T> {
	const previous = queueRef === 'keyconfig' ? keyconfigQueue : capabilitiesQueue;
	const run = previous.then(task, task);
	const settled = run.then(
		() => undefined,
		() => undefined,
	);
	if (queueRef === 'keyconfig') keyconfigQueue = settled;
	else capabilitiesQueue = settled;
	return run;
}

// ---------------------------------------------------------------------------------------------
// HTTP

type FetchSuccess = { ok: true; status: number; data?: unknown; sealed?: Buffer };
type FetchFailure = {
	ok: false;
	status?: number;
	error: GatewayErrorCode;
	retryAfter?: number;
};
type FetchResult = FetchSuccess | FetchFailure;

type RawResponse = {
	statusCode: number;
	contentType: string;
	body: Buffer;
	headers: Record<string, unknown>;
};

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

/** The parsed JSON body, or {} when it is not JSON (as the extension's `.json().catch(() => ({}))`). */
function parseJson(body: Buffer): unknown {
	try {
		return JSON.parse(body.toString('utf8')) as unknown;
	} catch {
		return {};
	}
}

function errorProperty(error: unknown, name: string): string {
	if (!isRecord(error) && !(error instanceof Error)) return '';
	const value = (error as unknown as Record<string, unknown>)[name];
	return typeof value === 'string' ? value : '';
}

const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'ECONNABORTED', 'ESOCKETTIMEDOUT']);
const HTTP_STATUS_RE = /^[1-5][0-9]{2}$/;

function isN8nError(error: unknown): boolean {
	const name = errorProperty(error, 'name');
	return name === 'NodeOperationError' || name === 'NodeApiError';
}

/**
 * Whether a failure thrown by the HTTP helper is n8n's own (for example missing credentials) and
 * passes through unchanged. n8n-core's httpRequestWithAuthentication rethrows EVERY axios failure
 * as `new NodeApiError(node, error)`, so a NodeApiError without a real HTTP status that wraps a
 * plain error (ECONNREFUSED, ECONNABORTED, ENOTFOUND...) is a request that got no response. A
 * NodeApiError around an n8n error (a missing credential is rewrapped that way) passes through.
 */
function passesThrough(error: unknown): boolean {
	const name = errorProperty(error, 'name');
	if (name === 'NodeOperationError') return true;
	if (name !== 'NodeApiError') return false;
	const httpCode = (error as { httpCode?: unknown }).httpCode;
	if (
		typeof httpCode === 'number' ||
		(typeof httpCode === 'string' && HTTP_STATUS_RE.test(httpCode))
	) {
		return true;
	}
	const cause: unknown = error instanceof Error ? error.cause : undefined;
	return !(cause instanceof Error) || isN8nError(cause);
}

/** A failure thrown by the HTTP helper with no response at all: `timeout` or `offline`. */
function transportCode(error: unknown): 'timeout' | 'offline' {
	const cause: unknown = error instanceof Error ? error.cause : undefined;
	const code = errorProperty(error, 'code') || errorProperty(cause, 'code');
	const message = `${errorProperty(error, 'message') || String(error)} ${errorProperty(cause, 'message')}`;
	return TIMEOUT_CODES.has(code) || /time(d)? ?out/i.test(message) ? 'timeout' : 'offline';
}

/**
 * One HTTP attempt. Throws n8n's own errors (for example missing credentials) unchanged; returns
 * `timeout` / `offline` for a request that got no response, also when n8n-core wrapped the
 * transport failure in a NodeApiError.
 */
async function send(
	ctx: GatewayContext,
	method: IHttpRequestMethods,
	path: string,
	body: Buffer | undefined,
	timeoutMs: number,
): Promise<RawResponse | FetchFailure> {
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
		timeout: timeoutMs,
	};
	if (body !== undefined) options.body = body;

	let raw: unknown;
	let thrown: unknown;
	let failed = false;
	try {
		raw = await ctx.helpers.httpRequestWithAuthentication.call(ctx, CREDENTIAL_NAME, options);
	} catch (error) {
		failed = true;
		thrown = error;
	}
	if (failed) {
		if (passesThrough(thrown)) throw thrown;
		return { ok: false, error: transportCode(thrown) };
	}

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

/** A server error code through the allowlist: known code, else `fallback`. */
function allowlisted(data: unknown, fallback: GatewayErrorCode): GatewayErrorCode {
	const code = isRecord(data) ? data.error : undefined;
	return typeof code === 'string' && KNOWN_ERROR_CODES.has(code)
		? (code as GatewayErrorCode)
		: fallback;
}

/** Retry-After as whole seconds when it is an integer in [1, 300], else undefined. */
function retryAfterSeconds(headers: Record<string, unknown>): number | undefined {
	const raw = headerValue(headers, 'retry-after').trim();
	if (!/^[0-9]{1,3}$/.test(raw)) return undefined;
	const seconds = Number(raw);
	return seconds >= 1 && seconds <= 300 ? seconds : undefined;
}

function isFailure(value: RawResponse | FetchFailure): value is FetchFailure {
	return (value as FetchFailure).ok === false;
}

/**
 * An authenticated request against the gateway (`gatewayFetch`). An octet-stream response (any
 * status) comes back as `{ok: true, status, sealed}` for the caller to open and classify; JSON as
 * `data`. `passive` (capabilities): a 3xx, 401 or 403 is a plain `http_<status>`.
 */
async function gatewayFetch(
	ctx: GatewayContext,
	method: IHttpRequestMethods,
	path: string,
	body: Buffer | undefined,
	{
		retryServerErrors,
		timeoutMs,
		passive = false,
	}: { retryServerErrors: boolean; timeoutMs: number; passive?: boolean },
): Promise<FetchResult> {
	let response = await send(ctx, method, path, body, timeoutMs);
	if (isFailure(response)) return response;
	let status = response.statusCode;

	const redirectOrUnauthorized = (status >= 300 && status < 400) || status === 401;
	if (passive && (redirectOrUnauthorized || status === 403)) {
		return { ok: false, status, error: `http_${status}` };
	}
	if (redirectOrUnauthorized) {
		// The BFF answers a missing or rejected key with a 302 to its login page (401 when the
		// request asks for JSON); with redirects followed it would end on a 200 HTML page.
		return { ok: false, status, error: 'auth_required' };
	}
	if (status === 403) {
		const data = parseJson(response.body);
		if (isRecord(data) && data.error === 'missing_role') {
			return { ok: false, status, error: 'no_access' };
		}
		return { ok: false, status, error: allowlisted(data, 'http_403') };
	}

	if (status >= 500 && retryServerErrors && response.contentType !== OCTET_STREAM) {
		// One retry on a server error (keyconfig: resending it is harmless).
		response = await send(ctx, method, path, body, timeoutMs);
		if (isFailure(response)) return response;
		status = response.statusCode;
	}

	if (response.contentType === OCTET_STREAM) {
		// Sealed: success, or a sealed error whatever the status says. Only the request's HPKE
		// context can tell, so the caller opens it.
		return { ok: true, status, sealed: response.body };
	}
	if (status === 429) {
		// The BFF's limits, or Traefik's in-flight cap (text body): same meaning.
		const retryAfter = retryAfterSeconds(response.headers);
		return { ok: false, status, error: 'rate_limited', ...(retryAfter ? { retryAfter } : {}) };
	}
	if (status >= 400) {
		// Pre-open errors (and the BFF's own) are plain JSON with generic codes.
		const fallback: GatewayErrorCode = status >= 500 ? 'server_error' : `http_${status}`;
		return { ok: false, status, error: allowlisted(parseJson(response.body), fallback) };
	}
	if (status < 200 || status >= 300) return { ok: false, status, error: `http_${status}` };
	return { ok: true, status, data: parseJson(response.body) };
}

function gatewayError(failure: FetchFailure, maxTextChars?: number): GatewayError {
	const text = gatewayErrorText(failure.error, {
		retryAfter: failure.retryAfter,
		maxTextChars,
		httpCode: failure.status,
	});
	return new GatewayError(
		failure.error,
		text.message,
		failure.status,
		undefined,
		failure.retryAfter,
	);
}

// ---------------------------------------------------------------------------------------------
// Keyconfig v2

type KeyconfigResult =
	Extract<KeyconfigVerification, { ok: true }> | (FetchFailure & { belowFloor?: boolean });

function verifyConfig(
	config: unknown,
	floor: number,
	options: GatewayTestSeams | undefined,
): KeyconfigVerification | { ok: false; error: GatewayErrorCode; belowFloor: true } {
	const result = verifyKeyconfigV2(config, roots(options), nowSeconds(options), EXPECTED_AUDIENCE);
	if (!result.ok) return result;
	if (result.serial < floor) {
		return { ok: false, error: 'hpke_unverified_keyconfig', belowFloor: true };
	}
	return result;
}

/**
 * Remembers a freshly fetched config that verified and raises the floor. If the floor rose above
 * this config's serial meanwhile, nothing is stored and the caller treats it as below the floor.
 */
function storeConfig(
	key: string,
	config: unknown,
	serial: number,
	options: GatewayTestSeams | undefined,
): boolean {
	const floor = delegationFloors.get(key) ?? 0;
	if (serial < floor) return false;
	if (serial > floor) delegationFloors.set(key, serial);
	keyconfigCache.set(key, { config, fetchedAt: nowMs(options) });
	return true;
}

async function acquireKeyconfigOnce(
	ctx: GatewayContext,
	force: boolean,
	options: GatewayTestSeams | undefined,
): Promise<KeyconfigResult> {
	const key = stateKey(options);
	const floor = delegationFloors.get(key) ?? 0;
	const cached = keyconfigCache.get(key);
	if (!force && cached && nowMs(options) - cached.fetchedAt < KEYCONFIG_TTL_MS) {
		// Never trusted as stored: re-verified on every use.
		const verified = verifyConfig(cached.config, floor, options);
		if (verified.ok) return verified;
		// Expired or otherwise no longer valid: drop it and fetch once.
		keyconfigCache.delete(key);
	}

	for (let attempt = 1; ; attempt++) {
		const result = await gatewayFetch(ctx, 'GET', KEYCONFIG_PATH, undefined, {
			retryServerErrors: true,
			timeoutMs: KEYCONFIG_TIMEOUT_MS,
		});
		if (!result.ok) return result;
		// A 200 that is sealed is not a keyconfig.
		const config = result.sealed ? {} : result.data;
		const verified = verifyConfig(config, floor, options);
		if (verified.ok && storeConfig(key, config, verified.serial, options)) return verified;
		if (!verified.ok && !('belowFloor' in verified)) {
			return { ok: false, status: result.status, error: verified.error };
		}
		// Renewal race: this replica still serves the older delegation while the newer one was
		// already seen. Keep the previously verified config if it still holds against the current
		// floor; else ask again once, a little later.
		const current = delegationFloors.get(key) ?? 0;
		if (cached) {
			const previous = verifyConfig(cached.config, current, options);
			if (previous.ok) return previous;
		}
		if (attempt >= 2) {
			return { ok: false, status: result.status, error: 'hpke_unverified_keyconfig' };
		}
		await sleep(options?.keyconfigRetryDelayMs ?? KEYCONFIG_RETRY_DELAY_MS);
	}
}

function acquireKeyconfigResult(
	ctx: GatewayContext,
	force: boolean,
	options: GatewayTestSeams | undefined,
): Promise<KeyconfigResult> {
	return enqueue('keyconfig', async () => await acquireKeyconfigOnce(ctx, force, options));
}

/**
 * The verified key to seal to: from the cached /v1/keyconfig (re-verified now) or a fresh fetch.
 * The HPKE public keys are never bundled; nothing is used unless it verifies against the pinned
 * roots. Throws GatewayError on any failure. Exported for diagnostics and the live smoke check.
 */
export async function acquireKeyconfig(
	ctx: GatewayContext,
	options?: GatewayTestSeams & { force?: boolean },
): Promise<Extract<KeyconfigVerification, { ok: true }>> {
	const result = await acquireKeyconfigResult(ctx, options?.force === true, options);
	if (!result.ok) throw gatewayError(result);
	return result;
}

// ---------------------------------------------------------------------------------------------
// Analyze

type AnalyzeOutcome =
	{ ok: true; spans: Span[]; possible: PossibleSpan[] } | (FetchFailure & { status?: number });

/** Opens and classifies a sealed answer: exactly one of `entities` (array) or `error` (code). */
function openAnalyzeResponse(
	sealed: SealedRequest,
	bytes: Buffer,
	status: number,
): { ok: true; entities: unknown[]; possible: unknown; hasPossible: boolean } | FetchFailure {
	let obj: unknown;
	let opened = false;
	try {
		obj = sealed.openResponse(bytes);
		opened = true;
	} catch {
		opened = false;
	}
	if (!opened || !isRecord(obj)) return { ok: false, status, error: 'hpke_bad_response' };
	const hasEntities = 'entities' in obj;
	const hasError = 'error' in obj;
	if (hasEntities && !hasError && Array.isArray(obj.entities)) {
		return {
			ok: true,
			entities: obj.entities as unknown[],
			possible: obj.possible,
			hasPossible: 'possible' in obj,
		};
	}
	if (
		hasError &&
		!hasEntities &&
		typeof obj.error === 'string' &&
		SEALED_ERROR_RE.test(obj.error)
	) {
		const code: GatewayErrorCode = SEALED_ERROR_CODES.has(obj.error)
			? (obj.error as GatewayErrorCode)
			: `http_${status}`;
		return { ok: false, status, error: code };
	}
	return { ok: false, status, error: 'hpke_bad_response' };
}

/**
 * Converts offsets from Unicode CODE POINTS (Python str indices, which the gateway reports) to the
 * UTF-16 code units JavaScript strings slice by, against the exact text that was sent. Fails
 * closed: an offset that is not an integer, or a span outside the text (or empty / reversed),
 * makes the whole response unusable (null). A lone surrogate counts as one code point on both sides.
 */
export function codePointSpansToUtf16(
	text: string,
	entities: unknown,
): Array<Record<string, unknown> & { start: number; end: number }> | null {
	if (typeof text !== 'string' || !Array.isArray(entities)) return null;
	let utf16At: number[] | null = null;
	let codePoints = text.length;
	if (/[\uD800-\uDFFF]/.test(text)) {
		utf16At = [];
		let unit = 0;
		for (const ch of text) {
			utf16At.push(unit);
			unit += ch.length;
		}
		codePoints = utf16At.length;
		utf16At.push(unit);
	}
	const converted: Array<Record<string, unknown> & { start: number; end: number }> = [];
	for (const entity of entities as unknown[]) {
		if (!isRecord(entity)) return null;
		const { start, end } = entity;
		if (typeof start !== 'number' || typeof end !== 'number') return null;
		if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return null;
		if (start < 0 || end <= start || end > codePoints) return null;
		converted.push(
			utf16At ? { ...entity, start: utf16At[start], end: utf16At[end] } : { ...entity, start, end },
		);
	}
	return converted;
}

/** Detected spans from the opened answer, or null (fail closed). */
function toSpans(text: string, entities: unknown[]): Span[] | null {
	const converted = codePointSpansToUtf16(text, entities);
	if (!converted) return null;
	const spans: Span[] = converted.map((entity) => {
		const type = entity.entity_type;
		const span: Span = {
			entity_type:
				typeof type === 'string' && ENTITY_TYPE_RE.test(type) ? type : FALLBACK_ENTITY_TYPE,
			start: entity.start,
			end: entity.end,
		};
		if (typeof entity.score === 'number' && Number.isFinite(entity.score)) {
			span.score = entity.score;
		}
		return span;
	});
	spans.sort((a, b) => a.start - b.start || b.end - a.end);
	return spans;
}

/**
 * Validates the review-only `possible` member and converts it like the entities: an array of
 * {start, end, entity_type} (type in the capabilities TYPE grammar), at most 10 000, every span
 * inside the text. Absent -> [] (an older gateway ignores the opt-in). Anything malformed -> null:
 * the caller fails the whole response closed. Spans overlapping an entity are dropped.
 */
export function possibleSpans(
	text: string,
	possible: unknown,
	entities: Array<{ start: number; end: number }>,
): PossibleSpan[] | null {
	if (possible === undefined) return [];
	if (!Array.isArray(possible) || possible.length > MAX_POSSIBLE_SPANS) return null;
	for (const p of possible as unknown[]) {
		if (!isRecord(p)) return null;
		if (typeof p.entity_type !== 'string' || !ENTITY_TYPE_RE.test(p.entity_type)) return null;
	}
	const converted = codePointSpansToUtf16(text, possible);
	if (!converted) return null;
	return converted
		.map(({ start, end, entity_type: type }) => ({ start, end, entity_type: type as string }))
		.filter((p) => !entities.some((e) => p.start < e.end && e.start < p.end));
}

function sealFor(
	publicKey: Buffer,
	keyId: number,
	payload: Record<string, unknown>,
	options: AnalyzeOptions | undefined,
): SealedRequest | undefined {
	try {
		return sealRequestV2(publicKey, keyId, payload, options?.nowSeconds, options?.testEphemeral);
	} catch {
		return undefined;
	}
}

/**
 * Seal {text[, entities][, possible]}, POST it, open the sealed answer (`analyzeSealed`). At most
 * two HTTP attempts, each with a FRESH seal.
 */
async function analyzeSealed(
	ctx: GatewayContext,
	text: string,
	filter: string[] | undefined,
	options: AnalyzeOptions | undefined,
): Promise<AnalyzeOutcome> {
	const wantPossible = options?.possible === true;
	const payload: Record<string, unknown> =
		filter !== undefined && filter.length > 0 ? { text, entities: filter } : { text };
	if (wantPossible) payload.possible = true;

	let refetchKeyconfig = false;
	for (let attempt = 1; attempt <= 2; attempt++) {
		const kc = await acquireKeyconfigResult(ctx, refetchKeyconfig, options);
		if (!kc.ok) return kc;
		const sealed = sealFor(kc.publicKey, kc.keyId, payload, options);
		if (!sealed) return { ok: false, error: 'hpke_seal_failed' };
		const result = await gatewayFetch(ctx, 'POST', ANALYZE_PATH, sealed.body, {
			retryServerErrors: false,
			timeoutMs: GATEWAY_TIMEOUT_MS,
		});

		let failure: FetchFailure;
		// The HTTP status of a sealed answer is unauthenticated and only advisory: the sealed
		// content decides, so only a plain (unsealed) 5xx is retried, as in the extension.
		let plainStatus: number | undefined;
		if (result.ok) {
			// A 2xx that is not sealed is not ours.
			const opened = result.sealed
				? openAnalyzeResponse(sealed, result.sealed, result.status)
				: ({ ok: false, status: result.status, error: 'hpke_bad_response' } as FetchFailure);
			if (opened.ok) {
				const spans = toSpans(text, opened.entities);
				if (!spans) return { ok: false, status: result.status, error: 'hpke_bad_response' };
				if (!wantPossible) return { ok: true, spans, possible: [] };
				const review = possibleSpans(text, opened.hasPossible ? opened.possible : undefined, spans);
				if (!review) return { ok: false, status: result.status, error: 'hpke_bad_response' };
				return { ok: true, spans, possible: review };
			}
			failure = opened;
		} else {
			failure = result;
			plainStatus = result.status;
		}

		if (attempt === 2) return failure;
		if (failure.error === 'hpke_unknown_key' || failure.error === 'hpke_key_expired') {
			refetchKeyconfig = true; // rotated under us
			continue;
		}
		if (
			(plainStatus !== undefined && plainStatus >= 500) ||
			failure.error === 'busy' ||
			failure.error === 'internal_error'
		) {
			await sleep(options?.retryDelayMs ?? ANALYZE_RETRY_DELAY_MS);
			continue;
		}
		return failure;
	}
	return { ok: false, error: 'server_error' };
}

/**
 * Sends `text` sealed to the gateway and returns the detected spans (UTF-16 offsets into `text`).
 * `entityTypes` undefined or empty means "all types" (the field is omitted). With
 * `options.possible`, also returns the review-only `possible` spans. Throws GatewayError on every
 * failure; nothing is sent when the text is over `options.maxTextChars` (default 120 000).
 */
export async function analyze(
	ctx: GatewayContext,
	text: string,
	entityTypes?: string[],
	options?: AnalyzeOptions,
): Promise<GatewayAnalyzeResult> {
	const maxTextChars = options?.maxTextChars ?? MAX_TEXT_CHARS;
	if (typeof text === 'string' && text.length > maxTextChars) {
		// The only failure that names the limit: the one that refused the text here.
		throw gatewayError({ ok: false, error: 'payload_too_large' }, maxTextChars);
	}
	const filter =
		Array.isArray(entityTypes) && entityTypes.length > 0 ? [...entityTypes] : undefined;
	let outcome = await analyzeSealed(ctx, text, filter, options);
	let entityFilterIgnored = false;
	if (!outcome.ok && outcome.error === 'invalid_entities' && filter !== undefined) {
		// The gateway refused our entity-type names (version skew). Fail OPEN to complete
		// anonymization, the privacy-safe direction, exactly once, and flag it.
		entityFilterIgnored = true;
		outcome = await analyzeSealed(ctx, text, undefined, options);
	}
	// A remote payload_too_large is not about the local cap, which the text already passed.
	if (!outcome.ok) throw gatewayError(outcome);
	return { spans: outcome.spans, possible: outcome.possible, entityFilterIgnored };
}

// ---------------------------------------------------------------------------------------------
// Capabilities

/**
 * The local text cap: the server's, from a verified capabilities document, when it is plausible
 * (v = min(max_text_chars, floor((max_body_bytes - 8192) / 6)) within [10 000, 1 000 000]), else
 * the bundled 120 000. The BFF and the gateway still enforce their own caps.
 */
export function effectiveMaxTextChars(
	capabilities: { maxTextChars?: number; maxBodyBytes?: number } | null | undefined,
): number {
	if (!capabilities) return MAX_TEXT_CHARS;
	const { maxTextChars, maxBodyBytes } = capabilities;
	if (!Number.isSafeInteger(maxTextChars) || !Number.isSafeInteger(maxBodyBytes)) {
		return MAX_TEXT_CHARS;
	}
	const v = Math.min(
		maxTextChars as number,
		Math.floor(((maxBodyBytes as number) - BODY_OVERHEAD_BYTES) / BODY_BYTES_PER_CHAR),
	);
	return v >= MIN_TEXT_CHARS && v <= MAX_TEXT_CHARS_CEILING ? v : MAX_TEXT_CHARS;
}

async function refreshCapabilities(
	ctx: GatewayContext,
	options: GatewayTestSeams | undefined,
): Promise<VerifiedCapabilities | null> {
	const key = stateKey(options);
	const floor = delegationFloors.get(key) ?? 0;
	const now = nowSeconds(options);
	const nowMillis = nowMs(options);
	const entry = capabilitiesCache.get(key);
	const current =
		entry?.verified && entry.verified.serial >= floor && capabilitiesInWindow(entry.verified, now)
			? entry.verified
			: undefined;
	if (
		current &&
		entry?.fetchedAt !== undefined &&
		nowMillis - entry.fetchedAt < CAPABILITIES_TTL_MS
	) {
		return current.capabilities;
	}
	if (entry?.attemptAt !== undefined && nowMillis - entry.attemptAt < CAPABILITIES_RETRY_MS) {
		return current ? current.capabilities : null;
	}

	const failed = (): VerifiedCapabilities | null => {
		// Keep a cached document that still verifies; only note the attempt.
		capabilitiesCache.set(key, {
			...(current ? { verified: current, fetchedAt: entry?.fetchedAt } : {}),
			attemptAt: nowMillis,
		});
		return current ? current.capabilities : null;
	};

	let result: FetchResult | undefined;
	let credentialFailure = false;
	try {
		result = await gatewayFetch(ctx, 'GET', CAPABILITIES_PATH, undefined, {
			retryServerErrors: false,
			timeoutMs: KEYCONFIG_TIMEOUT_MS,
			passive: true,
		});
	} catch {
		// Only n8n's own errors are thrown here (missing credentials): nothing was sent.
		credentialFailure = true;
	}
	if (
		credentialFailure ||
		(result &&
			!result.ok &&
			result.status !== undefined &&
			((result.status >= 300 && result.status < 400) ||
				result.status === 401 ||
				result.status === 403))
	) {
		// About one credential, while this cache is per process: not an attempt, so another
		// credential (or a sign-in right after) does not wait out the backoff. The extension skips the
		// backoff only for auth_required; 403 and other 3xx are skipped here too because n8n may hold
		// several credentials in one process.
		return current ? current.capabilities : null;
	}
	if (!result || !result.ok || result.sealed || !isRecord(result.data)) return failed();
	const verified = verifyCapabilitiesV1(result.data, roots(options), now, EXPECTED_AUDIENCE);
	// Serial floor, read only: the capabilities path never raises it.
	if (!verified.ok || verified.serial < (delegationFloors.get(key) ?? 0)) return failed();
	capabilitiesCache.set(key, { verified, fetchedAt: nowMillis });
	return verified.capabilities;
}

/**
 * The server's verified capabilities document, or null on ANY failure (no document, 404 from an
 * older gateway, auth, HTTP, verification, stale, below the serial floor). Passive: never throws.
 * Cached for 5 minutes (re-checked against its time window and the floor on every use); after a
 * failed attempt the next one waits 5 minutes. A credential failure (missing credential, 3xx, 401,
 * 403) is not an attempt: the cache is per process, shared by every credential. Callers use their bundled data when this is null.
 */
export async function fetchCapabilities(
	ctx: GatewayContext,
	options?: GatewayTestSeams,
): Promise<VerifiedCapabilities | null> {
	try {
		return await enqueue('capabilities', async () => await refreshCapabilities(ctx, options));
	} catch {
		return null;
	}
}
