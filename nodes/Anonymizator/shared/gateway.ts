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
 * - a text longer than one request is cut into parts (`chunker.ts`, the extension's and web app's
 *   algorithm), analysed one after another, each sealed afresh, and the parts' spans are merged
 *   back onto the whole text; any part that fails fails the whole text (no partial result). A part
 *   of a multi-part text waits out a rate limit (Retry-After, at most 3 times, at most 60 s each);
 * - the per-request cap (code points) is checked before a request is sealed (`payload_too_large`,
 *   no request); the chunker keeps every part 2 000 below it, so this is only a guard;
 * - payload `{ text }`, plus `entities` only for a non-empty filter, plus `possible: true` only when
 *   asked for, so the request is otherwise byte-for-byte the same;
 * - offsets come back in Unicode code points and are converted to UTF-16 against the text that was
 *   sent; a span outside the text makes the whole answer `hpke_bad_response` (never protect less);
 * - at most two HTTP attempts per analysis, each with a FRESH seal: the second only after
 *   `hpke_unknown_key` / `hpke_key_expired` (keyconfig refetched) or a server error (a plain,
 *   unsealed 5xx, `busy`, sealed `internal_error`; after 1 s; a sealed answer's status is ignored).
 *   Never after `hpke_replay`, `rate_limited`, `hpke_stale`;
 * - `invalid_entities` with a filter: the whole text once more without the filter, from the first
 *   part, `entityFilterIgnored`;
 * - plain-JSON codes pass an allowlist (`KNOWN_ERROR_CODES`), sealed ones `SEALED_ERROR_CODES`;
 *   server text (`detail`, `error_description`) is never kept.
 *
 * EXPERIMENTAL protocol v3 (post-quantum, X-Wing; gateway docs/HPKE-V3-EXPERIMENTAL.md): when the
 * caller's `postQuantum` reader says on AT THE TIME OF A SEND (it is read before every send,
 * including every retry), that send is sealed as v3 to a key from the verified `v3` keyconfig
 * member, or the part fails (`hpke_pq_unavailable` or the verifier's code). It is never sent as v2
 * instead. A v3 frame answered with a plain `hpke_bad_version` gets one keyconfig refetch and one
 * reseal per part (its own budget); a second one is `hpke_pq_unavailable`. Without a reader, or with
 * it off, nothing of v3 runs and every request is v2, byte for byte as before.
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
import { merge, partTargetFor, split, type TextPart } from './chunker';
import { GatewayError, type GatewayErrorCode } from './errors';
import { gatewayErrorText } from './gatewayMessages';
import { sealRequestV2, type SealedRequest, type TestEphemeral } from './hpke';
import { sealRequestV3 } from './hpkeV3';
import { TRUST_ROOTS_B64URL, verifyKeyconfigV2, type KeyconfigVerification } from './keyconfig';
import { verifyKeyconfigV3, type VerifiedKeyconfigV3 } from './keyconfigV3';
import { MAX_TEXT_CHARS } from './limits';
import { CREDENTIAL_NAME, GATEWAY_BASE_URL, GATEWAY_TIMEOUT_MS, type Span } from './types';

export { GatewayError };
export type { VerifiedCapabilities };
export {
	effectiveMaxTextChars,
	MAX_TEXT_CHARS,
	MAX_TEXT_CHARS_CEILING,
	MIN_TEXT_CHARS,
} from './limits';

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
	/** Length of one Retry-After second in a multi-part rate-limit wait, in ms (default 1000). */
	retryAfterSecondMs?: number;
	/** Fixed ephemeral key (test vectors only: reusing it reuses the AES-GCM key and nonce). */
	testEphemeral?: TestEphemeral;
	/** Fixed 64-byte X-Wing `eseed` for protocol v3 (test vectors only, as `testEphemeral`). */
	testEseed?: Buffer;
};

export type AnalyzeOptions = {
	/** Ask for the review-only `possible` spans (`"possible": true` in the sealed payload). */
	possible?: boolean;
	/**
	 * Per-request text cap in code points (`effectiveMaxTextChars`); defaults to MAX_TEXT_CHARS.
	 * A longer text is sent in parts of `partTargetFor(maxTextChars)` code points.
	 */
	maxTextChars?: number;
	/**
	 * EXPERIMENTAL: whether post-quantum encryption (protocol v3) is on, read before EVERY send
	 * (every part, retry and reseal). Only `true` is on. A reader that throws fails the text (no
	 * silent fallback). Omitted: off, every request is v2.
	 */
	postQuantum?: () => boolean | Promise<boolean>;
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

/** Keyconfig cache TTL, matching the extension. The cached document is re-verified on every use. */
export const KEYCONFIG_TTL_MS = 10 * 60 * 1000;
/** Capabilities: refetch a verified document after this; after a failed attempt wait as long. */
export const CAPABILITIES_TTL_MS = 5 * 60 * 1000;
export const CAPABILITIES_RETRY_MS = 5 * 60 * 1000;
/** Pause before the second analyze attempt (server error). */
export const ANALYZE_RETRY_DELAY_MS = 1000;
/** Pause before the renewal-race keyconfig refetch. */
export const KEYCONFIG_RETRY_DELAY_MS = 2000;
/**
 * A part of a multi-part text waits out a rate limit up to this many times (Retry-After, else
 * RATE_LIMIT_DEFAULT_S; a longer wait than RATE_LIMIT_MAX_WAIT_S fails the text), as the extension.
 */
export const RATE_LIMIT_WAITS = 3;
export const RATE_LIMIT_DEFAULT_S = 5;
export const RATE_LIMIT_MAX_WAIT_S = 60;
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
/** EXPERIMENTAL protocol v3: the raw /v1/keyconfig JSON whose `v3` member verified. */
const keyconfigV3Cache = new Map<string, KeyconfigCacheEntry>();
const capabilitiesCache = new Map<string, CapabilitiesCacheEntry>();
/**
 * The highest delegation serial that ever verified: a delegation below it is refused, so a stolen
 * older delegated key cannot be replayed once the renewal was seen. Never lowered; only a
 * successful keyconfig acquisition raises it, v2 or v3 alike, through `commitDelegationFloor`
 * (capabilities only read it). The floor belongs to the delegation, which v2 and v3 share.
 */
const delegationFloors = new Map<string, number>();
// One keyconfig acquisition (and one capabilities refresh) at a time in this process.
let keyconfigQueue: Promise<unknown> = Promise.resolve();
let capabilitiesQueue: Promise<unknown> = Promise.resolve();

/** Empties every module-level cache and the serial floors (tests). */
export function clearGatewayCaches(): void {
	keyconfigCache.clear();
	keyconfigV3Cache.clear();
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

function gatewayError(failure: FetchFailure): GatewayError {
	const text = gatewayErrorText(failure.error, {
		retryAfter: failure.retryAfter,
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
// Keyconfig (v2, and the EXPERIMENTAL v3 member through the same acquisition)

/** What a keyconfig acquisition yields: the selected key and the delegation serial. */
type VerifiedKey = {
	ok: true;
	keyId: number;
	publicKey: Buffer;
	issuedAt: number;
	serial: number;
	notAfter: number;
};

type KeyconfigResult = VerifiedKey | (FetchFailure & { belowFloor?: boolean });

/** One protocol's view of /v1/keyconfig: its own cache of the raw JSON and its own verifier. */
type KeyconfigFlavor = {
	cache: Map<string, KeyconfigCacheEntry>;
	verify: (
		config: unknown,
		options: GatewayTestSeams | undefined,
	) => VerifiedKey | { ok: false; error: GatewayErrorCode };
};

const V2_KEYCONFIG: KeyconfigFlavor = {
	cache: keyconfigCache,
	verify: (config, options) =>
		verifyKeyconfigV2(config, roots(options), nowSeconds(options), EXPECTED_AUDIENCE),
};

/** EXPERIMENTAL protocol v3: only the `v3` member is read (never `v2`). */
const V3_KEYCONFIG: KeyconfigFlavor = {
	cache: keyconfigV3Cache,
	verify: (config, options) =>
		verifyKeyconfigV3(config, roots(options), nowSeconds(options), EXPECTED_AUDIENCE),
};

function verifyConfig(
	flavor: KeyconfigFlavor,
	config: unknown,
	floor: number,
	options: GatewayTestSeams | undefined,
): VerifiedKey | { ok: false; error: GatewayErrorCode; belowFloor?: true } {
	const result = flavor.verify(config, options);
	if (!result.ok) return result;
	if (result.serial < floor) {
		return { ok: false, error: 'hpke_unverified_keyconfig', belowFloor: true };
	}
	return result;
}

/**
 * The one read-compare-raise of the delegation serial floor, shared by the v2 and v3 acquisitions
 * (both run inside `enqueue('keyconfig')`, so they never race): re-read the floor, refuse a serial
 * below it, raise it to a higher one, never lower it. Returns whether `serial` may be used.
 */
function commitDelegationFloor(key: string, serial: number): boolean {
	const floor = delegationFloors.get(key) ?? 0;
	if (serial < floor) return false;
	if (serial > floor) delegationFloors.set(key, serial);
	return true;
}

/**
 * Remembers a freshly fetched config that verified and raises the floor. If the floor rose above
 * this config's serial meanwhile, nothing is stored and the caller treats it as below the floor.
 */
function storeConfig(
	flavor: KeyconfigFlavor,
	key: string,
	config: unknown,
	serial: number,
	options: GatewayTestSeams | undefined,
): boolean {
	if (!commitDelegationFloor(key, serial)) return false;
	flavor.cache.set(key, { config, fetchedAt: nowMs(options) });
	return true;
}

async function acquireKeyconfigOnce(
	ctx: GatewayContext,
	flavor: KeyconfigFlavor,
	force: boolean,
	options: GatewayTestSeams | undefined,
): Promise<KeyconfigResult> {
	const key = stateKey(options);
	const floor = delegationFloors.get(key) ?? 0;
	const cached = flavor.cache.get(key);
	if (!force && cached && nowMs(options) - cached.fetchedAt < KEYCONFIG_TTL_MS) {
		// Never trusted as stored: re-verified on every use.
		const verified = verifyConfig(flavor, cached.config, floor, options);
		if (verified.ok) return verified;
		// Expired or otherwise no longer valid: drop it and fetch once.
		flavor.cache.delete(key);
	}

	for (let attempt = 1; ; attempt++) {
		const result = await gatewayFetch(ctx, 'GET', KEYCONFIG_PATH, undefined, {
			retryServerErrors: true,
			timeoutMs: KEYCONFIG_TIMEOUT_MS,
		});
		if (!result.ok) return result;
		// A 200 that is sealed is not a keyconfig.
		const config = result.sealed ? {} : result.data;
		const verified = verifyConfig(flavor, config, floor, options);
		if (verified.ok && storeConfig(flavor, key, config, verified.serial, options)) return verified;
		if (!verified.ok && !('belowFloor' in verified)) {
			return { ok: false, status: result.status, error: verified.error };
		}
		// Renewal race: this replica still serves the older delegation while the newer one was
		// already seen. Keep the previously verified config if it still holds against the current
		// floor; else ask again once, a little later.
		const current = delegationFloors.get(key) ?? 0;
		if (cached) {
			const previous = verifyConfig(flavor, cached.config, current, options);
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
	flavor: KeyconfigFlavor = V2_KEYCONFIG,
): Promise<KeyconfigResult> {
	return enqueue('keyconfig', async () => await acquireKeyconfigOnce(ctx, flavor, force, options));
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

/**
 * EXPERIMENTAL protocol v3: the verified X-Wing key from the `v3` member, as `acquireKeyconfig`
 * (same queue, same delegation serial floor, its own cache). Throws GatewayError, with
 * `hpke_pq_unavailable` when the gateway offers no `v3` member. For diagnostics and tests.
 */
export async function acquireKeyconfigV3(
	ctx: GatewayContext,
	options?: GatewayTestSeams & { force?: boolean },
): Promise<VerifiedKeyconfigV3> {
	const result = await acquireKeyconfigResult(ctx, options?.force === true, options, V3_KEYCONFIG);
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
	postQuantum = false,
): SealedRequest | undefined {
	try {
		return postQuantum
			? sealRequestV3(publicKey, keyId, payload, options?.nowSeconds, options?.testEseed)
			: sealRequestV2(publicKey, keyId, payload, options?.nowSeconds, options?.testEphemeral);
	} catch {
		return undefined;
	}
}

/** EXPERIMENTAL: whether this send is post-quantum (v3). Only an explicit `true` is on. */
async function postQuantumOn(options: AnalyzeOptions | undefined): Promise<boolean> {
	if (typeof options?.postQuantum !== 'function') return false;
	return (await options.postQuantum()) === true;
}

/**
 * The length of `text` in Unicode code points (the server's len(text)); a lone surrogate counts as
 * one, as in codePointSpansToUtf16.
 */
function codePointLength(text: string): number {
	return /[\uD800-\uDFFF]/.test(text) ? Array.from(text).length : text.length;
}

/**
 * Seal {text[, entities][, possible]}, POST it, open the sealed answer (`analyzeSealed`): ONE
 * request's worth of text (one part). At most two HTTP attempts, each with a FRESH seal (three with
 * post-quantum on, whose bad-version reseal has its own budget). A text over the per-request cap
 * (code points) is refused before anything is sealed; the chunker keeps every part below it, so
 * this is only a guard.
 */
async function analyzeSealed(
	ctx: GatewayContext,
	text: string,
	filter: string[] | undefined,
	options: AnalyzeOptions | undefined,
): Promise<AnalyzeOutcome> {
	if (codePointLength(text) > (options?.maxTextChars ?? MAX_TEXT_CHARS)) {
		return { ok: false, error: 'payload_too_large' };
	}
	const wantPossible = options?.possible === true;
	const payload: Record<string, unknown> =
		filter !== undefined && filter.length > 0 ? { text, entities: filter } : { text };
	if (wantPossible) payload.possible = true;

	let refetchKeyconfig = false;
	// The one retry (rotation, server error) and, for v3 only, the one bad-version reseal.
	let retried = false;
	let badVersionResealed = false;
	for (;;) {
		// Read at every send: post-quantum on now means v3 or nothing, never v2.
		const postQuantum = await postQuantumOn(options);
		const kc = await acquireKeyconfigResult(
			ctx,
			refetchKeyconfig,
			options,
			postQuantum ? V3_KEYCONFIG : V2_KEYCONFIG,
		);
		refetchKeyconfig = false;
		if (!kc.ok) return kc;
		const sealed = sealFor(kc.publicKey, kc.keyId, payload, options, postQuantum);
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

		if (postQuantum && plainStatus !== undefined && failure.error === 'hpke_bad_version') {
			// v3 switched off since the keyconfig was fetched, or replicas disagree during a
			// restart: refetch once and reseal once (a refetch without `v3` ends in
			// hpke_pq_unavailable). A second one ends the part. Never resent as v2.
			if (badVersionResealed) return { ...failure, error: 'hpke_pq_unavailable' };
			badVersionResealed = true;
			refetchKeyconfig = true;
			continue;
		}
		if (retried) return failure;
		if (failure.error === 'hpke_unknown_key' || failure.error === 'hpke_key_expired') {
			retried = true;
			refetchKeyconfig = true; // rotated under us
			continue;
		}
		if (
			(plainStatus !== undefined && plainStatus >= 500) ||
			failure.error === 'busy' ||
			failure.error === 'internal_error'
		) {
			retried = true;
			await sleep(options?.retryDelayMs ?? ANALYZE_RETRY_DELAY_MS);
			continue;
		}
		return failure;
	}
}

/**
 * One part, with the multi-part rate-limit rule: a part of a text of two or more parts waits out a
 * 429 (Retry-After, else RATE_LIMIT_DEFAULT_S) up to RATE_LIMIT_WAITS times, then fails; a wait
 * longer than RATE_LIMIT_MAX_WAIT_S fails at once. A one-part text answers rate_limited at once, as
 * before (Retry On Fail is the n8n way to wait there).
 */
async function analyzePart(
	ctx: GatewayContext,
	text: string,
	filter: string[] | undefined,
	multiPart: boolean,
	options: AnalyzeOptions | undefined,
): Promise<AnalyzeOutcome> {
	for (let waits = 0; ; waits++) {
		const outcome = await analyzeSealed(ctx, text, filter, options);
		if (outcome.ok || outcome.error !== 'rate_limited' || !multiPart || waits >= RATE_LIMIT_WAITS) {
			return outcome;
		}
		const seconds =
			outcome.retryAfter !== undefined && outcome.retryAfter > 0
				? outcome.retryAfter
				: RATE_LIMIT_DEFAULT_S;
		if (seconds > RATE_LIMIT_MAX_WAIT_S) return outcome;
		await sleep(seconds * (options?.retryAfterSecondMs ?? 1000));
	}
}

/**
 * Sends `text` sealed to the gateway and returns the detected spans (UTF-16 offsets into `text`).
 * `entityTypes` undefined or empty means "all types" (the field is omitted). With
 * `options.possible`, also returns the review-only `possible` spans. Throws GatewayError on every
 * failure.
 *
 * There is no length limit: a text longer than one request (`options.maxTextChars`, the per-request
 * cap in code points, MAX_TEXT_CHARS by default) is cut into parts of
 * min(maxTextChars - 2000, 100 000) code points at line ends (`chunker.split`), the parts are
 * analysed one after another (each sealed afresh, a fresh frame per request), and their spans,
 * UTF-16 offsets into each part, are shifted by the part's UTF-16 start and merged
 * (`chunker.merge`). Fail closed: any part that fails throws for the whole text, with
 * `failedPart` / `parts` set on the GatewayError when there are two or more parts; nothing of the
 * other parts is returned. `invalid_entities` with a filter restarts the whole text once without
 * the filter, from the first part.
 */
export async function analyze(
	ctx: GatewayContext,
	text: string,
	entityTypes?: string[],
	options?: AnalyzeOptions,
): Promise<GatewayAnalyzeResult> {
	const parts: TextPart[] = split(text, partTargetFor(options?.maxTextChars ?? MAX_TEXT_CHARS));
	let filter = Array.isArray(entityTypes) && entityTypes.length > 0 ? [...entityTypes] : undefined;
	let entityFilterIgnored = false;
	const results: Array<{ entities: Span[]; possible: PossibleSpan[] }> = [];
	for (let index = 0; index < parts.length; index++) {
		const outcome = await analyzePart(ctx, parts[index].text, filter, parts.length > 1, options);
		if (!outcome.ok && outcome.error === 'invalid_entities' && filter !== undefined) {
			// The gateway refused our entity-type names (version skew). Fail OPEN to complete
			// anonymization, the privacy-safe direction, exactly once for the whole text, and flag it.
			entityFilterIgnored = true;
			filter = undefined;
			results.length = 0;
			index = -1; // from the first part again
			continue;
		}
		if (!outcome.ok) {
			const error = gatewayError(outcome);
			if (parts.length > 1) {
				error.failedPart = index + 1;
				error.parts = parts.length;
			}
			throw error;
		}
		results[index] = { entities: outcome.spans, possible: outcome.possible };
	}
	const merged = merge(parts, results);
	return { spans: merged.entities, possible: merged.possible, entityFilterIgnored };
}

// ---------------------------------------------------------------------------------------------
// Capabilities

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
