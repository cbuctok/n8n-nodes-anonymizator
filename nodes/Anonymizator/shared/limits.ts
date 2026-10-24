/**
 * The gateway's per-request text cap, shared by the transport (`gateway.ts`) and the chunker
 * (`chunker.ts`). Port of `MAX_TEXT_CHARS` and `effectiveMaxTextChars` in the extension's
 * `lib/gateway.js`.
 *
 * The cap is per REQUEST, in Unicode code points (what the server counts: Python `len(text)`), not
 * per text: a longer text is cut into parts of `partTarget(caps)` code points (`chunker.ts`).
 */

/**
 * The bundled per-request cap, used when no verified capabilities document is at hand. It must
 * never exceed a cap a server publishes (parts would be refused), so it is MIN_TEXT_CHARS, the floor
 * of the plausibility window: no cap the node accepts is below it (parts of 8 000). The hosted
 * server publishes 14 000 (parts of 12 000).
 */
export const MAX_TEXT_CHARS = 10000;
/** Bounds for a cap taken from a verified capabilities document. */
export const MIN_TEXT_CHARS = 10000;
export const MAX_TEXT_CHARS_CEILING = 1000000;
// Body headroom for the frame, padding and JSON around the text, and the worst case of 6 body
// bytes per character (a JSON \uXXXX escape).
const BODY_OVERHEAD_BYTES = 8192;
const BODY_BYTES_PER_CHAR = 6;

/**
 * The per-request text cap in code points: the server's, from a verified capabilities document,
 * when it is plausible (v = min(max_text_chars, floor((max_body_bytes - 8192) / 6)) within
 * [10 000, 1 000 000]), else the bundled 10 000 (= MIN_TEXT_CHARS). The BFF and the gateway still
 * enforce their own caps; this decides how long one request may be (`partTarget` cuts parts 2 000
 * below it).
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
