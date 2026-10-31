/**
 * User-facing wording for every gateway failure code (`GatewayErrorCode`).
 *
 * Taken from the extension's Protect messages (`sidepanel/sidepanel-constants.js`
 * `PROTECT_ERROR_MESSAGES`, `ACCOUNT_NOTICES`) and adapted to n8n: "the server" is the Anonymizator
 * gateway, "your computer" is the n8n host, "update the extension" is "update the
 * n8n-nodes-anonymizator package", and there is nothing to click. `message` is the error title,
 * `description` says what to do. Like the extension, no server-supplied text is ever shown: only
 * these fixed sentences, plus the code itself.
 *
 * Wording rules (AGENTS.md): say what happened and how to fix it, avoid the words "error",
 * "problem" and "failure", never include a protected value.
 */
import type { GatewayErrorCode } from './errors';

export type GatewayMessage = { message: string; description: string };

const SERVER: GatewayMessage = {
	message: 'The Anonymizator gateway could not process the text',
	description:
		'Try again. If it keeps happening, the gateway is temporarily unavailable: enable Retry On Fail with a wait between tries, or try again later.',
};
const CLOCK: GatewayMessage = {
	message: "The n8n host's clock is off",
	description:
		'Correct the date and time of the machine running n8n (for example with NTP), then try again. Requests carry a timestamp and the gateway only accepts recent ones.',
};
const SECURE: GatewayMessage = {
	message: 'The secure connection to the Anonymizator gateway did not work',
	description:
		'Try again; if it keeps happening, update the n8n-nodes-anonymizator package to the latest version.',
};
const REJECTED: GatewayMessage = {
	message: 'The Anonymizator gateway rejected the request',
	description: 'Update the n8n-nodes-anonymizator package to the latest version.',
};
/**
 * There is no limit per item: a long text is split into parts below the gateway's published
 * per-request limit. This means one part was still refused as too long (a 413 from the BFF, a sealed
 * `payload_too_large`, or the local per-request guard), so no number is named.
 */
const TOO_LONG: GatewayMessage = {
	message: 'Part of the text was too long for one request',
	description:
		"The node splits long texts into parts below the Anonymizator gateway's per-request limit, so this should not happen. Try again; if it keeps happening, update the n8n-nodes-anonymizator package to the latest version.",
};
const AUTH: GatewayMessage = {
	message: 'The Anonymizator API key was rejected',
	description:
		'Check the API key in the Anonymizator API credential: it may be mistyped, expired or revoked.',
};
const NO_ACCESS: GatewayMessage = {
	message: 'This API key has no access to Anonymizator',
	description: "Ask your organisation admin to give the key's account the Anonymizator user role.",
};
const UNVERIFIED_KEY: GatewayMessage = {
	message: "Could not verify the gateway's encryption key, so nothing was sent",
	description:
		'The key configuration is not signed by a pinned Anonymizator trust root. This can mean the connection is being intercepted (for example by a TLS-inspecting proxy). The text was not sent. Try again later.',
};

/** Wording for every failure code (the `http_<status>` family uses `gatewayErrorText`). */
export const GATEWAY_MESSAGES: Record<
	Exclude<GatewayErrorCode, `http_${number}`>,
	GatewayMessage
> = {
	auth_required: AUTH,
	unauthenticated: AUTH,
	no_access: NO_ACCESS,
	missing_role: NO_ACCESS,

	offline: {
		message: 'Could not reach the Anonymizator gateway',
		description:
			'Check that the n8n host can reach https://anon.prosecco37.com (network, DNS, proxy or firewall).',
	},
	timeout: {
		message: 'The Anonymizator gateway did not answer in time',
		description:
			'Try again. Each part of a long text must be answered within 60 s; if the gateway is busy, enable Retry On Fail with a wait between tries, or try again later.',
	},
	payload_too_large: TOO_LONG,
	rate_limited: {
		message: 'Too many requests to the Anonymizator gateway',
		description:
			'Wait a moment and try again. Enable Retry On Fail with a wait between tries, or send fewer items at once.',
	},
	busy: {
		message: 'The Anonymizator gateway is busy',
		description:
			'Try again in a few seconds. Enable Retry On Fail with a wait between tries, or send fewer items at once.',
	},
	upstream_unavailable: SERVER,
	upstream_timeout: SERVER,
	server_error: SERVER,
	internal_error: SERVER,

	hpke_stale: CLOCK,
	hpke_stale_keyconfig: {
		message: CLOCK.message,
		description: `${CLOCK.description} The gateway's signed key configuration looks expired or not yet valid by this clock, so nothing was sent.`,
	},
	hpke_unverified_keyconfig: UNVERIFIED_KEY,
	hpke_no_usable_key: {
		message: "Could not verify the gateway's encryption key, so nothing was sent",
		description:
			'The signed key configuration lists no key that stays valid long enough. The text was not sent. Try again later.',
	},

	// EXPERIMENTAL protocol v3 (the credential's Post-Quantum Encryption option). The credential
	// test checks standard encryption only, so it can pass while this fails.
	hpke_pq_unavailable: {
		message:
			"Post-quantum encryption is on, but the Anonymizator gateway doesn't offer it, so nothing was sent",
		description:
			'The text was not sent with standard encryption instead. Turn off Post-Quantum Encryption (Experimental) in the Anonymizator API credential to protect with standard encryption, or try again later. The credential test checks standard encryption only.',
	},

	hpke_required: SECURE,
	hpke_bad_frame: SECURE,
	hpke_bad_version: SECURE,
	hpke_unknown_key: SECURE,
	hpke_key_expired: SECURE,
	hpke_open_failed: SECURE,
	hpke_bad_payload: SECURE,
	hpke_replay: SECURE,
	hpke_not_configured: SECURE,
	hpke_bad_key_material: SECURE,
	hpke_seal_failed: {
		message: 'The text could not be encrypted for the gateway, so nothing was sent',
		description: `The text could not be encrypted on this n8n host, so it was not sent. ${SECURE.description}`,
	},
	hpke_bad_response: {
		message: "The gateway's answer could not be decrypted or read",
		description: SECURE.description,
	},

	invalid_payload: REJECTED,
	invalid_entities: {
		message: 'The Anonymizator gateway rejected the selected entity types',
		description: `Choose All Types under Detect, or update the n8n-nodes-anonymizator package to the latest version.`,
	},
};

/**
 * Failures decided on the n8n side, even when a response was received (an unverifiable keyconfig
 * arrives with HTTP 200). They are reported as NodeOperationError, not as an API error. The local
 * per-request guard (`payload_too_large` without an HTTP status) is local by having no status.
 */
export const LOCAL_FAILURES: ReadonlySet<GatewayErrorCode> = new Set<GatewayErrorCode>([
	'hpke_unverified_keyconfig',
	'hpke_stale_keyconfig',
	'hpke_no_usable_key',
	'hpke_pq_unavailable',
	'hpke_seal_failed',
	'hpke_bad_response',
	'timeout',
	'offline',
]);

function isKnownCode(code: string): code is keyof typeof GATEWAY_MESSAGES {
	return Object.prototype.hasOwnProperty.call(GATEWAY_MESSAGES, code);
}

/**
 * The message for `code`, with the extension's additions: "Try again in N s." for a 429 with a
 * usable Retry-After, and a fixed sentence for any `http_<status>` (or unknown) code. Never
 * interpolates anything but numbers.
 */
export function gatewayErrorText(
	code: string,
	extra?: { retryAfter?: number; httpCode?: number },
): GatewayMessage {
	if (!isKnownCode(code)) {
		const status = extra?.httpCode;
		return {
			message: `The Anonymizator gateway answered with an unexpected status${
				typeof status === 'number' && Number.isInteger(status) ? ` (HTTP ${status})` : ''
			}`,
			description: 'Try again later.',
		};
	}
	const base = GATEWAY_MESSAGES[code];
	const wait = extra?.retryAfter;
	if (code === 'rate_limited' && Number.isInteger(wait) && (wait as number) >= 1) {
		if ((wait as number) <= 300) {
			return { message: base.message, description: `${base.description} Try again in ${wait} s.` };
		}
	}
	return base;
}

/**
 * The sentence that names the failed part of a text sent in two or more parts (integers only), as
 * the extension's "(Part i of n; nothing was protected.)", or '' for a one-part text.
 */
export function failedPartText(failedPart: unknown, parts: unknown): string {
	if (!Number.isSafeInteger(failedPart) || !Number.isSafeInteger(parts)) return '';
	if (
		(parts as number) < 2 ||
		(failedPart as number) < 1 ||
		(failedPart as number) > (parts as number)
	) {
		return '';
	}
	return `This was part ${failedPart} of ${parts} of the text; no partial result is output.`;
}
