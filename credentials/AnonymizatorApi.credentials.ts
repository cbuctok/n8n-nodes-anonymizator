import { GATEWAY_BASE_URL } from '../nodes/Anonymizator/shared/types';

import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	Icon,
	INodeProperties,
} from 'n8n-workflow';

export class AnonymizatorApi implements ICredentialType {
	name = 'anonymizatorApi';

	displayName = 'Anonymizator API';

	icon: Icon = {
		light: 'file:../icons/anonymizator.svg',
		dark: 'file:../icons/anonymizator.dark.svg',
	};

	documentationUrl =
		'https://github.com/cbuctok/n8n-nodes-anonymizator?tab=readme-ov-file#credentials';

	properties: INodeProperties[] = [
		// TODO(api-key-portal): once the Anonymizator user portal has a public URL, name it in the
		// description below (or in a `hint`) so users can find where to create a key.
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Anonymizator API key, created and managed in the Prosecco 37 Anonymizator user portal. The node sends it as a bearer token to the privacy gateway; only Protect uses it.',
		},
		// Encryption (gateway docs/HPKE-V3-EXPERIMENTAL.md, section 9.3). Kept last and behind a
		// gate: it is a property of the connection (how the text is encrypted to the gateway), so it
		// belongs here rather than in every node's options, and the default needs no attention.
		// `postQuantum` keeps its name from 0.4.0, where it was a boolean, and its stored values:
		// `false` or absent is Automatic, `true` is Always Post-Quantum. A credential saved by 0.4.0
		// with the experimental option on therefore stays Always Post-Quantum, and every other one
		// becomes Automatic, with no migration step. Hiding the gate hides the field, and n8n then
		// passes no value, which is Automatic.
		{
			displayName: 'Show Experimental Options',
			name: 'showExperimental',
			type: 'boolean',
			default: false,
			description:
				'Whether to show the Encryption setting, whose Always Post-Quantum choice is experimental',
		},
		{
			displayName: 'Encryption',
			name: 'postQuantum',
			type: 'options',
			options: [
				{
					name: 'Always Post-Quantum (Experimental)',
					value: true,
					description:
						"Always the post-quantum protocol. Where Node.js has no ML-KEM of its own, uses a bundled copy of @noble/post-quantum, which has not been independently audited. Protect and Detect fail instead of using standard encryption when the gateway doesn't offer it.",
				},
				{
					name: 'Automatic',
					value: false,
					description:
						'Post-quantum (X-Wing) when Node.js has ML-KEM built in (24.7.0 and later) and the gateway offers it, standard encryption otherwise. Never uses bundled post-quantum code.',
				},
			],
			default: false,
			displayOptions: { show: { showExperimental: [true] } },
			description:
				'How Protect and Detect encrypt the text for the gateway. Each output item reports the encryption used in its encryption field. The connection test checks standard encryption only.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '={{"Bearer " + $credentials.apiKey.trim()}}',
			},
		},
	};

	// The gateway answers a missing or rejected key with a 302 to its login page, not a 401. With
	// redirects followed, a bad key would end on a 200 HTML page and the test would pass, so
	// redirects are disabled and 302 is mapped to a clear message.
	test: ICredentialTestRequest = {
		request: {
			baseURL: GATEWAY_BASE_URL,
			url: '/v1/keyconfig',
			method: 'GET',
			disableFollowRedirect: true,
			// n8n 2.x applies `authenticate` to the test request too (critique R4); the header is
			// repeated so the test stays authenticated on versions that build it from this object alone.
			headers: {
				Authorization: '={{"Bearer " + $credentials.apiKey.trim()}}',
			},
		},
		rules: [
			{
				type: 'responseCode',
				properties: {
					value: 302,
					message: 'API key rejected. Check the key and that it has not expired.',
				},
			},
			{
				type: 'responseCode',
				properties: {
					value: 401,
					message: 'API key rejected. Check the key and that it has not expired.',
				},
			},
			{
				type: 'responseCode',
				properties: {
					value: 403,
					message:
						'The key is valid but has no access to Anonymizator (missing role). Ask your administrator to grant it.',
				},
			},
		],
	};
}
