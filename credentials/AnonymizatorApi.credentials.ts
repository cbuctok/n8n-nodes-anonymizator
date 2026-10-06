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
