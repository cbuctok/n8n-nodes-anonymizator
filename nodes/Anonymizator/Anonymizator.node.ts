import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { detectDescription, executeDetect } from './actions/detect';
import { createProtectRunState, executeProtect, protectDescription } from './actions/protect';
import { executeReveal, revealDescription } from './actions/reveal';
import { errorNode } from './shared/errors';

export class Anonymizator implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Anonymizator',
		name: 'anonymizator',
		icon: {
			light: 'file:../../icons/anonymizator.svg',
			dark: 'file:../../icons/anonymizator.dark.svg',
		},
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Replace personal data in text with placeholders before it reaches an LLM, and reveal it again',
		defaults: {
			name: 'Anonymizator',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'anonymizatorApi',
				required: true,
				displayOptions: { show: { operation: ['protect', 'detect'] } },
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Detect',
						value: 'detect',
						action: 'Detect personal data',
						description:
							'Report what personal data the text contains, without changing it. Useful for routing before an LLM call.',
					},
					{
						name: 'Protect',
						value: 'protect',
						action: 'Protect text',
						description: 'Replace personal data with placeholders',
					},
					{
						name: 'Reveal',
						value: 'reveal',
						action: 'Reveal text',
						description:
							'Put the original values back using a placeholder map. Runs locally, no credential needed. The output holds the real values.',
					},
				],
				default: 'protect',
			},
			{
				displayName:
					'Only detection runs on the Anonymizator gateway: it receives the encrypted text, returns ranges and keeps nothing. Everything else, including placeholders and the map, happens here in n8n. n8n saves execution data, including the original text and the map, so restrict saved executions for workflows that handle sensitive text.',
				name: 'notice',
				type: 'notice',
				default: '',
				displayOptions: { show: { operation: ['protect', 'detect'] } },
			},
			...protectDescription,
			...detectDescription,
			...revealDescription,
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const runState = createProtectRunState();

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;

				const results =
					operation === 'reveal'
						? await executeReveal.call(this, itemIndex)
						: operation === 'detect'
							? await executeDetect.call(this, itemIndex)
							: await executeProtect.call(this, itemIndex, runState);

				returnData.push(...results);
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: itemIndex },
					});
					continue;
				}

				// The AI tool variant runs on a context without `getNode`; errorNode guards for it.
				const node = errorNode(this);

				// Errors the operations already mapped to friendly n8n errors pass through unchanged:
				// both constructors hand back an instance of their own class as-is.
				if (error instanceof NodeApiError) {
					throw new NodeApiError(node, error as unknown as JsonObject, { itemIndex });
				}
				if (error instanceof NodeOperationError) {
					throw new NodeOperationError(node, error, { itemIndex });
				}

				// A response object means the gateway answered and rejected the request. No response
				// means the request never got there, or the failure is local.
				const hasResponse =
					typeof error === 'object' &&
					error !== null &&
					typeof (error as { response?: unknown }).response === 'object';

				// Carry the underlying message into `description` so a wrapped failure never loses
				// its cause.
				const cause = (error as Error).message;
				const description =
					cause && cause !== (error as Error).name
						? cause
						: String((error as { description?: string }).description ?? '');

				if (hasResponse) {
					throw new NodeApiError(node, error as unknown as JsonObject, {
						itemIndex,
						...(description ? { description } : {}),
					});
				}

				throw new NodeOperationError(node, error as Error, {
					itemIndex,
					...(description ? { description } : {}),
				});
			}
		}

		return [returnData];
	}
}
