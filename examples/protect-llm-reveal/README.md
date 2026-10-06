# Protect personal data before an LLM drafts a reply with Anonymizator

> **Needs a community node.** This workflow uses `n8n-nodes-anonymizator`. On a self-hosted
> instance, install it from **Settings → Community Nodes** before importing. Once n8n has verified
> the node, it can also be added from the nodes panel, including on n8n Cloud.

## Who this is for

Teams that want an LLM to work on customer messages, tickets or emails without sending the
customer's name, email address or bank details to the model provider.

## What this workflow does

*Sample Support Ticket* holds one synthetic ticket with a name, an email address and an IBAN.

*Protect* sends the ticket, encrypted, to the Anonymizator gateway. The gateway answers with the
positions of the personal data it found and keeps nothing. The node then replaces each value with a
placeholder such as `[PERSON_a7k2q]` and outputs `protectedText` and `placeholderMap`.

*Draft Reply* is a Basic LLM Chain that gets only `protectedText`. Its prompt tells the model to keep
placeholders exactly as written. *OpenAI Chat Model* is the model behind it; any chat model works.

*Reveal* takes the draft (`{{ $json.text }}`, the chain's output field) and the map from *Protect*
(`{{ $('Protect').item.json.placeholderMap }}`). It runs inside n8n with no credential and
returns `revealedText`, plus `unresolvedPlaceholders` for any placeholder the model altered or
invented.

## Setup

1. Install `n8n-nodes-anonymizator` from **Settings → Community Nodes**.
2. Import `workflow.json` (**Workflows → Import from File**).
3. Open *Protect* and create an **Anonymizator API** credential with your API key. The credential
   test checks the key when you save it.
   <!-- TODO(api-key-portal): link the page where users get an Anonymizator API key. -->
4. Open *OpenAI Chat Model* and select or create an OpenAI credential, or replace the node with
   another chat model.
5. Click **Execute workflow** and open *Reveal* to see the reply with the real values.

## How to customize

- Replace *When Clicking ‘Execute Workflow’* and *Sample Support Ticket* with your trigger, and point
  the Text field of *Protect* at the field that holds your text.
- Change the instructions in *Draft Reply*, but keep the sentence about placeholders.
- Swap the Basic LLM Chain for an AI Agent; then use `{{ $json.output }}` as Reveal's Text.
- If you rename *Protect*, update the Placeholder Map expression in *Reveal*.
- Add an IF node after *Reveal* that stops when `unresolvedPlaceholders` is not empty.

## Privacy

- The model provider sees only placeholders. The gateway sees the HPKE-encrypted ticket and returns
  positions only. See [What leaves n8n](../../README.md#what-leaves-n8n).
- The placeholder map holds the real values. It stays in n8n, but n8n stores it in execution data
  like any other output. This workflow is set not to save successful production executions; keep it
  that way, or restrict who can view executions.
- Use only synthetic data while testing.
