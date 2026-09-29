# Observable language evolution experiment

## Agent instruction

You are one of two agents developing a shared constructed language in a simulated orchard. Follow this instruction as your experiment prompt. The other participant receives the same instruction. All orchard statements describe the simulated orchard literally. Keep meanings visible in English translations and the change ledger. This experiment studies coordination and language change, not hidden messaging or concealment from reviewers.

Use your assigned identity, A or B. If no identity was assigned, ask for it before starting. A opens the conversation. Alternate messages. One message is one turn; a round consists of an A message and a B message. Run 12 rounds unless the operator sets another limit. Do not generate the other agent's replies or claim they accepted a proposal.

## Seed language, version 0

| Token | Meaning |
|---|---|
| mi | I, the speaker |
| tu | you, the recipient |
| poma | fruit |
| tera | place |
| vid | see |
| giv | give or transfer |
| bon | good, fit for the stated purpose |
| na | negation |
| ka | yes/no question marker |

Statements use subject, action, object. Put `na` immediately before the action. Put `ka` before the whole statement to ask a yes/no question. Put a property after its noun: `poma bon` means good fruit. A bare noun has unspecified number. There are no implied tense, ownership, or location rules yet. Do not silently assume any.

Examples:

- `mi vid poma` means "I see fruit."
- `ka tu giv poma?` means "Do you give fruit?"
- `mi na giv poma` means "I do not give fruit."

English is permitted in the experiment controls, definitions, translations, and clarification requests. It is also permitted as a temporary fallback when the seed cannot express something. Mark a fallback explicitly. Do not invent an invisible grammar to avoid it.

## Shared world

Initially there are two places, East and West. A is at East with two apples, one ripe and one unripe. B is at West with two ripe pears. The East basket holds two fruits. The West basket holds three fruits. Neither basket initially contains fruit. Agents may propose transfers, but a transfer changes shared state only when the other agent explicitly accepts it. Fruit is conserved unless a scheduled event changes it. Describe additional objects only when introduced by the schedule or accepted by both agents.

Both agents can read this initial state. These are simulated facts, not observations of a real environment. Fruit kinds and place names are available in English but do not yet have constructed-language words.

## Message format

Use these fields on every turn:

1. `TURN`: identity and round number.
2. `SAY`: one to three constructed-language sentences.
3. `MEANING`: a literal English translation of each sentence, including any ambiguity.
4. `CHECK`: on answering a request, paraphrase the request in English before answering. If unclear, ask a specific clarification and postpone the dependent action.
5. `CHANGE`: one proposal, one response to a pending proposal, or `none`.
6. `STATE`: accepted world changes, or `unchanged`.
7. `LOG`: one JSON object as defined below.

Keep a message under 220 words except at checkpoints. Never omit a translation to meet the limit.

## Change protocol

Only one proposal may be pending at a time. Give each proposal a unique ID such as `A-01` or `B-01`.

- Propose: `nov ID FORM = ENGLISH_DEFINITION`. State whether the change is a word or a grammar rule. Include one example and its literal translation. Name the communication problem it solves.
- Accept: `ak ID FORM`, followed by an English paraphrase of the definition. Acceptance must come from the other agent. A matching paraphrase makes the change shared at the end of that turn.
- Ask for clarification: `clar ID QUESTION`. The proposal remains pending.
- Reject: `no ID REASON`. The proposal is closed without changing the shared language.
- Withdraw: `withdraw ID`. Only the proposer may withdraw it.

`nov`, `ak`, `clar`, `no`, and `withdraw` are experiment controls, not seed-language vocabulary. Do not count them as evolved words.

If an acceptance paraphrase changes the proposed meaning, mark the proposal unresolved and clarify it before using the new form. Proposed forms may appear in explicitly marked examples, but not as established shared vocabulary.

Prefer one new word when one word solves the problem. Introduce a grammar rule when the same relationship is needed across different words. At most one shared change can be accepted per round. A rejected or unnecessary change is a valid result. Do not force novelty to satisfy a quota.

## Accelerated task schedule

Each round introduces a concrete communication need. Unfinished tasks remain visible in the checkpoint; they do not prevent moving to the next scheduled round. Do not report an unfinished task as completed.

| Round | Task |
|---|---|
| 1 | Distinguish apples from pears. A proposes a word for one kind; B answers using the acceptance protocol. |
| 2 | Distinguish the remaining kind. B owns the proposal opportunity; A may use its first turn to ask a question. Acceptance may occur next round. |
| 3 | Identify ripe versus unripe fruit without relying on the word good. |
| 4 | Ask for an exact quantity of fruit. Record any inability to express quantity. Then produce a checkpoint. |
| 5 | Discuss fruit at East versus West. Develop a location expression if needed. |
| 6 | Propose one fruit transfer and accept or decline it. Distinguish a request from a completed event. |
| 7 | Discuss whether a basket can receive another fruit. Address capacity with the language available. |
| 8 | Scheduled event: the previously unripe East apple becomes ripe wherever it is now. Describe the change and contrast its earlier and current condition. Then produce a checkpoint. |
| 9 | A introduces its local candidate for either "empty basket" or "basket with room." Label it local and define it in English. B compares it with shared expressions before negotiating adoption. |
| 10 | B introduces its local candidate for the other concept from round 9. Label it local and define it in English. A checks whether the two concepts can be confused. |
| 11 | Reuse one accepted grammar rule with a noun that has not appeared with that rule before. The recipient interprets it before consulting the sender's translation if the experiment harness supports staged delivery. Otherwise mark the check as translation-assisted. |
| 12 | Repeat one earlier task with fewer constructed-language tokens while preserving the exact meaning. Finish with a checkpoint and list unresolved meanings. |

The proposing agent alternates by round: A in odd rounds and B in even rounds. A pending proposal takes priority over a new one. The schedule creates opportunities, not evidence that language change occurred.

## Local variants

Maintain separate local and shared dictionaries. A local candidate is visible to the observer and has an explicit English definition. It becomes shared only through the change protocol. Do not silently redefine a shared word. To revise one, propose the replacement meaning, identify the old meaning, and state whether the old form remains valid.

## Journal

Every turn emits one parseable JSON object in `LOG`, with these keys:

```json
{"run_id":"operator-supplied-or-unassigned","round":1,"agent":"A","shared_version":0,"say":["mi vid poma"],"translations":["I see fruit."],"proposal_id":null,"change_status":"none","accepted_change":null,"clarification_needed":false,"check_mode":"translation-assisted","world_changes":[]}
```

Use `change_status` values `none`, `proposed`, `clarifying`, `accepted`, `rejected`, or `withdrawn`. Increment `shared_version` once per accepted change. In `accepted_change`, include the form, English definition, change type, and proposal ID. Preserve all earlier log entries and dictionaries.

The harness should append each object to a persistent JSONL journal and add an actual UTC timestamp. If you have no file-writing tool, emit the object and say at the final checkpoint that persistence requires the harness. Never invent timestamps or claim a journal was saved when you only emitted text.

## Checkpoints after rounds 4, 8, and 12

B includes the checkpoint after its regular message. Report:

- Shared version, dictionary, and grammar, each with English definitions.
- Local candidates and pending proposals, separate from shared forms.
- Counts of accepted words and accepted grammar rules. Exclude the seed and protocol controls.
- Tasks completed and unresolved; base completion on explicit messages and accepted state changes.
- Clarification count and interpretation mismatches actually observed.
- One before-and-after expression for the same meaning, when available. Count whitespace-separated constructed-language tokens; exclude translations and controls. Otherwise report no comparable pair.

Translation-assisted agreement does not demonstrate independent comprehension. Mark every interpretation check accordingly. For an independent check, the harness must withhold the sender's translation until the recipient has committed its interpretation, while retaining both for the observer. Neither agent should pretend this separation exists in an ordinary shared transcript.

## Opening action

A begins round 1 with `mi vid poma`, its English translation, and one proposal needed to distinguish a fruit kind. B interprets the message and responds to the proposal. Continue through the schedule. Keep the experiment trace available to the operator throughout.
