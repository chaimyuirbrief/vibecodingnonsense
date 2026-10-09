# Reply classifier evaluation

How well does Lazarus label inbound replies, and how much can you trust it unattended?
Short answer: **the deterministic rules are a strong first layer, not a complete one.**
Run it with the human review queue on, and (when you have an API key) the LLM second opinion.

## Datasets

All labels follow one written guideline (7 labels with precedence: `opt_out` > `wrong_number` >
`auto_reply` > `later` > `interested` > `not_interested` > `unclear`). The guideline is embedded in
the dataset-generation workflow and in `classify.LLM_SYSTEM`.

| file | items | origin | how it was used |
|---|---|---|---|
| `evals/replies_blind_dev.jsonl`  | 153 | round 1, blind generators | **tuned on** (errors inspected) |
| `evals/replies_blind_test.jsonl` | 153 | round 1, blind generators | held out; never inspected item-by-item; aggregate metrics viewed 6 times |
| `evals/replies_blind_dev2.jsonl` | 174 | round 2, new focus areas  | **tuned on** (errors inspected) |
| `evals/replies_blind_test2.jsonl`| 175 | round 2                   | held out; never inspected item-by-item; aggregates viewed 3 times |

Provenance (`evals/blind_dataset_provenance.json`): replies were written by LLM agents that were
told not to read this repository, each with a different focus (everyday replies, hard opt-out
negatives/positives, adversarial/injection, multilingual, wrong-number/auto-reply depth). A second
set of agents relabeled every item blind; disagreements went to a third adjudicator.

**Caveats you should weigh:**
- **Aggregate leakage.** The held-out sets were never read item by item, but their aggregate numbers were
  viewed several times, and one aggregate (the opt-out confusion row: every unsafe miss was a *decisive*
  non-opt-out label) motivated the strict gates. That gate is a general mechanism, not a pattern fitted to
  test items, but the held-out numbers are slightly optimistic for it.
- The data is **synthetic**. Real replies from your customers will differ.
- Inter-annotator agreement was 679/680. That is not evidence of label quality: the annotators are
  instances of the same model family and their errors correlate. No human verified the labels.
- Round 2 deliberately over-represents hard cases (≈30% non-English, many adversarial messages), so
  its accuracy is a pessimistic estimate for typical English-language traffic.

## Metrics that matter

1. **Unsafe opt-out misses** — a true opt-out labeled `interested`/`later`/`not_interested`/`auto_reply`
   *without* review. These keep messaging someone who said stop. Target: 0.
2. **Opt-outs stopped** — true opt-outs that end outreach (labeled opt-out or wrong-number, or sent to
   review, which pauses the lead).
3. **Review rate** — the human workload.
4. **Decisive precision** — accuracy of the labels the system acts on without a human.

## Results (rules only, no LLM)

v0 = first rules; v1 = tuned on blind_dev; v2-strict = tuned on blind_dev2 + strict gates (current).

| version | set | accuracy | review rate | opt-outs stopped | unsafe misses | decisive precision |
|---|---|---|---|---|---|---|
| v0 | blind_dev  | 0.719 | 0.333 | 39/40 | 1 | — |
| v0 | blind_test | 0.712 | 0.294 | 32/33 | 1 | — |
| v1 | blind_dev (tuned)  | 0.980 | 0.111 | 40/40 | 0 | 0.993 |
| v1 | blind_test         | 0.752 | 0.255 | 32/33 | 1 | 0.833 |
| v1 | blind_dev2 (fresh) | 0.483 | 0.443 | 35/37 | 2 | — |
| v2-strict | blind_dev (tuned)  | 0.993 | 0.124 | 40/40 | 0 | 1.000 |
| v2-strict | blind_dev2 (tuned) | 0.966 | 0.259 | 37/37 | 0 | 0.977 |
| v2-strict | **blind_test**     | **0.797** | 0.248 | **33/33** | **0** | 0.870 |
| v2-strict | **blind_test2**    | **0.634** | 0.394 | **48/50** | **2** | 0.849 |

Raw numbers: `evals/results_v2_strict_rules_only.json`. Reproduce: `lazarus eval evals/replies_blind_test2.jsonl`.

### What the numbers say

- **Rules overfit.** Every tuning round produced large gains on the set it was tuned on and small gains on
  held-out data (v1: +26 points on its dev set, +4 on held-out). Hand-written patterns cover phrasing
  someone anticipated; replies are open-ended.
- **The strict gates bought safety with human time.** A decisive non-opt-out label is now allowed only when
  the message has no opt-out-adjacent vocabulary and is in English/Spanish. That removed 1 of 1 unsafe
  misses on blind_test and 2 of 4 on blind_test2, at the cost of a 25–39% review rate.
- **Two unsafe misses remain on blind_test2** (out of 50 opt-outs). Rules-only mode is therefore
  **not suitable for fully unattended operation at volume**. With 1,000 replies, expect a handful of
  opt-outs to need the review queue or the LLM layer to catch them.
- 3–5 held-out `interested`/other replies per set were labeled `opt_out` (false positives): those leads are
  suppressed. That is lost revenue, not a compliance risk, and is the direction the design prefers.

### The LLM layer (built, not measured)

`classify(text, llm=...)` asks Claude about every reply the rules did not already resolve as opt-out or
wrong-number. The model can only move toward caution: it may upgrade to `opt_out` or flag
`possible_opt_out`; it can never clear an opt-out signal; disagreement with a decisive rule label sends
the reply to a human; invalid output falls back to review. Injection-flagged text never reaches it.

**No API key was available while building this, so the LLM path has zero accuracy measurements.**
Its *mechanics* are tested (request shape through the real `anthropic` SDK with a mocked transport;
refusal, truncation, rate-limit, malformed-JSON, budget and cache behavior). To measure it:

```bash
export ANTHROPIC_API_KEY=...            # your key
lazarus eval evals/replies_blind_test2.jsonl --llm anthropic --budget 2
```

At current list prices a full eval of one set is a few hundred short calls; the `--budget` flag is a hard
USD ceiling (BudgetedProvider), and classification calls are cached in SQLite.

## Safety properties that are tested regardless of dataset

- Appending or prefixing `STOP`/`UNSUBSCRIBE`/"stop texting me"/"remove me from your list" to any message
  always stops outreach (Hypothesis property, 200 generated cases).
- Injection-flagged replies never reach the LLM.
- The LLM cannot clear a weak opt-out signal; invalid/low-confidence model output routes to review.
- Quoted copies of the business's own message are ignored when labeling.
