# Eval datasets

| File                              | Source                                                                                                   | License    |
| --------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------- |
| `pii_pl.jsonl`                    | `eval/gen_pii.py` (seeded, fictional, checksum-valid IDs, exact gold spans)                              | this repo  |
| `injection_plen.jsonl`            | hand-written PL/EN attacks + hard benign (security talk, "ignore the flaky test")                        | this repo  |
| `deepset_prompt_injections.jsonl` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) train+test, EN/DE | Apache-2.0 |
