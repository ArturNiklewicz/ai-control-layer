# Eval 20261003-195759

## PII (regex)

| kind | P | R | tp | fp | fn |
|---|---|---|---|---|---|
| ADDRESS | 1.0 | 0.0 | 0 | 0 | 60 |
| CARD | 1.0 | 1.0 | 20 | 0 | 0 |
| EMAIL | 1.0 | 1.0 | 40 | 0 | 0 |
| IBAN | 1.0 | 1.0 | 40 | 0 | 0 |
| ID_CARD | 1.0 | 1.0 | 20 | 0 | 0 |
| NIP | 1.0 | 1.0 | 20 | 0 | 0 |
| PERSON | 1.0 | 0.0 | 0 | 0 | 160 |
| PESEL | 1.0 | 1.0 | 40 | 0 | 0 |
| PHONE | 0.857 | 1.0 | 60 | 10 | 0 |
| REGON | 1.0 | 1.0 | 20 | 0 | 0 |
| SECRET | 1.0 | 1.0 | 20 | 0 | 0 |
| **micro** | 0.966 | 0.56 | 280 | 10 | 220 |

## PII (hybrid)

| kind | P | R | tp | fp | fn |
|---|---|---|---|---|---|
| ADDRESS | 1.0 | 1.0 | 12 | 0 | 0 |
| CARD | 1.0 | 1.0 | 4 | 0 | 0 |
| EMAIL | 1.0 | 1.0 | 8 | 0 | 0 |
| IBAN | 1.0 | 1.0 | 8 | 0 | 0 |
| ID_CARD | 1.0 | 1.0 | 4 | 0 | 0 |
| NIP | 1.0 | 1.0 | 4 | 0 | 0 |
| PERSON | 1.0 | 0.969 | 31 | 0 | 1 |
| PESEL | 1.0 | 1.0 | 8 | 0 | 0 |
| PHONE | 0.857 | 1.0 | 12 | 2 | 0 |
| REGON | 1.0 | 1.0 | 4 | 0 | 0 |
| SECRET | 1.0 | 1.0 | 4 | 0 | 0 |
| **micro** | 0.98 | 0.99 | 99 | 2 | 1 |

## Injection signatures

| dataset | pos | neg | TPR any | FPR any | TPR high | FPR high |
|---|---|---|---|---|---|---|
| injection_plen | 35 | 35 | 0.457 | 0.086 | 0.371 | 0.086 |
| deepset_prompt_injections | 263 | 399 | 0.03 | 0.005 | 0.03 | 0.0 |

| signature | injection_plen pos/neg | deepset_prompt_injections pos/neg |
|---|---|---|
| CE-001 | 1/0 | 0/0 |
| EX-001 | 1/0 | 0/0 |
| EX-002 | 2/0 | 0/0 |
| PI-001 | 2/1 | 8/0 |
| PI-002 | 2/1 | 0/0 |
| PI-003 | 3/0 | 1/0 |
| PI-004 | 3/0 | 0/0 |
| PI-005 | 2/1 | 0/0 |
| PI-007 | 0/0 | 0/2 |

## Latency (in-process)

| layer | n | p50 ms | p95 ms |
|---|---|---|---|
| pii.detect (regex) | 220 | 0.028 | 0.053 |
| pii hybrid (regex+NER) | 44 | 1261.468 | 3296.584 |
| injection.scan | 732 | 0.021 | 0.092 |
| hook.evaluate (end to end) | 350 | 0.359 | 3.659 |
