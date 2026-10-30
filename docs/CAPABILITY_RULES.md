# Capability Rule DSL

The shipped `rules/*.yaml` files use the ghidra-report capability DSL, version
`1.0.0`. Its strict Draft 7 schema is
[`schemas/capability-rule-v1.schema.json`](../schemas/capability-rule-v1.schema.json).
This is a small project-specific format; it is **not** capa-compatible and does not
consume the Mandiant capa rule corpus.

## Evaluation scope

Every rule must declare `scope: "file"`. The evaluator runs against aggregate fields
from one JSON report: `suspicious_apis`, `threat_summary.indicators`,
`memory_blocks`, and `iocs`. It does not inspect instructions, basic blocks, or
individual functions. Rules declaring instruction, block, or function scope are
rejected during loading; changing the label cannot imply analysis capability that
the report data does not contain.

A result includes the stable rule `id`, schema version, original expression,
rationale, references, and `evidence_quality: "file_aggregate"`. This is an evidence
quality label, not a probability or calibrated confidence score. Current API evidence
records the library and function name but not a call-site address because the report's
suspicious-API data does not currently preserve call-site addresses.

## Rule metadata

Each rule requires:

- `schema_version`: exactly `"1.0.0"`.
- `id`: unique, stable `ghidra.*` identifier. Do not derive IDs from display names
  at runtime; once published, retain the same ID when wording changes.
- `name`, `namespace`, and `scope: "file"`.
- `meta.att&ck`: syntactically valid ATT&CK technique identifier.
- `meta.mbc`: the rule's MBC classification label.
- `meta.weight`: integer from 0 through 100, used only for result ordering/weight metadata.
- `meta.description` and `meta.rationale`: what the rule identifies and why its
  feature combination is relevant, including known benign overlap.
- `meta.references`: one or more HTTPS references. Shipped ATT&CK references point
  to the corresponding canonical MITRE ATT&CK technique page. The loader checks
  identifier syntax and HTTPS shape; it does not synchronize or certify MBC taxonomy.

Unknown top-level or metadata keys fail validation. Duplicate rule IDs fail the load.

## Feature operators

| Operator | Meaning |
|:--|:--|
| `and` | Every child expression must match. |
| `or` | At least one child expression must match. |
| `not` | Match only when the child expression does not match; this emits no positive evidence. |
| `count` | Match when at least `min` child expressions match; `min` defaults to 1. |
| `api` | Case-insensitive exact API function name, or exact `library!function`. Substring matches are not used. |
| `indicator` | Case-insensitive substring in an indicator description or category. |
| `section_name` | Case-insensitive exact memory-block name. |
| `section_rwx` | Match a memory block whose `rwx` value equals the requested boolean. |
| `ioc` | Case-insensitive substring in an IOC value or type. |

`and`, `or`, and `count.items` must be non-empty. Each feature node has exactly
one operator. Invalid types, unsupported operators, impossible count thresholds,
unknown keys, malformed YAML, missing PyYAML, and unsupported scopes fail closed
with the affected rule path in the diagnostic.

## Adding a rule

Copy an existing file, assign a new permanent `ghidra.*` ID, explain the rationale
and benign overlap, add a canonical reference, and construct the feature expression.
Add a positive and a negative report fixture to
[`tests/test_capability_engine.py`](../tests/test_capability_engine.py). Run:

```bash
python3 -m pip install -r requirements-rules.txt
python3 -m pip install -r requirements-test.txt
python3 tests/test_capability_engine.py
```

All shipped rules have a positive and negative fixture. Matching results are heuristic
triage leads, not proof of malicious behavior. Function/basic-block scopes, call-site
addresses, richer confidence, and semantic MBC taxonomy validation remain future work.
