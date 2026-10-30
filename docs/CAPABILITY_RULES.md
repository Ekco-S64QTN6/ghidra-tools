# Capability Rule DSL

The shipped `rules/*.yaml` files use the ghidra-report capability DSL, version
`1.0.0`. Its strict Draft 7 schema is
[`schemas/capability-rule-v1.schema.json`](../schemas/capability-rule-v1.schema.json).
This is a small project-specific format; it is **not** capa-compatible and does not
consume the Mandiant capa rule corpus.

## Evaluation scope

Rules declare either `scope: "file"` or `scope: "function"`.

File rules run against aggregate fields from one JSON report:
`suspicious_apis`, `threat_summary.indicators`, `memory_blocks`, and `iocs`.
Their result is labelled `evidence_quality: "file_aggregate"`.

Function rules currently support API-only expressions (including AND/OR/NOT/count)
and run independently against each entry in `function_api_evidence`. The exporter
records the caller function name/address and each resolved suspicious API's name,
target address, and call-site address. Function rules cannot combine evidence from
two different functions. Their result includes the matched caller and is labelled
`evidence_quality: "function_callsite"`. Function API primitives accept unqualified
API names; `library!function` selectors and file-only primitives are rejected for
function-scope rules.

Instruction and basic-block scopes are not supported. The function evidence is
limited to suspicious APIs that Ghidra can resolve through call operands/call graph;
it does not yet represent every call, arbitrary instruction patterns, or a complete
per-function IOC/indicator view. Evidence-quality labels describe provenance, not
probability or calibrated confidence.

## Rule metadata

Each rule requires:

- `schema_version`: exactly `"1.0.0"`.
- `id`: unique, stable `ghidra.*` identifier. Do not derive IDs from display names
  at runtime; once published, retain the same ID when wording changes.
- `name`, `namespace`, and either `scope: "file"` or `scope: "function"`.
- `meta.att&ck`: syntactically valid ATT&CK technique identifier.
- `meta.mbc`: the rule's MBC classification label.
- `meta.weight`: integer from 0 through 100, used only for result ordering/weight metadata.
- `meta.description` and `meta.rationale`: what the rule identifies and why its
  feature combination is relevant, including known benign overlap.
- `meta.references`: one or more HTTPS references. Shipped ATT&CK references point
  to the corresponding canonical MITRE ATT&CK technique page. The loader checks
  identifier syntax and HTTPS shape; it does not synchronize or certify MBC taxonomy.

Function-scope rules may only use `and`, `or`, `not`, `count`, and unqualified `api`
expressions. Other operators and library-qualified API selectors are rejected for
that scope. Unknown top-level or metadata keys fail validation. Duplicate rule IDs
fail the load.

## Feature operators

| Operator | Meaning |
|:--|:--|
| `and` | Every child expression must match. |
| `or` | At least one child expression must match. |
| `not` | Match only when the child expression does not match; this emits no positive evidence. |
| `count` | Match when at least `min` child expressions match; `min` defaults to 1. |
| `api` | Case-insensitive exact API function name; file scope also supports exact `library!function`. Substring matches are not used. |
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

All shipped rules have a positive and negative fixture. The process-injection rule
also has function-isolation controls proving that APIs from separate functions cannot
satisfy its expression together. Matching results are heuristic triage leads, not
proof of malicious behavior. Instruction/basic-block features, broader function
features, richer confidence, and semantic MBC taxonomy validation remain future work.
