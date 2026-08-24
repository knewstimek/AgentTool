# Deferred Tasks

This tracked file is the handoff point for work intentionally deferred to a later session.
When resuming, inspect the current implementation and measurements rather than assuming
the numbers below still match HEAD.

## CodeGraph accuracy phase 2

Status: deferred after v0.9.5. The embedded semantic graph is useful and stable; the
next phase should measure correctness against labeled truth before increasing the raw
`exact` rate.

### v0.9.5 baseline

| Dataset | Exact / all calls | Exact / internal resolutions | Classified | Truly unresolved |
| --- | ---: | ---: | ---: | ---: |
| Large C++ codebase standalone | 53.23% | 77.49% | 96.07% | 3.93% |
| Dependent C++ component standalone | 40.45% | 75.11% | 93.77% | 6.23% |
| Four-root workspace total | 54.53% | 78.48% | 96.53% | 3.47% |
| Dependent C++ component in workspace | 57.52% | 80.64% | 97.40% | 2.60% |

`exact` is analyzer confidence, not measured ground-truth accuracy. `candidate` preserves
reasonable alternatives and is not a failed resolution.

### Priority order

1. Build a stratified labeled benchmark of exact, candidate, external, callback, macro,
   and unresolved calls across every supported language. Report precision@1, recall@k,
   MRR, Brier score, and expected calibration error. Persist reproducible fixtures and
   keep private real-world source paths opt-in.
2. Parse build metadata without invoking external toolchains: `compile_commands.json`,
   Visual Studio `.sln`/`.vcxproj`/property sheets, Cargo features, Go modules/workspaces,
   C# project files, and Java Maven/Gradle metadata. Feed include paths, defines, features,
   and source sets into condition and visibility provenance.
3. Add function-local SSA-lite and field-sensitive points-to propagation for pointer and
   reference reassignment, aliases, container extractions, returned objects, and callback
   flow. Keep analysis bounded and incremental.
4. Strengthen C++ overload resolution with cv/ref qualifiers, pointer and inheritance
   conversions, default arguments, enums, template deduction, ADL, and operators.
5. Refine polymorphic calls with allocation-aware rapid type analysis so impossible
   override targets can be removed without hiding legitimate alternatives.
6. Extend language-specific project semantics for Rust associated items/macros, C# generic
   and extension receivers, Java wildcards/default methods, and Go interface type sets.
7. Add `explain` and `quality` operations that show persisted evidence, rejected candidates,
   score margins, configuration provenance, uncertainty hotspots, and aggregate calibration.

### Constraints

- Preserve the dependency-free default: source analysis must work without Go, Rust, C++,
  Java, or .NET toolchains installed on the target machine.
- Optional semantic integrations may be additive, but absence of an external binary must
  never disable the embedded analyzer.
- Do not optimize the `exact` percentage alone. Reject changes that improve coverage by
  turning false positives into confident-looking edges.
- Preserve deterministic serial/parallel output, bounded candidate sets, incremental
  indexing, schema migration, and multi-root source isolation.

### Completion gate

- A checked-in ground-truth suite and reproducible metric report exist.
- Confidence bins are calibrated and exact false-positive regressions are blocked in CI.
- Every supported language has focused regression coverage.
- The benchmark codebases are rerun standalone and as a scoped workspace, with
  accuracy, coverage, performance, database size, and binary size compared to v0.9.5.
- User-facing behavior and release notes are updated.

To resume, ask: `NEXT_TASKS.md의 CodeGraph accuracy phase 2를 goal로 잡고 시작해줘.`
