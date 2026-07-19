# secfinding  -  Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
Universal security finding types for vulnerability scanners.

## Purpose
Provides a shared language and data structures (Finding, Severity, Evidence, etc.) for all Santh security tools to report their findings consistently.

## North Star
The standard for security finding representation, enabling seamless integration between different scanners, reporting engines, and triage dashboards.

## Role in Ecosystem
- **Depends on:** `chrono`, `serde`, `uuid`.
- **Depended on by:** Almost every scanner and reporting tool (e.g. `vulnir`, `bugscope`, `secreport`).
- **Relationship to warpscan:** The primary data format for scan results.
- **Standalone value:** YES  -  A clean, well-defined set of Rust types for security findings.

## Invariants
- Finding UUIDs are globally unique.
- Severities follow a strict, well-defined order (Info < Low < Medium < High < Critical).
- Evidence types are structured and serializable without loss of detail.

## Boundaries
- Does not perform any scanning  -  it only defines the finding data model.
- Does not handle finding storage or persistence directly  -  that's for higher-level crates or databases.

## Quality State
- Tests: >10 including property tests (proptest).
- Lint preamble: yes (pedantic)
- #![forbid(unsafe_code)]: yes
- Doc coverage: ~95%
- Known issues: None.
