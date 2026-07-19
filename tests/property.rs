//! Property tests for secfinding (S-proptest-01 mass suites).

#[path = "property/proptest_filter_suite.rs"]
mod proptest_filter_suite;
#[path = "property/proptest_mass_roundtrip.rs"]
mod proptest_mass_roundtrip;
#[path = "property/strategies.rs"]
mod strategies;
#[path = "property/test_evidence.rs"]
mod test_evidence;
#[path = "property/test_finding.rs"]
mod test_finding;
#[path = "property/test_severity.rs"]
mod test_severity;
