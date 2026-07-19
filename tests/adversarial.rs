// Adversarial suite. The real tests live in finding.rs, evidence.rs, and
// location.rs. Previously only `finding` was declared, so evidence.rs (2 tests)
// and location.rs (2 tests, incl. location_deserialization_rejects_path_traversal)
// never ran. The sibling test_*.rs files and adversarial/mod.rs were empty
// stubs (0 tests) that referenced nothing real and have been removed.
mod adversarial {
    mod evidence;
    mod finding;
    mod location;
}
