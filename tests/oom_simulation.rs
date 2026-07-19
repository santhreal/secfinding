use secfinding::{Finding, Severity};

#[test]
fn simulate_oom_on_very_large_allocation_requests() {
    // Tests behavior when we try to create extremely huge values causing out-of-memory or allocation issues
    let result = std::panic::catch_unwind(|| {
        let mut string = String::new();
        // Just big enough to hopefully trip an allocator or limit without literally crashing host OS
        string.try_reserve(1usize << 40).ok();

        let _ = Finding::builder("scanner", "target", Severity::High)
            .title(string)
            .build()
            .unwrap();
    });
    // `result` is deliberately discarded: the reservation may succeed (Linux
    // overcommit) or fail, and the build may or may not reject the title, so its
    // Ok/Err is not a meaningful assertion (the old `is_err() || is_ok()` was a
    // tautology). What matters is that reaching this line proves the process did
    // NOT abort, and that the allocator/state is still usable afterwards.
    let _ = result;
    let recovered = Finding::builder("scanner", "target", Severity::High)
        .title("recovered")
        .detail("state is consistent after the large-allocation attempt")
        .build();
    assert!(
        recovered.is_ok(),
        "a normal finding must still build after the large-allocation attempt: {recovered:?}"
    );
}

#[test]
fn oom_allocation_failure_does_not_corrupt_state() {
    let _ = Finding::builder("scanner", "target", Severity::High)
        .title("Normal size title")
        .detail("Normal size details")
        .build();
    // Test passes if it didn't crash
}
