use secfinding::{Finding, FindingFilter, FindingKind, Severity};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn stress_finding_builder() {
    let mut handles = vec![];
    for _ in 0..32 {
        handles.push(thread::spawn(|| {
            for i in 0..1000 {
                let _ = Finding::builder("scanner", "target", Severity::High)
                    .title(format!("Finding {}", i))
                    .detail("Detail")
                    .kind(FindingKind::Vulnerability)
                    .build()
                    .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

// Salvaged from the previously dead tests/concurrent/test_filter.rs (orphaned
// behind an unwired tests/concurrent/mod.rs) and updated to the current API:
// FindingFilter grew fields (needs `..Default::default()`), its list fields are
// Vec<Arc<str>> (needs `.into()`), and Finding fields are private (needs the
// `scanner()` accessor). 100 threads share one filter+finding and read concurrently.
#[test]
fn concurrent_filter_reads_are_consistent() {
    let filter = Arc::new(FindingFilter {
        min_severity: Some(Severity::High),
        exclude_scanners: vec!["noisy-scanner".into()],
        include_tags: vec!["critical-tag".into()],
        ..Default::default()
    });

    let finding = Arc::new(
        Finding::builder("good-scanner", "target", Severity::Critical)
            .title("Title")
            .tag("critical-tag")
            .build()
            .unwrap(),
    );

    let num_threads = 100;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let barrier_clone = Arc::clone(&barrier);
        let filter_clone = Arc::clone(&filter);
        let finding_clone = Arc::clone(&finding);

        handles.push(thread::spawn(move || {
            barrier_clone.wait(); // force all threads to start together
            let slice = std::slice::from_ref(&*finding_clone);
            let filtered = secfinding::filter(slice, &filter_clone);
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].scanner(), "good-scanner");
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
