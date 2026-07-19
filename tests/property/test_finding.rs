use proptest::prelude::*;
use secfinding::{Finding, FindingKind, FindingStatus, Severity};

use crate::strategies::{arb_detail, arb_printable, arb_scanner, arb_tag, arb_target, arb_title};

proptest! {
    #[test]
    fn test_finding_serialization_symmetry(
        scanner in arb_scanner(),
        target in arb_target(),
        title in arb_title(),
        detail in arb_detail(),
        tag in arb_tag(),
        matched_value in arb_printable(64),
    ) {
        if let Ok(finding) = Finding::builder(&scanner, &target, Severity::High)
            .title(&title)
            .detail(&detail)
            .kind(FindingKind::Other)
            .status(FindingStatus::Open)
            .tag(tag.as_str())
            .matched_value(matched_value.as_str())
            .build()
        {
            let serialized = serde_json::to_string(&finding).unwrap();
            let deserialized: Finding = serde_json::from_str(&serialized).unwrap();

            assert_eq!(finding.scanner(), deserialized.scanner());
            assert_eq!(finding.target(), deserialized.target());
            assert_eq!(finding.title(), deserialized.title());
            assert_eq!(finding.detail(), deserialized.detail());
            assert_eq!(finding.tags(), deserialized.tags());
            assert_eq!(finding.matched_values(), deserialized.matched_values());
        }
    }
}
