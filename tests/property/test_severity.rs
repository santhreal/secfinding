use proptest::prelude::*;
use secfinding::Severity;

proptest! {
    #[test]
    fn test_severity_ordering(s1 in 0u8..5, s2 in 0u8..5) {
        let sev1 = Severity::try_from(s1).unwrap();
        let sev2 = Severity::try_from(s2).unwrap();
        if s1 > s2 {
            assert!(sev1 > sev2);
        } else if s1 < s2 {
            assert!(sev1 < sev2);
        } else {
            assert_eq!(sev1, sev2);
        }
    }
}
