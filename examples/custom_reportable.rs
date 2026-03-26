use secfinding::{Reportable, Severity};

struct PolicyFinding {
    source: String,
    title: String,
    score: f64,
}

impl Reportable for PolicyFinding {
    fn scanner(&self) -> &str {
        "policy-scanner"
    }

    fn target(&self) -> &str {
        &self.source
    }

    fn severity(&self) -> Severity {
        if self.score >= 0.9 {
            Severity::Critical
        } else if self.score >= 0.7 {
            Severity::High
        } else if self.score >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn detail(&self) -> &str {
        "Policy mismatch detected by governance check"
    }

    fn confidence(&self) -> Option<f64> {
        Some(self.score)
    }

    fn tags(&self) -> &[String] {
        &[]
    }

    fn cwe_ids(&self) -> &[String] {
        &[]
    }

    fn cve_ids(&self) -> &[String] {
        &[]
    }
}

fn main() {
    let f = PolicyFinding {
        source: "s3://bucket/config.yaml".into(),
        title: "Excessive privilege policy statement".into(),
        score: 0.93,
    };

    println!("scanner: {}", f.scanner());
    println!("target: {}", f.target());
    println!("severity: {}", f.severity());
    println!("rule id: {}", f.rule_id());
    println!("tags: {}", f.tags().join(", "));
    println!("{}", f.detail());
}
