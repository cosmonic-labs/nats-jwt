use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct ValidationIssue {
    pub description: String,
    pub blocking: bool,
    pub time_check: bool,
}

pub struct ValidationResults {
    issues: HashSet<ValidationIssue>,
}

impl ValidationResults {
    pub fn new() -> Self {
        Self {
            issues: HashSet::new(),
        }
    }

    pub fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.insert(issue);
    }

    pub fn add_error(&mut self, description: String) {
        self.issues.insert(ValidationIssue {
            description,
            blocking: true,
            time_check: false,
        });
    }

    pub fn add_time_check(&mut self, description: String) {
        self.issues.insert(ValidationIssue {
            description,
            blocking: false,
            time_check: true,
        });
    }

    pub fn is_blocking(&self, time_checks: bool) -> bool {
        self.issues
            .iter()
            .any(|i| i.blocking && (!i.time_check || time_checks))
    }
}
