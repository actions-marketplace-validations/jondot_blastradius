//! The YARA pass: compile a rules file with yara-x and scan file content.

use crate::error::{BrError, BrResult};

pub struct Rules {
    rules: yara_x::Rules,
    pub names: Vec<String>,
    pub sha256: String,
}

/// The rule names a source declares (`rule NAME {`).
pub fn declared(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+(\w+)").unwrap();
    let mut v: Vec<String> = vec![];
    for c in re.captures_iter(text) {
        let n = c[1].to_string();
        if !v.contains(&n) {
            v.push(n);
        }
    }
    v
}

pub fn compile(path: &str) -> BrResult<Rules> {
    let text = std::fs::read_to_string(path).map_err(|_| BrError::with_code(format!("cannot read {path}"), Some("pass a readable YARA rules file"), 2))?;
    let names = declared(&text);
    if names.is_empty() {
        return Err(BrError::with_code(format!("no rules found in {path}"), Some("the file must contain at least one 'rule NAME { ... }'"), 2));
    }
    let mut c = yara_x::Compiler::new();
    c.add_source(text.as_str()).map_err(|e| BrError::with_code(format!("{path}: {e}"), Some("fix the rule syntax; see the yara-x documentation"), 2))?;
    let rules = c.build();
    Ok(Rules { rules, names, sha256: crate::collect::fs::sha256_hex(text.as_bytes()) })
}

impl Rules {
    /// Names of the declared rules that match `data`, in rule order.
    /// A scan error is returned, never turned into "no match": the caller records it as a gap.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<String>, String> {
        let mut s = yara_x::Scanner::new(&self.rules);
        match s.scan(data) {
            Ok(r) => Ok(r.matching_rules().map(|m| m.identifier().to_string()).filter(|n| self.names.contains(n)).collect()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(tag: &str, src: &str) -> BrResult<Rules> {
        let d = std::env::temp_dir().join(format!("br-yara-{}-{tag}", std::process::id()));
        std::fs::write(&d, src).unwrap();
        let r = compile(d.to_str().unwrap());
        let _ = std::fs::remove_file(&d);
        r
    }

    #[test]
    fn matches_strings_and_only_declared_rules() {
        let r = rules("a", "rule A { strings: $a = \"netprobe\" condition: $a }\nrule B { strings: $b = \"NPROBE\" condition: $b }\n").unwrap();
        assert_eq!(r.names, vec!["A", "B"]);
        assert_eq!(r.scan(b"require('netprobe')").unwrap(), vec!["A"]);
        assert_eq!(r.scan(b"xx NPROBE xx").unwrap(), vec!["B"]);
        assert!(r.scan(b"nothing").unwrap().is_empty());
        assert_eq!(r.sha256.len(), 64);
    }

    #[test]
    fn declared_reads_rule_names() {
        assert_eq!(declared("rule X {\n}\n  private rule Y {}\n// rule Z\n"), vec!["X", "Y"]);
    }

    #[test]
    fn bad_rules_are_exit_2() {
        let e = rules("bad", "rule Bad { condition: nope }").err().unwrap();
        assert_eq!(e.code, 2);
    }
}
