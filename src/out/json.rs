//! An ordered JSON value that prints like Python's `json.dumps(v, indent=2)` (ensure_ascii on).

#[derive(Debug, Clone)]
pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn s(x: impl Into<String>) -> J {
        J::Str(x.into())
    }
    pub fn opt(x: Option<&str>) -> J {
        x.map_or(J::Null, |s| J::Str(s.to_string()))
    }
    pub fn strs(xs: &[String]) -> J {
        J::Arr(xs.iter().map(|s| J::Str(s.clone())).collect())
    }
    pub fn obj(items: Vec<(&str, J)>) -> J {
        J::Obj(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Set a key (replace in place when present, else append).
    pub fn set(&mut self, k: &str, v: J) {
        if let J::Obj(items) = self {
            if let Some(e) = items.iter_mut().find(|(x, _)| x == k) {
                e.1 = v;
            } else {
                items.push((k.to_string(), v));
            }
        }
    }

    pub fn dumps(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Int(n) => out.push_str(&n.to_string()),
            J::Str(s) => quote(s, out),
            J::Arr(a) if a.is_empty() => out.push_str("[]"),
            J::Arr(a) => {
                out.push_str("[\n");
                for (i, v) in a.iter().enumerate() {
                    out.push_str(&"  ".repeat(depth + 1));
                    v.write(out, depth + 1);
                    out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
                }
                out.push_str(&"  ".repeat(depth));
                out.push(']');
            }
            J::Obj(o) if o.is_empty() => out.push_str("{}"),
            J::Obj(o) => {
                out.push_str("{\n");
                for (i, (k, v)) in o.iter().enumerate() {
                    out.push_str(&"  ".repeat(depth + 1));
                    quote(k, out);
                    out.push_str(": ");
                    v.write(out, depth + 1);
                    out.push_str(if i + 1 < o.len() { ",\n" } else { "\n" });
                }
                out.push_str(&"  ".repeat(depth));
                out.push('}');
            }
        }
    }
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_like_python_indent_2() {
        let v = J::obj(vec![("a", J::Int(1)), ("b", J::Arr(vec![])), ("c", J::obj(vec![("d", J::s("é\n"))])), ("e", J::Null)]);
        assert_eq!(v.dumps(), "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {\n    \"d\": \"\\u00e9\\n\"\n  },\n  \"e\": null\n}");
    }
}
