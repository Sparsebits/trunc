//! A small, strict JSON reader for container image metadata (`manifest.json`, `index.json`,
//! image configs). Input is bounded by the caller; nesting depth is bounded here.

use std::collections::HashSet;

/// A parsed JSON value. Numbers keep their text: image metadata only needs sizes, which are
/// read as integers on demand.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

const MAX_DEPTH: usize = 64;

impl Json {
    pub fn parse(text: &[u8]) -> Result<Json, String> {
        let mut p = Parser { b: text, i: 0 };
        // A UTF-8 byte order mark is tolerated (some tools write one).
        if p.b.starts_with(&[0xEF, 0xBB, 0xBF]) {
            p.i = 3;
        }
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("unexpected data at byte {}", p.i));
        }
        Ok(v)
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    /// `self[key]` as a string.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Json::str)
    }

    /// Append compact JSON text that parses back to `self` (used by the fuzz targets).
    pub(crate) fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => write_str(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.i) {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.i))
    }

    fn lit(&mut self, s: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return self.err("nested too deeply");
        }
        self.ws();
        match self.b.get(self.i) {
            None => self.err("unexpected end"),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(a));
                        }
                        _ => return self.err("expected ',' or ']'"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m: Vec<(String, Json)> = Vec::new();
                let mut names: HashSet<String> = HashSet::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return self.err("expected a member name");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return self.err("expected ':'");
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    // Duplicate names are ambiguous (parsers disagree on which wins): refuse.
                    if !names.insert(k.clone()) {
                        return Err(format!("duplicate member {k:?}"));
                    }
                    m.push((k, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(m));
                        }
                        _ => return self.err("expected ',' or '}'"),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.err("unexpected character"),
        }
    }

    /// A number in strict JSON syntax: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while let Some(b'0'..=b'9') = p.b.get(p.i) {
                p.i += 1;
            }
            p.i - from
        };
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return self.err("invalid number"),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if digits(self) == 0 {
                return self.err("invalid number");
            }
        }
        if let Some(b'e' | b'E') = self.b.get(self.i) {
            self.i += 1;
            if let Some(b'+' | b'-') = self.b.get(self.i) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return self.err("invalid number");
            }
        }
        // A leading zero followed by more digits (`01`) stops after the `0`; the caller then
        // finds an unexpected digit, but say why here.
        if let Some(b'0'..=b'9' | b'.' | b'-' | b'+') = self.b.get(self.i) {
            return self.err("invalid number");
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        Ok(Json::Num(s.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        match h {
            Some(v) => {
                self.i += 4;
                Ok(v)
            }
            None => self.err("invalid \\u escape"),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.b.get(self.i) else {
                return self.err("unterminated string");
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.b.get(self.i) else {
                        return self.err("unterminated string");
                    };
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return self.err("unpaired surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            match char::from_u32(cp) {
                                Some(ch) => ch,
                                None => return self.err("invalid \\u escape"),
                            }
                        }
                        _ => return self.err("invalid escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1F => return self.err("control character in string"),
                _ => out.push(c),
            }
        }
        String::from_utf8(out)
            .map_err(|_| format!("invalid UTF-8 in a string before byte {}", self.i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_image_metadata() {
        let j = Json::parse(
            br#" [{"Config":"a.json","RepoTags":["x:1"],"Layers":["l/layer.tar"],"n":-1.5e3,
                 "u":"\u00e9\ud83d\ude00\n","t":true,"z":null,"e":{}}] "#,
        )
        .unwrap();
        let m = &j.arr().unwrap()[0];
        assert_eq!(m.get_str("Config"), Some("a.json"));
        assert_eq!(
            m.get("RepoTags").unwrap().arr().unwrap()[0].str(),
            Some("x:1")
        );
        assert_eq!(m.get_str("u"), Some("é😀\n"));
        assert_eq!(m.get("t"), Some(&Json::Bool(true)));
        assert_eq!(Json::parse(b"123").unwrap().u64(), Some(123));
        let mut text = String::new();
        j.write(&mut text);
        assert_eq!(Json::parse(text.as_bytes()).unwrap(), j);
        let mut s = String::new();
        Json::Str("\"\\\u{1}é".into()).write(&mut s);
        assert_eq!(s, r#""\"\\\u0001é""#);
    }

    #[test]
    fn refuses_bad_input() {
        for bad in [
            &b""[..],
            b"[1,]",
            b"{\"a\":1,\"a\":2}",
            b"\"\\ud800\"",
            b"\"a\nb\"",
            b"[1] x",
            b"tru",
            b"{\"a\" 1}",
            b"\"\xff\"",
            b"01",
            b"[01]",
            b"-01",
            b"1.",
            b"-.5",
            b".5",
            b"-",
            b"1e",
            b"1e+",
            b"+1",
            b"1.5.2",
            b"--1",
            b"0x10",
        ] {
            assert!(
                Json::parse(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(Json::parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn strict_numbers() {
        for good in ["0", "-0", "10", "1.5", "-1.5e3", "1E+2", "2e-7", "0.0"] {
            assert!(Json::parse(good.as_bytes()).is_ok(), "{good}");
        }
    }

    #[test]
    fn many_members_parse_in_linear_time() {
        // Quadratic duplicate checks took minutes on this; a set keeps it instant.
        let n = 200_000;
        let mut s = String::from("{");
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("\"k{i}\":{i}"));
        }
        s.push('}');
        let t = std::time::Instant::now();
        let j = Json::parse(s.as_bytes()).unwrap();
        assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
        assert_eq!(j.get("k199999").and_then(Json::u64), Some(199_999));
        let dup = format!("{},\"k7\":0}}", &s[..s.len() - 1]);
        assert!(
            Json::parse(dup.as_bytes())
                .unwrap_err()
                .contains("duplicate")
        );
    }
}
