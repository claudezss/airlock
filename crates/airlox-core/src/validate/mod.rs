//! Content validators. These run on clients and runners; the server is blind.

#[cfg(feature = "image")]
pub mod image;
pub mod markdown;
pub mod sniff;
pub mod zip;

/// Invisible formatting characters (Unicode category Cf and look-alikes) that
/// can disguise a name, e.g. `x\u{202e}gnp.py` displays as `xyp.png`.
pub fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

const RESERVED: [&str; 4] = ["con", "prn", "aux", "nul"];

/// True for Windows device names (`CON`, `com1.txt`, ...), with any extension.
pub fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or("").trim_end().to_ascii_lowercase();
    if RESERVED.contains(&stem.as_str()) {
        return true;
    }
    let b = stem.as_bytes();
    b.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) && b[3].is_ascii_digit()
}

/// One path component, portable to Linux, macOS and Windows. Returns the
/// reason it is rejected.
pub fn check_name_component(s: &str) -> Result<(), &'static str> {
    if s.is_empty() || s == "." || s == ".." {
        return Err("empty or traversal component");
    }
    if s.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0') || c.is_control() || is_format_char(c)) {
        return Err("illegal character");
    }
    if s.ends_with('.') || s.ends_with(' ') {
        return Err("trailing dot or space");
    }
    if is_reserved_device_name(s) {
        return Err("reserved device name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules() {
        for ok in ["orders.csv", "README.md", "a b.py", "données.csv", ".gitignore", "console.py"] {
            assert!(check_name_component(ok).is_ok(), "{ok}");
        }
        for bad in
            ["a.py:evil", "CON", "con.py", "LPT1.txt", "a.py.", "a.py ", "x\u{202e}gnp.py", "..", "a\\b"]
        {
            assert!(check_name_component(bad).is_err(), "{bad:?}");
        }
    }
}
