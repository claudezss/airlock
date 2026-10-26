//! Markdown is shared as raw bytes. Rendering (with HTML disabled and the
//! output sanitized) is the viewer's job; the core only checks it is text.

use crate::{Error, Result};

pub fn validate_markdown(b: &[u8]) -> Result<&str> {
    let s = std::str::from_utf8(b).map_err(|_| Error::invalid("markdown", "not utf-8"))?;
    if s.contains('\0') {
        return Err(Error::invalid("markdown", "contains NUL"));
    }
    Ok(s)
}
