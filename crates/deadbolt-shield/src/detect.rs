//! Content checks on the three 4 KB samples: header versus extension, and entropy.

/// Shannon entropy in bits per byte.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Which `infer` types are acceptable for a given extension. Extensions not
/// listed have no reliable magic and are never judged by header.
fn accepted(ext: &str) -> Option<&'static [&'static str]> {
    const ZIP: &[&str] = &[
        "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "jar", "apk",
    ];
    Some(match ext {
        "jpg" | "jpeg" => &["jpg"],
        "png" => &["png", "apng"],
        "gif" => &["gif"],
        "bmp" => &["bmp"],
        "webp" => &["webp"],
        "tif" | "tiff" => &["tif"],
        "psd" => &["psd"],
        "pdf" => &["pdf"],
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "zip" | "jar" | "apk" => ZIP,
        "gz" | "tgz" => &["gz"],
        "xz" => &["xz"],
        "bz2" => &["bz2"],
        "7z" => &["7z"],
        "zst" => &["zst"],
        "rar" => &["rar"],
        "flac" => &["flac"],
        "ogg" | "opus" => &["ogg", "oga", "opus", "ogx"],
        "wav" => &["wav"],
        "mp4" | "m4v" | "mov" => &["mp4", "m4v", "mov", "heic", "avif"],
        "m4a" => &["m4a", "mp4"],
        "mkv" | "webm" => &["mkv", "webm"],
        "sqlite" | "sqlite3" | "db" => &["sqlite"],
        "doc" | "xls" | "ppt" | "msg" => &["doc", "xls", "ppt", "msi"],
        "elf" => &["elf"],
        _ => return None,
    })
}

/// Some(false) when the file has a known type and its header does not match.
/// None when the extension has no magic we trust, or the file is empty.
pub fn header_matches(ext: &str, head: &[u8]) -> Option<bool> {
    let want = accepted(ext)?;
    if head.is_empty() {
        return None;
    }
    // `.db` is used by many formats. Only judge it when it claims to be SQLite-ish.
    if ext == "db" && !head.starts_with(b"SQLite") {
        return None;
    }
    // Zip-based office files: "PK" is enough, infer may not see the inner type in 4 KB.
    if want.contains(&"zip") {
        return Some(head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06"));
    }
    match infer::get(head) {
        Some(kind) => Some(want.contains(&kind.extension())),
        None => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert!(entropy(&[b'a'; 4096]) < 0.01);
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((entropy(&all) - 8.0).abs() < 0.001);
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(80);
        assert!(entropy(&text) < 5.0);
    }

    #[test]
    fn jpeg_header() {
        assert_eq!(
            header_matches("jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]),
            Some(true)
        );
        assert_eq!(
            header_matches("jpg", &[0x12, 0x34, 0x56, 0x78]),
            Some(false)
        );
    }

    #[test]
    fn docx_must_be_zip() {
        assert_eq!(header_matches("docx", b"PK\x03\x04rest"), Some(true));
        assert_eq!(header_matches("docx", b"\x8a\x91random"), Some(false));
    }

    #[test]
    fn unknown_ext_not_judged() {
        assert_eq!(header_matches("txt", b"anything"), None);
        assert_eq!(header_matches("jpg", b""), None);
    }
}
