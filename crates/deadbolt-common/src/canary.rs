//! Decoy files for the ransomware shield. Reading them is fine; writing,
//! renaming or deleting them trips the shield at once.

pub const DOCX: &[u8] = include_bytes!("../../../data/canary/canary.docx");
pub const XLSX: &[u8] = include_bytes!("../../../data/canary/canary.xlsx");
pub const JPG: &[u8] = include_bytes!("../../../data/canary/canary.jpg");
pub const PDF: &[u8] = include_bytes!("../../../data/canary/canary.pdf");

/// Named to sort first and last in a folder, so a ransomware walk in either
/// direction hits one early.
pub const FILES: &[(&str, &[u8])] = &[
    ("0000-household-records.docx", DOCX),
    ("0000-budget.xlsx", XLSX),
    ("zzzz-scan-0001.jpg", JPG),
    ("zzzz-tax-return.pdf", PDF),
];

/// XDG keys and their English fallbacks.
pub const XDG: &[(&str, &str)] = &[
    ("XDG_DOCUMENTS_DIR", "Documents"),
    ("XDG_PICTURES_DIR", "Pictures"),
    ("XDG_DESKTOP_DIR", "Desktop"),
    ("XDG_MUSIC_DIR", "Music"),
    ("XDG_VIDEOS_DIR", "Videos"),
    ("XDG_DOWNLOAD_DIR", "Downloads"),
];

/// Resolve the six folders from ~/.config/user-dirs.dirs, falling back to
/// English names. Only folders inside the home directory are returned.
pub fn xdg_folders(home: &str, user_dirs: Option<&str>) -> Vec<String> {
    XDG.iter()
        .map(|(key, fallback)| {
            let from_file = user_dirs.and_then(|t| {
                t.lines().find_map(|l| {
                    let v = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
                    let v = v.trim().trim_matches('"');
                    let v = v.replace("$HOME", home);
                    Some(v)
                })
            });
            from_file.unwrap_or_else(|| format!("{home}/{fallback}"))
        })
        .filter(|p| p.starts_with(&format!("{home}/")) && !p.contains("/../"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_parsing() {
        let t = "XDG_DOCUMENTS_DIR=\"$HOME/Dokumente\"\nXDG_DESKTOP_DIR=\"$HOME/\"\n";
        let f = xdg_folders("/home/z", Some(t));
        assert_eq!(f[0], "/home/z/Dokumente");
        assert!(f.contains(&"/home/z/Pictures".to_string()));
        // "$HOME/" is the home itself, which is fine as a folder.
        assert!(f.contains(&"/home/z/".to_string()));
        assert_eq!(f.len(), 6);
    }

    #[test]
    fn templates_look_real() {
        assert!(DOCX.starts_with(b"PK"));
        assert!(XLSX.starts_with(b"PK"));
        assert!(JPG.starts_with(&[0xFF, 0xD8, 0xFF]));
        assert!(PDF.starts_with(b"%PDF"));
    }
}
