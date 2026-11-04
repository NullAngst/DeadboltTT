//! Which file extensions count as user data for the ransomware shield.

use std::collections::HashSet;

/// Shipped list, also installed to /usr/share/deadbolt/user-data-extensions.txt.
pub const BUILTIN: &str = include_str!("../../../data/user-data-extensions.txt");

/// Types that are compressed by nature. Entropy never counts for these.
pub const COMPRESSED: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "mp4", "mkv", "webm", "mov",
    "avi", "m4v", "mp3", "m4a", "aac", "ogg", "opus", "flac", "zip", "gz", "tgz", "xz", "zst",
    "bz2", "7z", "rar", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "pdf", "jar", "apk",
    "cr2", "nef", "arw", "dng", "raf", "orf", "tif", "tiff", "psd", "kra", "xcf", "wma", "wmv",
];

/// Normally low-entropy types where high entropy is a strong signal.
pub const LOW_ENTROPY: &[&str] = &[
    "txt", "csv", "tsv", "svg", "md", "rst", "json", "xml", "html", "htm", "css", "js", "ts", "py",
    "rs", "go", "c", "h", "cpp", "hpp", "cc", "java", "kt", "rb", "php", "sh", "bash", "pl", "lua",
    "sql", "yaml", "yml", "toml", "ini", "conf", "cfg", "log", "tex", "bib", "vue", "tsx", "jsx",
    "swift", "cs", "scala", "r", "m", "org", "srt", "vtt", "eml", "ics", "vcf",
];

#[derive(Debug, Clone)]
pub struct UserData {
    exts: HashSet<String>,
}

impl UserData {
    pub fn parse(text: &str) -> UserData {
        let exts = text
            .lines()
            .map(|l| {
                l.split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .filter(|l| !l.is_empty())
            .map(|l| l.trim_start_matches('.').to_string())
            .collect();
        UserData { exts }
    }

    pub fn builtin() -> UserData {
        UserData::parse(BUILTIN)
    }

    pub fn load_or_builtin(path: &str) -> UserData {
        match std::fs::read_to_string(path) {
            Ok(t) if t.len() < 1 << 20 => UserData::parse(&t),
            _ => UserData::builtin(),
        }
    }

    pub fn contains(&self, ext: &str) -> bool {
        self.exts.contains(&ext.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.exts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exts.is_empty()
    }
}

pub fn extension(name: &str) -> Option<String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 16 {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

pub fn is_compressed(ext: &str) -> bool {
    COMPRESSED.contains(&ext)
}

pub fn is_low_entropy(ext: &str) -> bool {
    LOW_ENTROPY.contains(&ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_is_about_150() {
        let u = UserData::builtin();
        assert!(u.len() >= 140 && u.len() <= 200, "got {}", u.len());
        assert!(u.contains("docx"));
        assert!(u.contains("JPG"));
        assert!(!u.contains("o"));
    }

    #[test]
    fn ext_parsing() {
        assert_eq!(extension("/a/b/photo.JPG").as_deref(), Some("jpg"));
        assert_eq!(extension("/a/.bashrc"), None);
        assert_eq!(extension("noext"), None);
    }
}
