//! Per-app scoring over a rolling window. Pure logic, no syscalls, so the
//! whole thing is unit tested against synthetic event streams.

use std::collections::{HashMap, HashSet, VecDeque};

pub const CANARY: u32 = 100;
pub const HEADER_MISMATCH: u32 = 6;
pub const HIGH_ENTROPY: u32 = 5;
pub const NEW_SUFFIX: u32 = 4;
pub const NEW_SUFFIX_MIN_FILES: usize = 5;
pub const RANSOM_NOTE: u32 = 25;
pub const RANSOM_NOTE_MIN_DIRS: usize = 3;
pub const WRITE_THEN_DELETE: u32 = 3;
pub const MANY_WRITES: u32 = 10;
pub const MANY_WRITES_MIN: usize = 50;
pub const ENTROPY_LINE: f64 = 7.9;
pub const NEAR_MISS_FLOOR: u32 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppKey {
    pub cgroup: String,
    pub exe: String,
}

#[derive(Debug, Clone)]
pub enum Obs {
    /// A user-data file was closed after writing.
    Content {
        path: String,
        ext: String,
        /// From detect::header_matches.
        header_ok: Option<bool>,
        entropy: f64,
    },
    Created {
        dir: String,
        name: String,
    },
    Deleted {
        dir: String,
        name: String,
    },
    Renamed {
        old: String,
        new: String,
    },
    Canary {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Quiet,
    /// Score between NEAR_MISS_FLOOR and the threshold, reported once per window.
    NearMiss {
        score: u32,
    },
    Trip {
        score: u32,
    },
}

#[derive(Debug, Default)]
struct AppState {
    /// (time ms, points, label, path)
    hits: VecDeque<(u64, u32, &'static str, String)>,
    header_seen: HashSet<String>,
    entropy_seen: HashSet<String>,
    written: VecDeque<(u64, String)>,
    many_writes_fired_at: Option<u64>,
    suffix_files: HashMap<String, VecDeque<(u64, String)>>,
    suffix_fired: HashSet<String>,
    created_names: HashMap<String, VecDeque<(u64, String)>>,
    note_fired: HashSet<String>,
    /// (time, dir, stem) of files created in the window
    created_stems: VecDeque<(u64, String, String)>,
    near_miss_at: Option<u64>,
    tripped: bool,
    last_seen: u64,
}

impl AppState {
    fn add(&mut self, now: u64, pts: u32, label: &'static str, path: &str) {
        self.hits.push_back((now, pts, label, path.to_string()));
    }

    fn prune(&mut self, now: u64, window: u64) {
        let cut = now.saturating_sub(window);
        while self.hits.front().is_some_and(|h| h.0 < cut) {
            let (_, _, _, p) = self.hits.pop_front().unwrap_or_default();
            self.header_seen.remove(&p);
            self.entropy_seen.remove(&p);
        }
        while self.written.front().is_some_and(|w| w.0 < cut) {
            self.written.pop_front();
        }
        if self.many_writes_fired_at.is_some_and(|t| t < cut) {
            self.many_writes_fired_at = None;
        }
        for q in self.suffix_files.values_mut() {
            while q.front().is_some_and(|x| x.0 < cut) {
                q.pop_front();
            }
        }
        self.suffix_files.retain(|_, q| !q.is_empty());
        let live: HashSet<String> = self.suffix_files.keys().cloned().collect();
        self.suffix_fired.retain(|s| live.contains(s));
        for q in self.created_names.values_mut() {
            while q.front().is_some_and(|x| x.0 < cut) {
                q.pop_front();
            }
        }
        self.created_names.retain(|_, q| !q.is_empty());
        let live: HashSet<String> = self.created_names.keys().cloned().collect();
        self.note_fired.retain(|s| live.contains(s));
        while self.created_stems.front().is_some_and(|x| x.0 < cut) {
            self.created_stems.pop_front();
        }
        if self.near_miss_at.is_some_and(|t| t < cut) {
            self.near_miss_at = None;
        }
    }

    fn score(&self) -> u32 {
        self.hits.iter().map(|h| h.1).sum()
    }
}

fn stem(name: &str) -> &str {
    let base = name.rsplit('/').next().unwrap_or(name);
    match base.find('.') {
        Some(0) | None => base,
        Some(i) => &base[..i],
    }
}

fn split_path(p: &str) -> (&str, &str) {
    match p.rsplit_once('/') {
        Some((d, n)) => (if d.is_empty() { "/" } else { d }, n),
        None => ("", p),
    }
}

/// The suffix a rename added, if it only appended to the old name:
/// "a.docx" -> "a.docx.locked" gives "locked".
pub fn added_suffix(old: &str, new: &str) -> Option<String> {
    let (od, on) = split_path(old);
    let (nd, nn) = split_path(new);
    if od != nd || nn.len() <= on.len() || !nn.starts_with(on) {
        return None;
    }
    let tail = &nn[on.len()..];
    let tail = tail.strip_prefix('.')?;
    if tail.is_empty() || tail.len() > 32 || tail.contains('/') {
        return None;
    }
    Some(tail.to_ascii_lowercase())
}

pub struct Scorer {
    pub threshold: u32,
    pub window_ms: u64,
    apps: HashMap<AppKey, AppState>,
}

impl Scorer {
    pub fn new(threshold: u32, window_secs: u64) -> Scorer {
        Scorer {
            threshold,
            window_ms: window_secs * 1000,
            apps: HashMap::new(),
        }
    }

    pub fn observe(&mut self, key: &AppKey, now: u64, obs: Obs) -> Verdict {
        let window = self.window_ms;
        let st = self.apps.entry(key.clone()).or_default();
        st.last_seen = now;
        st.prune(now, window);
        if st.tripped {
            return Verdict::Quiet;
        }
        match obs {
            Obs::Canary { path } => st.add(now, CANARY, "canary file touched", &path),
            Obs::Content {
                path,
                ext,
                header_ok,
                entropy,
            } => {
                if !st.written.iter().any(|w| w.1 == path) {
                    st.written.push_back((now, path.clone()));
                }
                if header_ok == Some(false) && st.header_seen.insert(path.clone()) {
                    st.add(
                        now,
                        HEADER_MISMATCH,
                        "file header no longer matches its type",
                        &path,
                    );
                }
                if deadbolt_common::userdata::is_low_entropy(&ext)
                    && !deadbolt_common::userdata::is_compressed(&ext)
                    && entropy > ENTROPY_LINE
                    && st.entropy_seen.insert(path.clone())
                {
                    st.add(now, HIGH_ENTROPY, "high entropy in a text-like file", &path);
                }
                if st.written.len() > MANY_WRITES_MIN && st.many_writes_fired_at.is_none() {
                    st.many_writes_fired_at = Some(now);
                    st.add(now, MANY_WRITES, "more than 50 files written", &path);
                }
            }
            Obs::Renamed { old, new } => {
                if let Some(sfx) = added_suffix(&old, &new) {
                    let q = st.suffix_files.entry(sfx.clone()).or_default();
                    if !q.iter().any(|x| x.1 == new) {
                        q.push_back((now, new.clone()));
                    }
                    let files: Vec<String> = q.iter().map(|x| x.1.clone()).collect();
                    if files.len() >= NEW_SUFFIX_MIN_FILES {
                        if st.suffix_fired.insert(sfx) {
                            // Crossing the line counts every file seen so far.
                            for f in &files {
                                st.add(now, NEW_SUFFIX, "rename added the same new suffix", f);
                            }
                        } else {
                            st.add(now, NEW_SUFFIX, "rename added the same new suffix", &new);
                        }
                    }
                }
                let (dir, name) = split_path(&new);
                st.created_stems
                    .push_back((now, dir.to_string(), stem(name).to_string()));
            }
            Obs::Created { dir, name } => {
                let q = st.created_names.entry(name.clone()).or_default();
                if !q.iter().any(|x| x.1 == dir) {
                    q.push_back((now, dir.clone()));
                }
                if q.len() >= RANSOM_NOTE_MIN_DIRS && st.note_fired.insert(name.clone()) {
                    st.add(
                        now,
                        RANSOM_NOTE,
                        "same file created in many folders",
                        &format!("{dir}/{name}"),
                    );
                }
                st.created_stems
                    .push_back((now, dir, stem(&name).to_string()));
            }
            Obs::Deleted { dir, name } => {
                let s = stem(&name);
                let full = format!("{dir}/{name}");
                if let Some(pos) = st
                    .created_stems
                    .iter()
                    .position(|(_, d, cs)| *d == dir && cs == s)
                {
                    st.created_stems.remove(pos);
                    st.add(
                        now,
                        WRITE_THEN_DELETE,
                        "new file written, original deleted",
                        &full,
                    );
                }
            }
        }
        let score = st.score();
        if score >= self.threshold {
            st.tripped = true;
            Verdict::Trip { score }
        } else if score >= NEAR_MISS_FLOOR && st.near_miss_at.is_none() {
            st.near_miss_at = Some(now);
            Verdict::NearMiss { score }
        } else {
            Verdict::Quiet
        }
    }

    /// Distinct signal labels and the files involved, for the incident record.
    pub fn explain(&self, key: &AppKey) -> (Vec<String>, Vec<String>) {
        let Some(st) = self.apps.get(key) else {
            return (Vec::new(), Vec::new());
        };
        let mut labels = Vec::new();
        let mut files = Vec::new();
        for (_, pts, label, path) in &st.hits {
            let l = format!("{label} (+{pts})");
            if !labels.iter().any(|x: &String| x.starts_with(label)) {
                labels.push(l);
            }
            if !files.contains(path) {
                files.push(path.clone());
            }
        }
        for (_, p) in &st.written {
            if !files.contains(p) {
                files.push(p.clone());
            }
        }
        (labels, files)
    }

    /// Forget an app after a decision so it starts from zero.
    pub fn reset(&mut self, key: &AppKey) {
        self.apps.remove(key);
    }

    /// Drop apps idle for longer than the window.
    pub fn gc(&mut self, now: u64) {
        let w = self.window_ms;
        self.apps
            .retain(|_, s| s.tripped || now.saturating_sub(s.last_seen) <= w);
    }

    pub fn tracked(&self) -> usize {
        self.apps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AppKey {
        AppKey {
            cgroup: "/user.slice/app-evil.scope".into(),
            exe: "/home/u/evil".into(),
        }
    }

    #[test]
    fn canary_trips_instantly() {
        let mut s = Scorer::new(100, 20);
        let v = s.observe(
            &key(),
            0,
            Obs::Canary {
                path: "/home/u/Documents/0000.docx".into(),
            },
        );
        assert_eq!(v, Verdict::Trip { score: 100 });
    }

    #[test]
    fn mass_encrypt_trips_before_200_files() {
        let mut s = Scorer::new(100, 20);
        let k = key();
        let mut tripped_at = None;
        for i in 0..200u64 {
            let p = format!("/home/u/test/f{i}.txt");
            let v = s.observe(
                &k,
                i * 10,
                Obs::Content {
                    path: p.clone(),
                    ext: "txt".into(),
                    header_ok: None,
                    entropy: 7.99,
                },
            );
            if matches!(v, Verdict::Trip { .. }) {
                tripped_at = Some(i);
                break;
            }
            let v = s.observe(
                &k,
                i * 10 + 1,
                Obs::Renamed {
                    old: p.clone(),
                    new: format!("{p}.enc"),
                },
            );
            if matches!(v, Verdict::Trip { .. }) {
                tripped_at = Some(i);
                break;
            }
        }
        let at = tripped_at.expect("never tripped");
        assert!(at < 20, "tripped late at file {at}");
    }

    #[test]
    fn normal_editing_stays_quiet() {
        let mut s = Scorer::new(100, 20);
        let k = key();
        for i in 0..40u64 {
            let v = s.observe(
                &k,
                i * 100,
                Obs::Content {
                    path: format!("/home/u/src/file{i}.rs"),
                    ext: "rs".into(),
                    header_ok: None,
                    entropy: 4.5,
                },
            );
            assert_eq!(v, Verdict::Quiet);
        }
    }

    #[test]
    fn gzip_like_compression_is_quiet() {
        // gzip writes x.txt.gz then deletes x.txt. Few files: stays under the line.
        let mut s = Scorer::new(100, 20);
        let k = key();
        for i in 0..10u64 {
            s.observe(
                &k,
                i,
                Obs::Created {
                    dir: "/home/u/logs".into(),
                    name: format!("l{i}.txt.gz"),
                },
            );
            let v = s.observe(
                &k,
                i,
                Obs::Deleted {
                    dir: "/home/u/logs".into(),
                    name: format!("l{i}.txt"),
                },
            );
            assert!(!matches!(v, Verdict::Trip { .. }));
        }
    }

    #[test]
    fn ransom_note_counts_once() {
        let mut s = Scorer::new(100, 20);
        let k = key();
        for d in ["/a", "/b", "/c", "/d", "/e"] {
            s.observe(
                &k,
                0,
                Obs::Created {
                    dir: d.into(),
                    name: "HOW_TO_DECRYPT.txt".into(),
                },
            );
        }
        let (labels, _) = s.explain(&k);
        assert_eq!(labels.len(), 1);
        assert!(labels[0].contains("+25"));
    }

    #[test]
    fn window_expires() {
        let mut s = Scorer::new(100, 20);
        let k = key();
        for i in 0..9u64 {
            s.observe(
                &k,
                0,
                Obs::Content {
                    path: format!("/x/{i}.jpg"),
                    ext: "jpg".into(),
                    header_ok: Some(false),
                    entropy: 8.0,
                },
            );
        }
        // 54 points, a near miss. 30 s later everything has aged out.
        let v = s.observe(
            &k,
            30_000,
            Obs::Content {
                path: "/x/new.jpg".into(),
                ext: "jpg".into(),
                header_ok: Some(true),
                entropy: 8.0,
            },
        );
        assert_eq!(v, Verdict::Quiet);
    }

    #[test]
    fn near_miss_reported_once() {
        let mut s = Scorer::new(100, 20);
        let k = key();
        let mut misses = 0;
        for i in 0..12u64 {
            if let Verdict::NearMiss { .. } = s.observe(
                &k,
                i,
                Obs::Content {
                    path: format!("/x/{i}.png"),
                    ext: "png".into(),
                    header_ok: Some(false),
                    entropy: 8.0,
                },
            ) {
                misses += 1;
            }
        }
        assert_eq!(misses, 1);
    }

    #[test]
    fn suffix_detection() {
        assert_eq!(
            added_suffix("/a/b.docx", "/a/b.docx.locked").as_deref(),
            Some("locked")
        );
        assert_eq!(added_suffix("/a/b.docx", "/c/b.docx.locked"), None);
        assert_eq!(added_suffix("/a/b.docx", "/a/c.docx"), None);
    }
}
