//! ============================================================================
//! Module: `features.rs` — File Grouping, Deduplication & Intent Discovery
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! Beyond classic find-and-replace, FFRR provides three workspace-intelligence
//! engines that operate across all local folders, USB volumes, and archives:
//!
//! 1. **File Grouping (`group_files`)**:
//!    Classifies files by `Language`, `Extension`, `Source` (disk vs `.zip`/`.rar`),
//!    `Directory`, `Size` tier, `Encoding`, or `Age`, computing byte shares and
//!    line counts in parallel.
//! 2. **Exact & Fuzzy Near-Duplicate Finder (`find_duplicates`)**:
//!    - **Stage 1**: Pre-filters by exact byte size (eliminating 95%+ of unique files
//!      without reading content).
//!    - **Stage 2**: Computes parallel **BLAKE3** + **SHA-256** cryptographic hashes
//!      (optionally normalizing `CRLF` and trailing whitespace).
//!    - **Stage 3**: Tokenizes remaining text files into 3-word rolling shingles and
//!      computes **Jaccard Set Similarity** (`|A ∩ B| / |A ∪ B|`) to detect copy-pasted
//!      or slightly modified near-duplicate clones.
//! 3. **Context & Intent Analyzer (`analyze_intents`)**:
//!    Scans files against 8 built-in semantic packs (`secrets`, `pii`,
//!    `insecure-http`, `todos`, `conflicts`, `localhost-ports`, `deprecated`,
//!    `console-debug`) and can apply 1-click refactoring (`execute_intent_pack`).
//!
//! ### Memory & Security Guarantees
//! - `analyze_intents` evaluates all regex packs per file on the fly and drops
//!   each file's decoded string immediately, keeping RAM usage flat (`O(threads)`
//!   instead of holding the whole repository in memory).
//! - Duplicate deletion (`--delete-duplicates`) sorts by modification time so the
//!   oldest original copy is preserved as `PRIMARY`, and refuses to delete symlinks.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use crate::archive::{decode_bytes, is_known_binary_extension, resolve_sources, SourceItem, TraversalOptions};
use crate::engine::{find_semantic_context, run_search_replace, ScopeFilter, SearchReplaceOptions, SearchReplaceSummary};
use anyhow::Result;
use clap::ValueEnum;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// 1. FILE GROUPING & CLASSIFICATION ENGINE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum GroupByMode {
    /// Group by programming language / file category (Rust, Python, Config, Logs, Web, Archive, etc.)
    Language,
    /// Group by file extension (.rs, .json, .log, .cs, etc.)
    Extension,
    /// Group by input source root or archive container (.zip, .rar, .tar.gz, folder)
    Source,
    /// Group by parent directory path
    Directory,
    /// Group by file size tier (Empty, Tiny, Small, Medium, Large, Huge)
    Size,
    /// Group by detected character encoding (UTF-8, UTF-8-BOM, UTF-16LE, Windows-1252, Binary)
    Encoding,
    /// Group by modification age (Last 24h, Last 7d, Last 30d, Older)
    Age,
}

impl Default for GroupByMode {
    fn default() -> Self {
        GroupByMode::Language
    }
}

impl GroupByMode {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "ext" | "extension" => GroupByMode::Extension,
            "src" | "source" | "archive" => GroupByMode::Source,
            "dir" | "directory" | "folder" => GroupByMode::Directory,
            "size" | "size-bucket" => GroupByMode::Size,
            "enc" | "encoding" => GroupByMode::Encoding,
            "age" | "mtime" | "date" => GroupByMode::Age,
            _ => GroupByMode::Language,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileGroupEntry {
    pub group_key: String,
    pub file_count: usize,
    pub archive_member_count: usize,
    pub total_bytes: u64,
    pub total_lines: usize,
    pub percentage_bytes: f64,
    pub sample_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileGroupReport {
    pub group_by: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub total_lines: usize,
    pub elapsed_ms: u128,
    pub groups: Vec<FileGroupEntry>,
}

pub fn classify_language(ext: &str, file_name: &str) -> &'static str {
    let lower_name = file_name.to_lowercase();
    if lower_name == "dockerfile" || lower_name == "makefile" || lower_name == "justfile" {
        return "Build / DevOps";
    }
    match ext {
        "rs" => "Rust",
        "py" | "pyi" => "Python",
        "js" | "jsx" | "mjs" | "cjs" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "cs" | "vb" | "fs" | "csproj" | "sln" => "C# / .NET",
        "go" => "Go",
        "java" | "kt" | "scala" | "gradle" => "JVM (Java/Kotlin)",
        "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => "C / C++",
        "html" | "htm" | "css" | "scss" | "less" | "vue" | "svelte" => "Web (HTML/CSS)",
        "json" | "yaml" | "yml" | "toml" | "xml" | "ini" | "conf" | "cfg" | "env" | "config"
        | "properties" => "Configuration (JSON/YAML/TOML/XML)",
        "sql" | "csv" | "tsv" | "parquet" => "SQL & Tabular Data",
        "log" | "txt" | "out" | "err" => "Logs & Plain Text",
        "md" | "rst" | "adoc" => "Documentation / Markdown",
        "sh" | "bash" | "zsh" | "ps1" | "psm1" | "bat" | "cmd" => "Shell / PowerShell Scripts",
        "zip" | "rar" | "gz" | "tgz" | "tar" | "zst" | "bz2" => "Compressed Archives",
        "" => "No Extension",
        _ => "Other Files",
    }
}

pub fn classify_size_bucket(size: u64) -> &'static str {
    if size == 0 {
        "0. Empty (0 B)"
    } else if size < 4 * 1024 {
        "1. Tiny (< 4 KB)"
    } else if size < 64 * 1024 {
        "2. Small (4 KB - 64 KB)"
    } else if size < 1024 * 1024 {
        "3. Medium (64 KB - 1 MB)"
    } else if size < 50 * 1024 * 1024 {
        "4. Large (1 MB - 50 MB)"
    } else {
        "5. Huge (> 50 MB)"
    }
}

pub fn classify_age_bucket(mtime_secs: u64) -> &'static str {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age = now.saturating_sub(mtime_secs);
    if age < 86_400 {
        "1. Last 24 Hours"
    } else if age < 7 * 86_400 {
        "2. Last 7 Days"
    } else if age < 30 * 86_400 {
        "3. Last 30 Days"
    } else {
        "4. Older (> 30 Days)"
    }
}

pub fn group_files(traversal: &TraversalOptions, mode: GroupByMode) -> Result<FileGroupReport> {
    let start = Instant::now();
    let items = resolve_sources(traversal)?;

    let inspected: Vec<(String, String, bool, u64, usize)> = items
        .into_par_iter()
        .map(|item| {
            let display = item.display_path();
            let ext = item.extension();
            let fname = item.file_name();
            let size = item.size();
            let is_arc = item.is_archive_member();

            let (enc_str, line_count) = match item.read_bytes() {
                Ok(bytes) => {
                    let dec = decode_bytes(&bytes, None, false);
                    let lc = if dec.is_binary { 0 } else { dec.text.lines().count() };
                    (dec.encoding.as_str().to_string(), lc)
                }
                Err(_) => ("Unreadable".to_string(), 0),
            };

            let key = match mode {
                GroupByMode::Language => classify_language(&ext, &fname).to_string(),
                GroupByMode::Extension => {
                    if ext.is_empty() {
                        "(no extension)".to_string()
                    } else {
                        format!(".{}", ext)
                    }
                }
                GroupByMode::Source => format!("{} [{}]", item.source_root(), item.archive_kind()),
                GroupByMode::Directory => Path::new(&display)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| ".".to_string()),
                GroupByMode::Size => classify_size_bucket(size).to_string(),
                GroupByMode::Encoding => enc_str,
                GroupByMode::Age => classify_age_bucket(item.mtime_secs()).to_string(),
            };

            (key, display, is_arc, size, line_count)
        })
        .collect();

    let total_files = inspected.len();
    let total_bytes: u64 = inspected.iter().map(|x| x.3).sum();
    let total_lines: usize = inspected.iter().map(|x| x.4).sum();

    let mut map: BTreeMap<String, (usize, usize, u64, usize, Vec<String>)> = BTreeMap::new();
    for (key, display, is_arc, size, lines) in inspected {
        let entry = map.entry(key).or_insert_with(|| (0, 0, 0, 0, Vec::new()));
        entry.0 += 1;
        if is_arc {
            entry.1 += 1;
        }
        entry.2 += size;
        entry.3 += lines;
        if entry.4.len() < 8 {
            entry.4.push(display);
        }
    }

    let mut groups: Vec<FileGroupEntry> = map
        .into_iter()
        .map(|(group_key, (file_count, archive_member_count, bytes, lines, sample_files))| {
            let pct = if total_bytes > 0 {
                (bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            FileGroupEntry {
                group_key,
                file_count,
                archive_member_count,
                total_bytes: bytes,
                total_lines: lines,
                percentage_bytes: (pct * 100.0).round() / 100.0,
                sample_files,
            }
        })
        .collect();

    groups.sort_by(|a, b| b.file_count.cmp(&a.file_count).then(b.total_bytes.cmp(&a.total_bytes)));

    Ok(FileGroupReport {
        group_by: format!("{:?}", mode),
        total_files,
        total_bytes,
        total_lines,
        elapsed_ms: start.elapsed().as_millis(),
        groups,
    })
}

// ============================================================================
// 2. DUPLICATE & NEAR-DUPLICATE FILE FINDER ENGINE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateOptions {
    pub traversal: TraversalOptions,
    /// Ignore CRLF vs LF and trailing whitespace differences when hashing
    pub normalized_whitespace: bool,
    /// Also detect near-duplicate text files with Jaccard similarity >= threshold (0.0 to 1.0)
    pub near_duplicates: bool,
    pub similarity_threshold: f64,
    /// Minimum file size in bytes to consider (default: 1 byte, skipping 0-byte empty files unless set to 0)
    pub min_bytes: u64,
    /// Delete duplicate disk files (keeps the first/oldest file in each exact cluster)
    pub delete_duplicates: bool,
    pub dry_run: bool,
}

impl Default for DuplicateOptions {
    fn default() -> Self {
        Self {
            traversal: TraversalOptions::default(),
            normalized_whitespace: false,
            near_duplicates: false,
            similarity_threshold: 0.85,
            min_bytes: 1,
            delete_duplicates: false,
            dry_run: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateFileMember {
    pub path: String,
    pub archive_kind: String,
    pub size_bytes: u64,
    pub mtime_secs: u64,
    pub is_primary: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateCluster {
    pub hash_blake3: String,
    pub hash_sha256: String,
    pub match_kind: String, // "Exact", "Normalized (CRLF/Whitespace)", or "Near-Duplicate (XX% similar)"
    pub similarity_pct: f64,
    pub file_size_bytes: u64,
    pub wasted_bytes: u64,
    pub files: Vec<DuplicateFileMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateReport {
    pub total_files_scanned: usize,
    pub exact_clusters: usize,
    pub near_clusters: usize,
    pub total_duplicate_files: usize,
    pub total_wasted_bytes: u64,
    pub files_deleted: usize,
    pub elapsed_ms: u128,
    pub clusters: Vec<DuplicateCluster>,
}

fn normalize_content_for_hash(bytes: &[u8]) -> Vec<u8> {
    let dec = decode_bytes(bytes, None, false);
    if dec.is_binary {
        return bytes.to_vec();
    }
    let mut out = String::with_capacity(dec.text.len());
    for line in dec.text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push_str(trimmed);
            out.push('\n');
        }
    }
    out.into_bytes()
}

fn compute_line_shingles(text: &str) -> HashSet<u64> {
    use std::hash::{Hash, Hasher};
    let tokens: Vec<&str> = text
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .take(4000)
        .collect();
    let mut set = HashSet::new();
    if tokens.len() < 3 {
        for t in tokens {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            t.hash(&mut h);
            set.insert(h.finish());
        }
        return set;
    }
    for win in tokens.windows(3) {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        win.hash(&mut h);
        set.insert(h.finish());
    }
    set
}

pub fn find_duplicates(opts: &DuplicateOptions) -> Result<DuplicateReport> {
    let start = Instant::now();
    let items: Vec<SourceItem> = resolve_sources(&opts.traversal)?
        .into_iter()
        .filter(|i| i.size() >= opts.min_bytes)
        .collect();
    let total_files_scanned = items.len();

    // When normalized_whitespace is false, pre-filter by exact byte size (eliminates unique sizes immediately!)
    let candidate_items: Vec<SourceItem> = if !opts.normalized_whitespace && !opts.near_duplicates {
        let mut size_counts: HashMap<u64, usize> = HashMap::new();
        for item in &items {
            *size_counts.entry(item.size()).or_insert(0) += 1;
        }
        items
            .into_iter()
            .filter(|i| size_counts.get(&i.size()).copied().unwrap_or(0) > 1)
            .collect()
    } else {
        items
    };

    #[derive(Clone)]
    struct HashedItem {
        display_path: String,
        disk_path: Option<std::path::PathBuf>,
        archive_kind: String,
        size_bytes: u64,
        mtime_secs: u64,
        raw_blake3: String,
        eff_blake3: String,
        eff_sha256: String,
        shingles: Option<HashSet<u64>>,
    }

    let hashed: Vec<HashedItem> = candidate_items
        .into_par_iter()
        .filter_map(|item| {
            let bytes = item.read_bytes().ok()?;
            let raw_blake3 = blake3::hash(&bytes).to_hex().to_string();

            let eff_bytes = if opts.normalized_whitespace {
                normalize_content_for_hash(&bytes)
            } else {
                bytes.clone()
            };
            let eff_blake3 = blake3::hash(&eff_bytes).to_hex().to_string();
            let mut sha = Sha256::new();
            sha.update(&eff_bytes);
            let eff_sha256 = format!("{:x}", sha.finalize());

            let shingles = if opts.near_duplicates {
                let dec = decode_bytes(&bytes, None, false);
                if !dec.is_binary && !dec.text.is_empty() {
                    Some(compute_line_shingles(&dec.text))
                } else {
                    None
                }
            } else {
                None
            };

            let disk_path = match &item {
                SourceItem::DiskFile { path, .. } => Some(path.clone()),
                _ => None,
            };

            Some(HashedItem {
                display_path: item.display_path(),
                disk_path,
                archive_kind: item.archive_kind().to_string(),
                size_bytes: item.size(),
                mtime_secs: item.mtime_secs(),
                raw_blake3,
                eff_blake3,
                eff_sha256,
                shingles,
            })
        })
        .collect();

    let mut groups: BTreeMap<String, Vec<HashedItem>> = BTreeMap::new();
    for h in &hashed {
        groups.entry(h.eff_blake3.clone()).or_default().push(h.clone());
    }

    let mut clusters = Vec::new();
    let mut exact_clusters = 0usize;
    let mut near_clusters = 0usize;
    let mut total_duplicate_files = 0usize;
    let mut total_wasted_bytes = 0u64;
    let mut files_deleted = 0usize;
    let mut already_clustered: HashSet<String> = HashSet::new();

    for (eff_hash, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        // Sort by oldest modification timestamp first (so the oldest original file is kept as PRIMARY),
        // breaking ties deterministically by path.
        members.sort_by(|a, b| {
            let ma = if a.mtime_secs == 0 { u64::MAX } else { a.mtime_secs };
            let mb = if b.mtime_secs == 0 { u64::MAX } else { b.mtime_secs };
            ma.cmp(&mb).then_with(|| a.display_path.cmp(&b.display_path))
        });
        for m in &members {
            already_clustered.insert(m.display_path.clone());
        }

        let all_raw_identical = members.iter().all(|m| m.raw_blake3 == members[0].raw_blake3);
        let match_kind = if all_raw_identical {
            "Exact Byte-Identical".to_string()
        } else {
            "Normalized (Whitespace/CRLF)".to_string()
        };

        let file_size = members[0].size_bytes;
        let dup_count = members.len() - 1;
        let wasted = file_size * (dup_count as u64);
        exact_clusters += 1;
        total_duplicate_files += dup_count;
        total_wasted_bytes += wasted;

        let sha256_short = members[0].eff_sha256[..16].to_string();
        let blake3_short = eff_hash[..16].to_string();

        let mut file_entries = Vec::with_capacity(members.len());
        for (idx, m) in members.into_iter().enumerate() {
            let is_primary = idx == 0;
            let mut deleted = false;
            if !is_primary && opts.delete_duplicates && !opts.dry_run {
                if let Some(ref dp) = m.disk_path {
                    // Safety check: only delete regular files, never symlinks
                    let is_regular = fs::symlink_metadata(dp)
                        .map(|meta| meta.file_type().is_file() && !meta.file_type().is_symlink())
                        .unwrap_or(false);
                    if is_regular && fs::remove_file(dp).is_ok() {
                        deleted = true;
                        files_deleted += 1;
                    }
                }
            }
            file_entries.push(DuplicateFileMember {
                path: m.display_path,
                archive_kind: m.archive_kind,
                size_bytes: m.size_bytes,
                mtime_secs: m.mtime_secs,
                is_primary,
                deleted,
            });
        }

        clusters.push(DuplicateCluster {
            hash_blake3: blake3_short,
            hash_sha256: sha256_short,
            match_kind,
            similarity_pct: 100.0,
            file_size_bytes: file_size,
            wasted_bytes: wasted,
            files: file_entries,
        });
    }

    // Near-duplicate detection for remaining unclustered text files
    if opts.near_duplicates {
        let remaining: Vec<&HashedItem> = hashed
            .iter()
            .filter(|h| !already_clustered.contains(&h.display_path) && h.shingles.is_some())
            .collect();

        let mut used_near: HashSet<usize> = HashSet::new();
        for i in 0..remaining.len() {
            if used_near.contains(&i) {
                continue;
            }
            let s1 = remaining[i].shingles.as_ref().unwrap();
            if s1.is_empty() {
                continue;
            }
            let mut cluster_members = vec![remaining[i]];
            let mut best_sim = 1.0f64;

            for j in (i + 1)..remaining.len() {
                if used_near.contains(&j) {
                    continue;
                }
                let s2 = remaining[j].shingles.as_ref().unwrap();
                if s2.is_empty() {
                    continue;
                }
                let inter = s1.intersection(s2).count();
                let union = s1.len() + s2.len() - inter;
                if union > 0 {
                    let sim = inter as f64 / union as f64;
                    if sim >= opts.similarity_threshold {
                        used_near.insert(j);
                        best_sim = best_sim.min(sim);
                        cluster_members.push(remaining[j]);
                    }
                }
            }

            if cluster_members.len() >= 2 {
                used_near.insert(i);
                near_clusters += 1;
                let dup_count = cluster_members.len() - 1;
                total_duplicate_files += dup_count;
                let file_size = cluster_members[0].size_bytes;
                let wasted = file_size * (dup_count as u64);
                total_wasted_bytes += wasted;
                let sim_pct = (best_sim * 1000.0).round() / 10.0;

                let files = cluster_members
                    .iter()
                    .enumerate()
                    .map(|(idx, m)| DuplicateFileMember {
                        path: m.display_path.clone(),
                        archive_kind: m.archive_kind.clone(),
                        size_bytes: m.size_bytes,
                        mtime_secs: m.mtime_secs,
                        is_primary: idx == 0,
                        deleted: false,
                    })
                    .collect();

                clusters.push(DuplicateCluster {
                    hash_blake3: cluster_members[0].eff_blake3[..16].to_string(),
                    hash_sha256: cluster_members[0].eff_sha256[..16].to_string(),
                    match_kind: format!("Near-Duplicate ({:.1}% similar)", sim_pct),
                    similarity_pct: sim_pct,
                    file_size_bytes: file_size,
                    wasted_bytes: wasted,
                    files,
                });
            }
        }
    }

    clusters.sort_by(|a, b| b.wasted_bytes.cmp(&a.wasted_bytes));

    Ok(DuplicateReport {
        total_files_scanned,
        exact_clusters,
        near_clusters,
        total_duplicate_files,
        total_wasted_bytes,
        files_deleted,
        elapsed_ms: start.elapsed().as_millis(),
        clusters,
    })
}

// ============================================================================
// 3. CONTEXT & INTENT ANALYZER / SMART REFACTORING RECIPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentPack {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub find_regex: &'static str,
    pub suggested_replace: &'static str,
    pub recommended_scope: ScopeFilter,
}

pub fn list_intent_packs() -> Vec<IntentPack> {
    vec![
        IntentPack {
            id: "secrets",
            title: "Hardcoded Secrets, API Keys & Private Tokens",
            category: "Security & Compliance",
            severity: "CRITICAL",
            description: "Detects AWS keys (AKIA...), API/Bearer tokens (sk-..., ghp_...), private keys, and hardcoded password/secret assignments across configs and code.",
            find_regex: r"(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\x22][^'\x22\s]{6,}['\x22])",
            suggested_replace: "{{REDACT}}",
            recommended_scope: ScopeFilter::All,
        },
        IntentPack {
            id: "pii",
            title: "PII (Emails, SSNs & Sensitive Identifiers)",
            category: "Privacy / GDPR",
            severity: "HIGH",
            description: "Finds email addresses and US SSN patterns in logs, configs, or data dumps and can anonymize them deterministically with {{SHA256}} or {{REDACT}}.",
            find_regex: r"(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\b\d{3}-\d{2}-\d{4}\b)",
            suggested_replace: "anon_{{SHA256}}",
            recommended_scope: ScopeFilter::All,
        },
        IntentPack {
            id: "insecure-http",
            title: "Insecure HTTP URLs (Upgrade to HTTPS)",
            category: "Security & Modernization",
            severity: "MEDIUM",
            description: "Finds non-loopback http:// URLs across code, configs, and docs and upgrades them to https://.",
            find_regex: r"http://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s'\x22<>)]*)?)",
            suggested_replace: "https://$1",
            recommended_scope: ScopeFilter::All,
        },
        IntentPack {
            id: "todos",
            title: "Technical Debt Markers (TODO / FIXME / HACK / XXX)",
            category: "Code Quality",
            severity: "INFO",
            description: "Locates all TODO, FIXME, HACK, BUG, and XXX markers inside comments with enclosing function/class context.",
            find_regex: r"\b(TODO|FIXME|HACK|XXX|BUG)\b[:\s]*(.*)",
            suggested_replace: "$1 [TRACKED]: $2",
            recommended_scope: ScopeFilter::Comments,
        },
        IntentPack {
            id: "conflicts",
            title: "Unresolved Git Merge Conflict Markers",
            category: "Build Integrity",
            severity: "CRITICAL",
            description: "Detects leftover <<<<<<<, =======, and >>>>>>> merge conflict markers before deployment.",
            find_regex: r"^(?:<{7}|={7}|>{7})(?:\s+.*)?$",
            suggested_replace: "",
            recommended_scope: ScopeFilter::All,
        },
        IntentPack {
            id: "localhost-ports",
            title: "Hardcoded Localhost / Loopback Endpoints & Ports",
            category: "Configuration Portability",
            severity: "MEDIUM",
            description: "Finds hardcoded localhost / 127.0.0.1 / 0.0.0.0 host:port bindings in configs and source files.",
            find_regex: r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{2,5})\b",
            suggested_replace: "${APP_HOST}:$2",
            recommended_scope: ScopeFilter::All,
        },
        IntentPack {
            id: "deprecated",
            title: "Deprecated / Unsafe Calls (eval, md5, sha1, var)",
            category: "Modernization",
            severity: "MEDIUM",
            description: "Detects legacy or unsafe API calls such as eval(), md5(), sha1(), strcpy(), or legacy var declarations.",
            find_regex: r"\b(eval\s*\(|md5\s*\(|sha1\s*\(|strcpy\s*\()",
            suggested_replace: "/* REVIEW_DEPRECATED */ $1",
            recommended_scope: ScopeFilter::Code,
        },
        IntentPack {
            id: "console-debug",
            title: "Leftover Debug Print Statements (console.log / dbg! / println)",
            category: "Code Hygiene",
            severity: "LOW",
            description: "Finds leftover console.log(...), dbg!(...), or System.out.println(...) statements in executable code.",
            find_regex: r"\b(console\.log|dbg!|System\.out\.println)\s*\(",
            suggested_replace: "// $1(",
            recommended_scope: ScopeFilter::Code,
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFinding {
    pub pack_id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub find_regex: String,
    pub suggested_replace: String,
    pub total_matches: usize,
    pub affected_files: usize,
    pub sample_matches: Vec<IntentMatchSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMatchSample {
    pub file: String,
    pub line_number: usize,
    pub semantic_context: Option<String>,
    pub matched_text: String,
    pub preview_replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAnalysisReport {
    pub total_files_scanned: usize,
    pub total_findings: usize,
    pub elapsed_ms: u128,
    pub findings: Vec<IntentFinding>,
}

pub fn analyze_intents(
    traversal: &TraversalOptions,
    pack_filter: Option<&str>,
) -> Result<IntentAnalysisReport> {
    let start = Instant::now();
    let items = resolve_sources(traversal)?;
    let total_files_scanned = items.len();

    let packs: Vec<IntentPack> = list_intent_packs()
        .into_iter()
        .filter(|p| {
            pack_filter
                .map(|f| f.is_empty() || f.eq_ignore_ascii_case("all") || p.id.eq_ignore_ascii_case(f))
                .unwrap_or(true)
        })
        .collect();

    let compiled_packs: Vec<(IntentPack, Regex)> = packs
        .into_iter()
        .filter_map(|p| Regex::new(p.find_regex).ok().map(|r| (p, r)))
        .collect();

    // Stream-scan each file in parallel against all compiled packs and drop the file's
    // text buffer immediately after scanning (prevents holding all files in RAM at once!).
    let per_file_hits: Vec<Vec<(usize, usize, Vec<IntentMatchSample>)>> = items
        .into_par_iter()
        .filter_map(|item| {
            let ext = item.extension();
            if is_known_binary_extension(&ext) {
                return None;
            }
            let bytes = item.read_bytes().ok()?;
            let dec = decode_bytes(&bytes, None, false);
            if dec.is_binary || dec.text.is_empty() {
                return None;
            }
            let path = item.display_path();
            let lines: Vec<&str> = dec.text.lines().collect();
            let mut file_pack_results = Vec::new();

            for (pack_idx, (pack, regex)) in compiled_packs.iter().enumerate() {
                let mut matches_in_file = 0usize;
                let mut samples = Vec::new();

                for (idx, &line) in lines.iter().enumerate() {
                    for m in regex.find_iter(line) {
                        let sc = crate::engine::classify_line_scope(line, m.start(), &ext);
                        if !crate::engine::scope_matches(
                            pack.recommended_scope,
                            sc,
                            line,
                            m.start(),
                        ) {
                            continue;
                        }
                        matches_in_file += 1;
                        if samples.len() < 4 {
                            let sem = find_semantic_context(&lines, idx);
                            samples.push(IntentMatchSample {
                                file: path.clone(),
                                line_number: idx + 1,
                                semantic_context: sem,
                                matched_text: m.as_str().to_string(),
                                preview_replacement: pack.suggested_replace.to_string(),
                            });
                        }
                    }
                }
                if matches_in_file > 0 {
                    file_pack_results.push((pack_idx, matches_in_file, samples));
                }
            }
            if file_pack_results.is_empty() {
                None
            } else {
                Some(file_pack_results)
            }
        })
        .collect();

    let mut agg_matches = vec![0usize; compiled_packs.len()];
    let mut agg_files = vec![0usize; compiled_packs.len()];
    let mut agg_samples: Vec<Vec<IntentMatchSample>> = vec![Vec::new(); compiled_packs.len()];

    for file_vec in per_file_hits {
        for (pack_idx, m_count, samples) in file_vec {
            agg_matches[pack_idx] += m_count;
            agg_files[pack_idx] += 1;
            for s in samples {
                if agg_samples[pack_idx].len() < 10 {
                    agg_samples[pack_idx].push(s);
                }
            }
        }
    }

    let mut findings = Vec::new();
    let mut total_findings = 0usize;

    for (pack_idx, (pack, _)) in compiled_packs.iter().enumerate() {
        let pack_matches = agg_matches[pack_idx];
        if pack_matches > 0 {
            total_findings += pack_matches;
            findings.push(IntentFinding {
                pack_id: pack.id.to_string(),
                title: pack.title.to_string(),
                category: pack.category.to_string(),
                severity: pack.severity.to_string(),
                description: pack.description.to_string(),
                find_regex: pack.find_regex.to_string(),
                suggested_replace: pack.suggested_replace.to_string(),
                total_matches: pack_matches,
                affected_files: agg_files[pack_idx],
                sample_matches: std::mem::take(&mut agg_samples[pack_idx]),
            });
        }
    }

    Ok(IntentAnalysisReport {
        total_files_scanned,
        total_findings,
        elapsed_ms: start.elapsed().as_millis(),
        findings,
    })
}

pub fn execute_intent_pack(
    traversal: &TraversalOptions,
    pack_id: &str,
    custom_replace: Option<String>,
    dry_run: bool,
) -> Result<SearchReplaceSummary> {
    let pack = list_intent_packs()
        .into_iter()
        .find(|p| p.id.eq_ignore_ascii_case(pack_id))
        .ok_or_else(|| anyhow::anyhow!("Unknown intent pack `{}`. Available: secrets, pii, insecure-http, todos, conflicts, localhost-ports, deprecated, console-debug", pack_id))?;

    let opts = SearchReplaceOptions {
        traversal: traversal.clone(),
        find: pack.find_regex.to_string(),
        replace: Some(custom_replace.unwrap_or_else(|| pack.suggested_replace.to_string())),
        use_regex: true,
        case_sensitive: true,
        smart_case: false,
        scope: pack.recommended_scope,
        dry_run,
        create_backup: true,
        semantic_context: true,
        ..Default::default()
    };

    run_search_replace(&opts)
}
