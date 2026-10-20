//! ============================================================================
//! Module: `engine.rs` — Multi-Threaded Find, Replace, Refactor & Undo Engine
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! This module is the core pattern-matching and text-transformation engine of
//! FFRR. If you are coming from C#, Java, Python, or JavaScript:
//! - Think of `SearchReplaceOptions` as the configuration DTO passed from the
//!   CLI, TUI, Web Studio REST API, or AI MCP server.
//! - Think of `run_search_replace()` as a parallel MapReduce pipeline powered by
//!   Rust's `rayon` work-stealing thread pool (`Parallel.ForEach` in C# /
//!   `parallelStream()` in Java, but with compile-time data-race safety).
//!
//! ### Key Innovations Over Classic `fnr.exe` / `sed` / `grep`
//! 1. **Smart Case-Preserving Replace (`apply_preserve_case`)**:
//!    Automatically detects whether a matched identifier is `snake_case`,
//!    `SCREAMING_SNAKE_CASE`, `PascalCase`, `camelCase`, or `kebab-case`, and
//!    transforms the replacement token to match that exact naming convention.
//! 2. **Lexical Scope Filtering (`classify_line_scope`)**:
//!    Classifies every match into `code`, `comments`, `strings`, `keys`, or
//!    `values` so you can refactor executable code without accidentally breaking
//!    comments or quoted strings (or vice versa).
//! 3. **Enclosing Semantic Context (`find_semantic_context`)**:
//!    Scans upward from each match to report the enclosing `fn`, `struct`,
//!    `class`, `def`, `[section]`, or `# Heading`.
//! 4. **Dynamic & User-Defined Macros (`expand_replacement_macros`)**:
//!    Expands `{{UPPER}}`, `{{SNAKE}}`, `{{SHA256}}`, `{{REDACT}}`, `{{DATE}}`,
//!    `{{FILE}}`, `{{LINE}}`, `{{ENV:VAR}}`, plus custom macros stored in
//!    `ffrr.macros.json`.
//! 5. **Transactional Backup & Undo (`TransactionManager`)**:
//!    Snapshots original file bytes into `.ffrr_backups/<tx_id>/` before any
//!    live replacement so `ffrr undo` can atomically restore modified files.
//!
//! ### Memory & Security Guarantees
//! - Compiled regexes are bounded by `size_limit(10 MB)` and `dfa_size_limit(10 MB)`
//!   to prevent Regular Expression Denial of Service (ReDoS).
//! - String truncation uses character iterators (`chars().take(72)`) and
//!   `is_char_boundary()` so multi-byte UTF-8 characters never panic.
//! - Raw file buffers are dropped immediately on each worker thread during
//!   search and dry-run previews so RAM usage stays flat regardless of repo size.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use crate::archive::{
    decode_bytes, encode_text, finish_progress_job, get_live_results_json, is_known_binary_extension,
    is_progress_cancelled, is_remote_source_uri, push_live_result_json, record_scanned_file,
    resolve_sources, set_active_find_hint, set_progress_phase, start_progress_job,
    write_item_bytes, write_remote_uri_bytes, FileEncoding, SourceItem, TraversalOptions,
};
use anyhow::{Context, Result};
use base64::Engine as _;
use clap::ValueEnum;
use rayon::prelude::*;
use regex::{Captures, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ScopeFilter {
    /// Match anywhere in the file (default)
    All,
    /// Match only in executable code (skip comments and string literals)
    Code,
    /// Match only inside comments (//, #, --, /* */, <!-- -->)
    Comments,
    /// Match only inside quoted string literals ("...", '...', `...`)
    Strings,
    /// Match only configuration keys (left of = or : in JSON/YAML/TOML/INI/.env)
    Keys,
    /// Match only configuration values (right of = or : in JSON/YAML/TOML/INI/.env)
    Values,
}

impl Default for ScopeFilter {
    fn default() -> Self {
        ScopeFilter::All
    }
}

impl ScopeFilter {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "code" => ScopeFilter::Code,
            "comment" | "comments" => ScopeFilter::Comments,
            "string" | "strings" | "literal" | "literals" => ScopeFilter::Strings,
            "key" | "keys" | "config-keys" => ScopeFilter::Keys,
            "val" | "value" | "values" | "config-values" => ScopeFilter::Values,
            _ => ScopeFilter::All,
        }
    }
}

fn default_search_target() -> String {
    "both".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchReplaceOptions {
    pub traversal: TraversalOptions,
    pub find: String,
    pub replace: Option<String>,
    #[serde(default = "default_search_target")]
    pub search_target: String, // "both", "filename", or "content"
    pub use_regex: bool,
    pub case_sensitive: bool,
    pub smart_case: bool,
    pub whole_word: bool,
    pub multiline: bool,
    pub use_escape_chars: bool,
    pub preserve_case: bool,
    pub invert_match: bool,
    pub ignore_binary: bool,
    pub forced_encoding: Option<String>,
    pub always_use_encoding: bool,
    pub show_encoding: bool,
    pub keep_mtime: bool,
    pub dry_run: bool,
    pub create_backup: bool,
    pub context_before: usize,
    pub context_after: usize,
    pub semantic_context: bool,
    pub scope: ScopeFilter,
    pub max_matches_per_file: Option<usize>,
}

impl Default for SearchReplaceOptions {
    fn default() -> Self {
        Self {
            traversal: TraversalOptions::default(),
            find: String::new(),
            replace: None,
            search_target: "both".to_string(),
            use_regex: false,
            case_sensitive: false,
            smart_case: true,
            whole_word: false,
            multiline: false,
            use_escape_chars: false,
            preserve_case: false,
            invert_match: false,
            ignore_binary: true,
            forced_encoding: None,
            always_use_encoding: false,
            show_encoding: true,
            keep_mtime: false,
            dry_run: false,
            create_backup: true,
            context_before: 0,
            context_after: 0,
            semantic_context: true,
            scope: ScopeFilter::All,
            max_matches_per_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextLine {
    pub line_number: usize,
    pub line_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSpan {
    pub start_col: usize,
    pub end_col: usize,
    pub matched_text: String,
    pub replaced_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineMatch {
    pub line_number: usize,
    pub column: usize,
    pub line_text: String,
    pub replaced_line_text: Option<String>,
    pub semantic_context: Option<String>,
    pub scope_kind: String,
    pub spans: Vec<MatchSpan>,
    pub context_before: Vec<ContextLine>,
    pub context_after: Vec<ContextLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSearchResult {
    pub path: String,
    pub file_name: String,
    pub extension: String,
    pub archive_kind: String,
    pub source_root: String,
    pub size_bytes: u64,
    pub encoding: String,
    pub is_binary: bool,
    pub match_count: usize,
    pub replaced_count: usize,
    pub modified_on_disk: bool,
    pub unified_diff: Option<String>,
    pub matches: Vec<LineMatch>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchReplaceSummary {
    pub total_files_scanned: usize,
    pub files_with_matches: usize,
    pub files_modified: usize,
    pub binary_files_skipped: usize,
    pub archive_entries_scanned: usize,
    pub total_matches: usize,
    pub total_replacements: usize,
    pub elapsed_ms: u128,
    pub dry_run: bool,
    pub transaction_id: Option<String>,
    pub cli_equivalents: CliEquivalents,
    pub results: Vec<FileSearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliEquivalents {
    pub ffrr_cmd: String,
    pub fnr_exe_cmd: String,
    pub unix_cmd: String,
    pub powershell_cmd: String,
}

pub fn unescape_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek().copied() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                }
                Some('r') => {
                    chars.next();
                    out.push('\r');
                }
                Some('t') => {
                    chars.next();
                    out.push('\t');
                }
                Some('0') => {
                    chars.next();
                    out.push('\0');
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                Some('x') => {
                    chars.next();
                    let h1 = chars.next();
                    let h2 = chars.next();
                    if let (Some(a), Some(b)) = (h1, h2) {
                        let hex = format!("{}{}", a, b);
                        if let Ok(code) = u8::from_str_radix(&hex, 16) {
                            out.push(code as char);
                            continue;
                        }
                    }
                    out.push_str("\\x");
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn build_search_regex(opts: &SearchReplaceOptions) -> Result<Regex> {
    let raw_find = if opts.use_escape_chars {
        unescape_string(&opts.find)
    } else {
        opts.find.clone()
    };

    let base_pat = if opts.use_regex {
        raw_find
    } else if opts.preserve_case {
        let words = split_identifier_words(&raw_find);
        if words.len() > 1 {
            words
                .iter()
                .map(|w| regex::escape(w))
                .collect::<Vec<_>>()
                .join(r"[_-]?")
        } else {
            regex::escape(&raw_find)
        }
    } else {
        regex::escape(&raw_find)
    };

    let pat = if opts.whole_word {
        format!(r"\b(?:{})\b", base_pat)
    } else {
        base_pat
    };

    let effective_case_sensitive = if opts.case_sensitive {
        true
    } else if opts.smart_case {
        opts.find.chars().any(|c| c.is_uppercase())
    } else {
        false
    };

    RegexBuilder::new(&pat)
        .case_insensitive(!effective_case_sensitive)
        .multi_line(true)
        .dot_matches_new_line(opts.multiline)
        .size_limit(10 * 1024 * 1024)
        .dfa_size_limit(10 * 1024 * 1024)
        .build()
        .with_context(|| format!("Invalid search pattern `{}`", opts.find))
}

/// Apply smart case-preservation from `matched` onto `replacement`
pub fn apply_preserve_case(matched: &str, replacement: &str) -> String {
    let alpha_chars: Vec<char> = matched.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha_chars.is_empty() {
        return replacement.to_string();
    }

    if alpha_chars.iter().all(|c| c.is_uppercase()) {
        return replacement.to_uppercase();
    }
    if alpha_chars.iter().all(|c| c.is_lowercase()) {
        return replacement.to_lowercase();
    }

    // Check TitleCase / PascalCase vs camelCase
    let words_matched = split_identifier_words(matched);
    let words_repl = split_identifier_words(replacement);

    if words_matched.len() > 1 && words_repl.len() > 1 {
        let has_underscore = matched.contains('_');
        let has_hyphen = matched.contains('-');
        let first_upper = alpha_chars[0].is_uppercase();

        if has_underscore {
            let transformed: Vec<String> = words_repl
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    if words_matched
                        .get(i)
                        .and_then(|mw| mw.chars().next())
                        .map(|c| c.is_uppercase())
                        .unwrap_or(first_upper)
                    {
                        capitalize_word(w)
                    } else {
                        w.to_lowercase()
                    }
                })
                .collect();
            return transformed.join("_");
        }
        if has_hyphen {
            let transformed: Vec<String> = words_repl
                .iter()
                .map(|w| {
                    if first_upper {
                        capitalize_word(w)
                    } else {
                        w.to_lowercase()
                    }
                })
                .collect();
            return transformed.join("-");
        }

        // camelCase or PascalCase
        let mut out = String::new();
        for (i, w) in words_repl.iter().enumerate() {
            if i == 0 && !first_upper {
                out.push_str(&w.to_lowercase());
            } else {
                out.push_str(&capitalize_word(w));
            }
        }
        return out;
    }

    if alpha_chars[0].is_uppercase() && alpha_chars[1..].iter().all(|c| c.is_lowercase()) {
        return capitalize_word(replacement);
    }

    replacement.to_string()
}

fn split_identifier_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c == '_' || c == '-' || c.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else if c.is_uppercase() && !current.is_empty() && current.chars().last().map(|p| p.is_lowercase()).unwrap_or(false) {
            words.push(std::mem::take(&mut current));
            current.push(c);
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn capitalize_word(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        Some(first) => {
            let mut s = first.to_uppercase().to_string();
            s.push_str(&chars.as_str().to_lowercase());
            s
        }
        None => String::new(),
    }
}

fn to_snake_case(s: &str) -> String {
    split_identifier_words(s)
        .into_iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

fn to_kebab_case(s: &str) -> String {
    split_identifier_words(s)
        .into_iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("-")
}

fn to_pascal_case(s: &str) -> String {
    split_identifier_words(s)
        .into_iter()
        .map(|w| capitalize_word(&w))
        .collect::<Vec<_>>()
        .join("")
}

fn to_camel_case(s: &str) -> String {
    let words = split_identifier_words(s);
    let mut out = String::new();
    for (i, w) in words.iter().enumerate() {
        if i == 0 {
            out.push_str(&w.to_lowercase());
        } else {
            out.push_str(&capitalize_word(w));
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMacro {
    pub name: String,
    pub template: String,
    pub description: String,
}

static CUSTOM_MACROS: std::sync::OnceLock<std::sync::Mutex<Vec<CustomMacro>>> =
    std::sync::OnceLock::new();

pub fn custom_macros_store() -> &'static std::sync::Mutex<Vec<CustomMacro>> {
    CUSTOM_MACROS.get_or_init(|| {
        let loaded = load_custom_macros_from_disk();
        std::sync::Mutex::new(loaded)
    })
}

pub fn load_custom_macros_from_disk() -> Vec<CustomMacro> {
    if let Ok(raw) = fs::read_to_string("ffrr.macros.json") {
        if let Ok(list) = serde_json::from_str::<Vec<CustomMacro>>(&raw) {
            return list;
        }
    }
    vec![
        CustomMacro {
            name: "AUDIT_TAG".to_string(),
            template: "/* [FFRR-AUDIT {{DATE}} {{FILE}}:{{LINE}}] */ {{MATCH}}".to_string(),
            description: "Prepends an audit comment with date, filename, and line number before the matched text".to_string(),
        },
        CustomMacro {
            name: "ANON_EMAIL".to_string(),
            template: "user_{{SHA256}}@redacted.local".to_string(),
            description: "Replaces matched email/identifier with a deterministic SHA-256 anonymized email".to_string(),
        },
    ]
}

pub fn save_custom_macro(name: &str, template: &str, description: &str) -> Result<Vec<CustomMacro>> {
    let clean_name = name
        .trim()
        .trim_start_matches("{{")
        .trim_end_matches("}}")
        .to_uppercase();
    let store = custom_macros_store();
    let mut list = store.lock().unwrap();
    if let Some(existing) = list.iter_mut().find(|m| m.name == clean_name) {
        existing.template = template.to_string();
        existing.description = description.to_string();
    } else {
        list.push(CustomMacro {
            name: clean_name,
            template: template.to_string(),
            description: description.to_string(),
        });
    }
    fs::write("ffrr.macros.json", serde_json::to_string_pretty(&*list)?)?;
    Ok(list.clone())
}

pub fn delete_custom_macro(name: &str) -> Result<Vec<CustomMacro>> {
    let clean_name = name
        .trim()
        .trim_start_matches("{{")
        .trim_end_matches("}}")
        .to_uppercase();
    let store = custom_macros_store();
    let mut list = store.lock().unwrap();
    list.retain(|m| m.name != clean_name);
    fs::write("ffrr.macros.json", serde_json::to_string_pretty(&*list)?)?;
    Ok(list.clone())
}

pub fn list_custom_macros() -> Vec<CustomMacro> {
    custom_macros_store()
        .lock()
        .map(|l| l.clone())
        .unwrap_or_default()
}

/// Evaluate dynamic template macros (`{{UPPER}}`, `{{LOWER}}`, `{{SNAKE}}`, `{{CAMEL}}`, `{{PASCAL}}`, `{{KEBAB}}`, `{{SHA256}}`, `{{BLAKE3}}`, `{{REDACT}}`, `{{BASE64}}`, `{{FILE}}`, `{{LINE}}`, `{{MATCH_INDEX}}`, `{{DATE}}`, `{{TIMESTAMP}}`, `{{URLENCODE}}`, `{{URLDECODE}}`, `{{REVERSE}}`, `{{LEN}}`, `{{ENV:VAR}}`, plus any user-defined `{{CUSTOM_MACRO}}`)
fn expand_replacement_macros(
    expanded: &str,
    matched_text: &str,
    file_name: &str,
    line_num: usize,
    match_idx: usize,
) -> String {
    if !expanded.contains("{{") {
        return expanded.to_string();
    }
    let mut out = expanded.to_string();

    // First expand any user-defined custom macros (which can themselves reference built-in macros like {{DATE}}, {{SHA256}}, {{MATCH}})
    if let Ok(custom_list) = custom_macros_store().lock() {
        for cm in custom_list.iter() {
            let token = format!("{{{{{}}}}}", cm.name);
            if out.contains(&token) {
                let body = cm.template.replace("{{MATCH}}", matched_text);
                out = out.replace(&token, &body);
            }
        }
    }

    out = out.replace("{{MATCH}}", matched_text);
    out = out.replace("{{UPPER}}", &matched_text.to_uppercase());
    out = out.replace("{{LOWER}}", &matched_text.to_lowercase());
    out = out.replace("{{SNAKE}}", &to_snake_case(matched_text));
    out = out.replace("{{KEBAB}}", &to_kebab_case(matched_text));
    out = out.replace("{{PASCAL}}", &to_pascal_case(matched_text));
    out = out.replace("{{CAMEL}}", &to_camel_case(matched_text));
    out = out.replace("{{FILE}}", file_name);
    out = out.replace("{{LINE}}", &line_num.to_string());
    out = out.replace("{{MATCH_INDEX}}", &match_idx.to_string());
    out = out.replace("{{LEN}}", &matched_text.chars().count().to_string());

    if out.contains("{{DATE}}") {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        out = out.replace("{{DATE}}", &today);
    }
    if out.contains("{{TIMESTAMP}}") {
        let ts = chrono::Utc::now().to_rfc3339();
        out = out.replace("{{TIMESTAMP}}", &ts);
    }
    if out.contains("{{REVERSE}}") {
        let rev: String = matched_text.chars().rev().collect();
        out = out.replace("{{REVERSE}}", &rev);
    }
    if out.contains("{{URLENCODE}}") {
        let enc = urlencoding::encode(matched_text).into_owned();
        out = out.replace("{{URLENCODE}}", &enc);
    }
    if out.contains("{{URLDECODE}}") {
        let dec = urlencoding::decode(matched_text)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| matched_text.to_string());
        out = out.replace("{{URLDECODE}}", &dec);
    }
    // Expand {{ENV:VAR_NAME}}
    while let Some(start_idx) = out.find("{{ENV:") {
        if let Some(end_rel) = out[start_idx..].find("}}") {
            let var_name = &out[start_idx + 6..start_idx + end_rel];
            let val = std::env::var(var_name).unwrap_or_default();
            let full_token = &out[start_idx..start_idx + end_rel + 2].to_string();
            out = out.replace(full_token, &val);
        } else {
            break;
        }
    }

    if out.contains("{{SHA256}}") {
        let mut hasher = Sha256::new();
        hasher.update(matched_text.as_bytes());
        let hex = format!("{:x}", hasher.finalize());
        out = out.replace("{{SHA256}}", &hex[..16]);
    }
    if out.contains("{{BLAKE3}}") {
        let hash = blake3::hash(matched_text.as_bytes()).to_hex().to_string();
        out = out.replace("{{BLAKE3}}", &hash[..16]);
    }
    if out.contains("{{BASE64}}") {
        let b64 = base64::engine::general_purpose::STANDARD.encode(matched_text.as_bytes());
        out = out.replace("{{BASE64}}", &b64);
    }
    if out.contains("{{REDACT}}") {
        let redacted = if matched_text.len() <= 4 {
            "****".to_string()
        } else {
            let keep = matched_text.chars().take(3).collect::<String>();
            format!("{}{}", keep, "*".repeat(matched_text.chars().count().saturating_sub(3).min(16)))
        };
        out = out.replace("{{REDACT}}", &redacted);
    }
    out
}

/// Classify a line and column span into lexical/syntactic scope (`code`, `comments`, `strings`, `keys`, `values`)
pub fn classify_line_scope(line: &str, col_start: usize, ext: &str) -> &'static str {
    let trimmed = line.trim_start();
    // Whole-line comment check
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("--")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("<!--")
    {
        return "comments";
    }

    // Check inline comment before col_start (guarded with is_char_boundary so multi-byte UTF-8 never panics)
    let prefix = if col_start <= line.len() && line.is_char_boundary(col_start) {
        &line[..col_start]
    } else {
        line
    };

    let mut in_double = false;
    let mut in_single = false;
    let mut prev = '\0';
    for (idx, ch) in prefix.char_indices() {
        if ch == '"' && !in_single && prev != '\\' {
            in_double = !in_double;
        } else if ch == '\'' && !in_double && prev != '\\' {
            in_single = !in_single;
        } else if !in_double && !in_single {
            if ch == '/' && prefix[idx..].starts_with("//") {
                return "comments";
            }
            if ch == '#' && matches!(ext, "py" | "sh" | "yaml" | "yml" | "toml" | "conf" | "env" | "rb") {
                return "comments";
            }
        }
        prev = ch;
    }

    if in_double || in_single {
        // Also check if this is a config file key or value
        if matches!(ext, "json" | "yaml" | "yml" | "toml" | "ini" | "env" | "conf" | "properties") {
            if let Some(sep_pos) = line.find(':').or_else(|| line.find('=')) {
                return if col_start < sep_pos { "keys" } else { "values" };
            }
        }
        return "strings";
    }

    if matches!(ext, "json" | "yaml" | "yml" | "toml" | "ini" | "env" | "conf" | "properties") {
        if let Some(sep_pos) = line.find(':').or_else(|| line.find('=')) {
            return if col_start < sep_pos { "keys" } else { "values" };
        }
    }

    "code"
}

pub fn scope_matches(filter: ScopeFilter, detected_scope: &str, line: &str, col_start: usize) -> bool {
    match filter {
        ScopeFilter::All => true,
        ScopeFilter::Code => detected_scope == "code",
        ScopeFilter::Comments => detected_scope == "comments",
        ScopeFilter::Strings => detected_scope == "strings",
        ScopeFilter::Keys => {
            if detected_scope == "keys" {
                return true;
            }
            if let Some(sep) = line.find(':').or_else(|| line.find('=')) {
                col_start < sep
            } else {
                false
            }
        }
        ScopeFilter::Values => {
            if detected_scope == "values" {
                return true;
            }
            if let Some(sep) = line.find(':').or_else(|| line.find('=')) {
                col_start > sep
            } else {
                false
            }
        }
    }
}

/// Detect the nearest enclosing semantic header (function, class, struct, config section, markdown header)
pub fn find_semantic_context(lines: &[&str], line_idx: usize) -> Option<String> {
    let start = line_idx.saturating_sub(1);
    for idx in (0..=start.min(lines.len().saturating_sub(1))).rev() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub async fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("pub struct ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("class ")
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("export function ")
            || trimmed.starts_with("export class ")
            || trimmed.starts_with("interface ")
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
            || trimmed.starts_with("# ")
            || trimmed.starts_with("## ")
        {
            let clean = trimmed.trim_end_matches('{').trim();
            let char_count = clean.chars().count();
            return Some(if char_count > 72 {
                let truncated: String = clean.chars().take(72).collect();
                format!("{}...", truncated)
            } else {
                clean.to_string()
            });
        }
        if line_idx - idx > 80 {
            break;
        }
    }
    None
}

/// Generate a compact unified diff between original and modified text
pub fn generate_unified_diff(path: &str, old_text: &str, new_text: &str) -> String {
    if old_text == new_text {
        return String::new();
    }
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    let mut out = String::new();
    out.push_str(&format!("--- a/{}\n+++ b/{}\n", path, path));

    let max_len = old_lines.len().max(new_lines.len());
    let mut i = 0;
    while i < max_len {
        let o = old_lines.get(i).copied();
        let n = new_lines.get(i).copied();
        if o != n {
            let ctx_start = i.saturating_sub(2);
            let mut hunk_end = i;
            while hunk_end < max_len
                && (old_lines.get(hunk_end) != new_lines.get(hunk_end)
                    || (hunk_end + 1 < max_len && old_lines.get(hunk_end + 1) != new_lines.get(hunk_end + 1)))
            {
                hunk_end += 1;
            }
            let ctx_end = (hunk_end + 2).min(max_len);
            out.push_str(&format!(
                "@@ -{},{} +{},{} @@\n",
                ctx_start + 1,
                ctx_end - ctx_start,
                ctx_start + 1,
                ctx_end - ctx_start
            ));
            for k in ctx_start..ctx_end {
                let ol = old_lines.get(k).copied();
                let nl = new_lines.get(k).copied();
                if ol == nl {
                    if let Some(line) = ol {
                        out.push_str(&format!(" {}\n", line));
                    }
                } else {
                    if let Some(line) = ol {
                        out.push_str(&format!("-{}\n", line));
                    }
                    if let Some(line) = nl {
                        out.push_str(&format!("+{}\n", line));
                    }
                }
            }
            i = ctx_end;
        } else {
            i += 1;
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFileEntry {
    pub original_path: String,
    pub backup_file: String,
    pub original_size: u64,
    pub mtime_secs: u64,
    pub replacements: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub transaction_id: String,
    pub timestamp_utc: String,
    pub find_pattern: String,
    pub replace_pattern: String,
    pub files: Vec<BackupFileEntry>,
}

pub struct TransactionManager;

impl TransactionManager {
    pub fn backup_root() -> PathBuf {
        PathBuf::from(".ffrr_backups")
    }

    pub fn create_transaction(find_pat: &str, repl_pat: &str) -> Result<(String, PathBuf)> {
        let now = chrono::Utc::now();
        let tx_id = format!("tx_{}", now.format("%Y%m%d_%H%M%S_%3f"));
        let dir = Self::backup_root().join(&tx_id);
        fs::create_dir_all(&dir)?;
        let manifest = BackupManifest {
            transaction_id: tx_id.clone(),
            timestamp_utc: now.to_rfc3339(),
            find_pattern: find_pat.to_string(),
            replace_pattern: repl_pat.to_string(),
            files: Vec::new(),
        };
        let manifest_path = dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
        Ok((tx_id, dir))
    }

    pub fn record_backup(
        tx_dir: &Path,
        idx: usize,
        original_path: &str,
        original_bytes: &[u8],
        mtime_secs: u64,
        replacements: usize,
    ) -> Result<BackupFileEntry> {
        let bak_name = format!("file_{:05}.bak", idx);
        let bak_path = tx_dir.join(&bak_name);
        fs::write(&bak_path, original_bytes)?;
        Ok(BackupFileEntry {
            original_path: original_path.to_string(),
            backup_file: bak_name,
            original_size: original_bytes.len() as u64,
            mtime_secs,
            replacements,
        })
    }

    pub fn finalize_manifest(
        tx_dir: &Path,
        tx_id: &str,
        find_pat: &str,
        repl_pat: &str,
        entries: Vec<BackupFileEntry>,
    ) -> Result<()> {
        if entries.is_empty() {
            let _ = fs::remove_dir_all(tx_dir);
            return Ok(());
        }
        let manifest = BackupManifest {
            transaction_id: tx_id.to_string(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            find_pattern: find_pat.to_string(),
            replace_pattern: repl_pat.to_string(),
            files: entries,
        };
        fs::write(
            tx_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?,
        )?;
        Ok(())
    }

    pub fn list_transactions() -> Result<Vec<BackupManifest>> {
        let root = Self::backup_root();
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut manifests = Vec::new();
        for entry in fs::read_dir(root)?.flatten() {
            let mpath = entry.path().join("manifest.json");
            if mpath.is_file() {
                if let Ok(raw) = fs::read_to_string(&mpath) {
                    if let Ok(m) = serde_json::from_str::<BackupManifest>(&raw) {
                        manifests.push(m);
                    }
                }
            }
        }
        manifests.sort_by(|a, b| b.transaction_id.cmp(&a.transaction_id));
        Ok(manifests)
    }

    pub fn undo_transaction(tx_id: Option<&str>) -> Result<(BackupManifest, usize)> {
        let manifests = Self::list_transactions()?;
        if manifests.is_empty() {
            anyhow::bail!("No backup transactions found in .ffrr_backups/");
        }
        let target = if let Some(id) = tx_id {
            manifests
                .into_iter()
                .find(|m| m.transaction_id == id)
                .with_context(|| format!("Transaction `{}` not found", id))?
        } else {
            manifests.into_iter().next().unwrap()
        };

        let tx_dir = Self::backup_root().join(&target.transaction_id);
        let mut restored = 0usize;
        for f in &target.files {
            // Validate backup_file name has no path traversal components
            if f.backup_file.contains("..")
                || f.backup_file.contains('/')
                || f.backup_file.contains('\\')
            {
                continue;
            }
            let bak_path = tx_dir.join(&f.backup_file);
            if bak_path.is_file() {
                let bytes = fs::read(&bak_path)?;
                if is_remote_source_uri(&f.original_path) {
                    write_remote_uri_bytes(&f.original_path, &bytes)?;
                } else {
                    let orig_target = if let Some((arc, _)) = f.original_path.split_once("::") {
                        arc
                    } else {
                        &f.original_path
                    };
                    fs::write(orig_target, bytes)?;
                }
                restored += 1;
            }
        }
        let _ = fs::remove_dir_all(&tx_dir);
        Ok((target, restored))
    }
}

pub fn generate_cli_equivalents(opts: &SearchReplaceOptions) -> CliEquivalents {
    let dir_str = opts
        .traversal
        .sources
        .first()
        .cloned()
        .unwrap_or_else(|| ".".to_string());
    let mask_str = if opts.traversal.file_masks.is_empty() {
        "*.*".to_string()
    } else {
        opts.traversal.file_masks.join(",")
    };

    // 1. Modern ffrr CLI
    let mut ffrr_parts = vec![format!("ffrr -f {:?}", opts.find)];
    if let Some(ref r) = opts.replace {
        ffrr_parts.push(format!("-r {:?}", r));
    }
    for s in &opts.traversal.sources {
        ffrr_parts.push(format!("-d {:?}", s));
    }
    if !opts.traversal.file_masks.is_empty() {
        ffrr_parts.push(format!("-m {:?}", mask_str));
    }
    if !opts.traversal.exclude_masks.is_empty() {
        ffrr_parts.push(format!("-x {:?}", opts.traversal.exclude_masks.join(",")));
    }
    if opts.use_regex {
        ffrr_parts.push("-E".to_string());
    }
    if opts.case_sensitive {
        ffrr_parts.push("-s".to_string());
    }
    if opts.whole_word {
        ffrr_parts.push("-w".to_string());
    }
    if opts.preserve_case {
        ffrr_parts.push("-P".to_string());
    }
    if opts.scope != ScopeFilter::All {
        ffrr_parts.push(format!("--scope {:?}", opts.scope).to_lowercase());
    }
    if opts.dry_run {
        ffrr_parts.push("--dry-run".to_string());
    }

    // 2. Classic fnr.exe CLI (findandreplace.io)
    let mut fnr_parts = vec![
        "fnr.exe --cl".to_string(),
        format!("--dir {:?}", dir_str),
        format!("--fileMask {:?}", mask_str),
    ];
    if !opts.traversal.exclude_masks.is_empty() {
        fnr_parts.push(format!(
            "--excludeFileMask {:?}",
            opts.traversal.exclude_masks.join(",")
        ));
    }
    if opts.traversal.recursive {
        fnr_parts.push("--includeSubDirectories".to_string());
    }
    if opts.case_sensitive {
        fnr_parts.push("--caseSensitive".to_string());
    }
    if opts.use_regex {
        fnr_parts.push("--useRegEx".to_string());
    }
    if opts.use_escape_chars {
        fnr_parts.push("--useEscapeChars".to_string());
    }
    if opts.keep_mtime {
        fnr_parts.push("--KeepModifiedDate".to_string());
    }
    fnr_parts.push(format!("--find {:?}", opts.find));
    if let Some(ref r) = opts.replace {
        fnr_parts.push(format!("--replace {:?}", r));
    }

    // 3. Unix ripgrep + sed / sd equivalent
    let unix_cmd = if let Some(ref r) = opts.replace {
        format!(
            "rg -l {} {:?} {:?} | xargs sed -i '' 's/{}/{}/g'",
            if opts.case_sensitive { "-s" } else { "-i" },
            opts.find,
            dir_str,
            opts.find.replace('/', "\\/"),
            r.replace('/', "\\/")
        )
    } else {
        format!(
            "rg -n {} {:?} {:?}",
            if opts.case_sensitive { "-s" } else { "-i" },
            opts.find,
            dir_str
        )
    };

    // 4. PowerShell equivalent
    let powershell_cmd = if let Some(ref r) = opts.replace {
        format!(
            "Get-ChildItem -Path {:?} -Filter {:?} -Recurse -File | ForEach-Object {{ (Get-Content $_.FullName -Raw) -replace {:?}, {:?} | Set-Content $_.FullName }}",
            dir_str, mask_str, opts.find, r
        )
    } else {
        format!(
            "Get-ChildItem -Path {:?} -Filter {:?} -Recurse -File | Select-String -Pattern {:?}",
            dir_str, mask_str, opts.find
        )
    };

    CliEquivalents {
        ffrr_cmd: ffrr_parts.join(" "),
        fnr_exe_cmd: fnr_parts.join(" "),
        unix_cmd,
        powershell_cmd,
    }
}

pub fn run_search_replace(opts: &SearchReplaceOptions) -> Result<SearchReplaceSummary> {
    let start = Instant::now();
    let cli_equivalents = generate_cli_equivalents(opts);
    start_progress_job("Discovering files across sources & archives...");
    let target_mode = opts.search_target.to_lowercase();
    let allow_filename_match = target_mode != "content";
    let allow_content_match = target_mode != "filename";
    if allow_filename_match {
        set_active_find_hint(&opts.find);
    } else {
        set_active_find_hint("");
    }

    let find_trimmed = opts.find.trim();
    // If Find Text is empty AND no file mask is provided, return empty summary immediately
    if find_trimmed.is_empty() && opts.traversal.file_masks.is_empty() {
        finish_progress_job("Idle");
        return Ok(SearchReplaceSummary {
            total_files_scanned: 0,
            files_with_matches: 0,
            files_modified: 0,
            binary_files_skipped: 0,
            archive_entries_scanned: 0,
            total_matches: 0,
            total_replacements: 0,
            elapsed_ms: 0,
            dry_run: opts.dry_run,
            transaction_id: None,
            cli_equivalents,
            results: Vec::new(),
        });
    }

    let regex = if find_trimmed.is_empty() {
        RegexBuilder::new(".*").build()?
    } else {
        build_search_regex(opts)?
    };
    let mut items = resolve_sources(&opts.traversal)?;
    let total_files_scanned = items.len();
    let archive_entries_scanned = items.iter().filter(|i| i.is_archive_member()).count();

    // Prioritize files whose filename matches `regex` at the front of `items` so they are processed in the first few milliseconds!
    if !find_trimmed.is_empty() {
        items.sort_by_cached_key(|it| {
            let fn_match = regex.is_match(&it.file_name()) || regex.is_match(&it.display_path());
            if fn_match { 0u8 } else { 1u8 }
        });
    }

    set_progress_phase(&format!(
        "Scanning {} matching files across worker threads...",
        total_files_scanned
    ));

    let forced_enc = opts
        .forced_encoding
        .as_deref()
        .and_then(FileEncoding::from_name);

    let replace_template = opts.replace.as_ref().map(|r| {
        if opts.use_escape_chars {
            unescape_string(r)
        } else {
            r.clone()
        }
    });

    // Process all items in parallel across Rayon worker threads
    let raw_results: Vec<(SourceItem, FileSearchResult, Option<(Vec<u8>, Vec<u8>)>)> = items
        .into_par_iter()
        .filter_map(|item| {
            if is_progress_cancelled() {
                return None;
            }
            let display_path = item.display_path();
            let file_name = item.file_name();
            let extension = item.extension();
            let archive_kind = item.archive_kind().to_string();
            let source_root = item.source_root().to_string();
            let size_bytes = if item.size() > 0 {
                item.size()
            } else {
                fs::metadata(&display_path).map(|m| m.len()).unwrap_or(0)
            };

            let filename_matched = allow_filename_match
                && replace_template.is_none()
                && (find_trimmed.is_empty()
                    || regex.is_match(&file_name)
                    || regex.is_match(&display_path));

            // Fast path 1: Filename-Only mode OR empty Find Text with File Mask
            if !allow_content_match || (find_trimmed.is_empty() && replace_template.is_none()) {
                if filename_matched {
                    record_scanned_file(&display_path, 1);
                    let res = FileSearchResult {
                        path: display_path.clone(),
                        file_name: file_name.clone(),
                        extension,
                        archive_kind,
                        source_root,
                        size_bytes,
                        encoding: "Filename Match".to_string(),
                        is_binary: false,
                        match_count: 1,
                        replaced_count: 0,
                        modified_on_disk: false,
                        unified_diff: None,
                        matches: vec![LineMatch {
                            line_number: 1,
                            column: 1,
                            line_text: format!("[FILENAME MATCH] {}", display_path),
                            replaced_line_text: None,
                            semantic_context: Some("Filename / Path Match".to_string()),
                            scope_kind: "filename".to_string(),
                            spans: Vec::new(),
                            context_before: Vec::new(),
                            context_after: Vec::new(),
                        }],
                        error: None,
                    };
                    if let Ok(v) = serde_json::to_value(&res) {
                        push_live_result_json(v);
                    }
                    return Some((item, res, None));
                } else {
                    record_scanned_file(&display_path, 0);
                    return None;
                }
            }

            // Fast path 2: Skip known binary extensions immediately without reading gigabytes of disk bytes!
            if opts.ignore_binary && is_known_binary_extension(&extension) && !filename_matched {
                record_scanned_file(&display_path, 0);
                return Some((
                    item,
                    FileSearchResult {
                        path: display_path,
                        file_name,
                        extension,
                        archive_kind,
                        source_root,
                        size_bytes,
                        encoding: FileEncoding::Binary.as_str().to_string(),
                        is_binary: true,
                        match_count: 0,
                        replaced_count: 0,
                        modified_on_disk: false,
                        unified_diff: None,
                        matches: Vec::new(),
                        error: None,
                    },
                    None,
                ));
            }

            // Skip reading huge >8MB files during content scan unless filename matched
            if size_bytes > 8 * 1024 * 1024 && !filename_matched {
                record_scanned_file(&display_path, 0);
                return None;
            }

            let raw_bytes = match item.read_bytes() {
                Ok(b) => b,
                Err(e) => {
                    record_scanned_file(&display_path, 0);
                    return Some((
                        item,
                        FileSearchResult {
                            path: display_path,
                            file_name,
                            extension,
                            archive_kind,
                            source_root,
                            size_bytes,
                            encoding: "Error".to_string(),
                            is_binary: false,
                            match_count: 0,
                            replaced_count: 0,
                            modified_on_disk: false,
                            unified_diff: None,
                            matches: Vec::new(),
                            error: Some(e.to_string()),
                        },
                        None,
                    ));
                }
            };

            let decoded = decode_bytes(&raw_bytes, forced_enc, opts.always_use_encoding);
            if decoded.is_binary && opts.ignore_binary && !filename_matched {
                record_scanned_file(&display_path, 0);
                return Some((
                    item,
                    FileSearchResult {
                        path: display_path,
                        file_name,
                        extension,
                        archive_kind,
                        source_root,
                        size_bytes,
                        encoding: FileEncoding::Binary.as_str().to_string(),
                        is_binary: true,
                        match_count: 0,
                        replaced_count: 0,
                        modified_on_disk: false,
                        unified_diff: None,
                        matches: Vec::new(),
                        error: None,
                    },
                    None,
                ));
            }

            let lines: Vec<&str> = decoded.text.lines().collect();
            let mut line_matches = Vec::new();
            let mut total_file_matches = 0usize;
            let mut total_file_replacements = 0usize;
            let mut modified_lines: Vec<String> = Vec::with_capacity(lines.len());

            if filename_matched {
                total_file_matches += 1;
                line_matches.push(LineMatch {
                    line_number: 1,
                    column: 1,
                    line_text: format!(
                        "[FILENAME MATCH] {} ({} lines, {} bytes)",
                        display_path,
                        lines.len(),
                        size_bytes
                    ),
                    replaced_line_text: None,
                    semantic_context: Some("Filename Match".to_string()),
                    scope_kind: "filename".to_string(),
                    spans: Vec::new(),
                    context_before: Vec::new(),
                    context_after: Vec::new(),
                });
            }

            for (idx, &line) in lines.iter().enumerate() {
                let line_num = idx + 1;
                if let Some(max_m) = opts.max_matches_per_file {
                    if total_file_matches >= max_m {
                        if replace_template.is_some() {
                            modified_lines.push(line.to_string());
                        }
                        continue;
                    }
                }

                if opts.invert_match {
                    let has_match = regex.is_match(line);
                    if !has_match {
                        total_file_matches += 1;
                        line_matches.push(LineMatch {
                            line_number: line_num,
                            column: 1,
                            line_text: line.to_string(),
                            replaced_line_text: None,
                            semantic_context: if opts.semantic_context {
                                find_semantic_context(&lines, idx)
                            } else {
                                None
                            },
                            scope_kind: classify_line_scope(line, 0, &extension).to_string(),
                            spans: Vec::new(),
                            context_before: Vec::new(),
                            context_after: Vec::new(),
                        });
                    }
                    continue;
                }

                let mut spans = Vec::new();
                let mut first_scope = "code";

                for m in regex.find_iter(line) {
                    let sc = classify_line_scope(line, m.start(), &extension);
                    if !scope_matches(opts.scope, sc, line, m.start()) {
                        continue;
                    }
                    if spans.is_empty() {
                        first_scope = sc;
                    }
                    total_file_matches += 1;
                    let match_idx = total_file_matches;

                    let replaced_span = replace_template.as_ref().map(|tpl| {
                        let base_repl = if opts.use_regex {
                            let mut dst = String::new();
                            if let Some(caps) = regex.captures(&line[m.start()..m.end()]) {
                                caps.expand(tpl, &mut dst);
                            } else {
                                dst.push_str(tpl);
                            }
                            dst
                        } else {
                            tpl.clone()
                        };
                        let with_macros = expand_replacement_macros(
                            &base_repl,
                            m.as_str(),
                            &file_name,
                            line_num,
                            match_idx,
                        );
                        if opts.preserve_case {
                            apply_preserve_case(m.as_str(), &with_macros)
                        } else {
                            with_macros
                        }
                    });

                    spans.push(MatchSpan {
                        start_col: m.start() + 1,
                        end_col: m.end() + 1,
                        matched_text: m.as_str().to_string(),
                        replaced_text: replaced_span,
                    });
                }

                if !spans.is_empty() {
                    let replaced_line = if let Some(ref tpl) = replace_template {
                        let mut match_counter = total_file_matches - spans.len();
                        let new_l = regex
                            .replace_all(line, |caps: &Captures| {
                                let m0 = caps.get(0).unwrap();
                                let sc = classify_line_scope(line, m0.start(), &extension);
                                if !scope_matches(opts.scope, sc, line, m0.start()) {
                                    return m0.as_str().to_string();
                                }
                                match_counter += 1;
                                total_file_replacements += 1;
                                let base_repl = if opts.use_regex {
                                    let mut dst = String::new();
                                    caps.expand(tpl, &mut dst);
                                    dst
                                } else {
                                    tpl.clone()
                                };
                                let with_macros = expand_replacement_macros(
                                    &base_repl,
                                    m0.as_str(),
                                    &file_name,
                                    line_num,
                                    match_counter,
                                );
                                if opts.preserve_case {
                                    apply_preserve_case(m0.as_str(), &with_macros)
                                } else {
                                    with_macros
                                }
                            })
                            .into_owned();
                        modified_lines.push(new_l.clone());
                        Some(new_l)
                    } else {
                        None
                    };

                    let mut ctx_before = Vec::new();
                    if opts.context_before > 0 {
                        let b_start = idx.saturating_sub(opts.context_before);
                        for b_idx in b_start..idx {
                            ctx_before.push(ContextLine {
                                line_number: b_idx + 1,
                                line_text: lines[b_idx].to_string(),
                            });
                        }
                    }
                    let mut ctx_after = Vec::new();
                    if opts.context_after > 0 {
                        let a_end = (idx + 1 + opts.context_after).min(lines.len());
                        for a_idx in (idx + 1)..a_end {
                            ctx_after.push(ContextLine {
                                line_number: a_idx + 1,
                                line_text: lines[a_idx].to_string(),
                            });
                        }
                    }

                    line_matches.push(LineMatch {
                        line_number: line_num,
                        column: spans[0].start_col,
                        line_text: line.to_string(),
                        replaced_line_text: replaced_line,
                        semantic_context: if opts.semantic_context {
                            find_semantic_context(&lines, idx)
                        } else {
                            None
                        },
                        scope_kind: first_scope.to_string(),
                        spans,
                        context_before: ctx_before,
                        context_after: ctx_after,
                    });
                } else if replace_template.is_some() {
                    modified_lines.push(line.to_string());
                }
            }

            // Also support multi-line replacements when opts.multiline is enabled and line-by-line didn't catch spanning newlines
            let mut new_full_text: Option<String> = None;
            if opts.multiline && total_file_matches == 0 && !opts.invert_match {
                if regex.is_match(&decoded.text) {
                    for m in regex.find_iter(&decoded.text) {
                        total_file_matches += 1;
                        let line_num = decoded.text[..m.start()].lines().count().max(1);
                        line_matches.push(LineMatch {
                            line_number: line_num,
                            column: 1,
                            line_text: m.as_str().replace('\n', "\\n"),
                            replaced_line_text: replace_template.clone(),
                            semantic_context: None,
                            scope_kind: "multiline".to_string(),
                            spans: vec![MatchSpan {
                                start_col: 1,
                                end_col: m.len() + 1,
                                matched_text: m.as_str().to_string(),
                                replaced_text: replace_template.clone(),
                            }],
                            context_before: Vec::new(),
                            context_after: Vec::new(),
                        });
                    }
                    if let Some(ref tpl) = replace_template {
                        total_file_replacements = total_file_matches;
                        new_full_text = Some(regex.replace_all(&decoded.text, tpl.as_str()).into_owned());
                    }
                }
            } else if replace_template.is_some() && total_file_replacements > 0 {
                let line_sep = if decoded.has_crlf { "\r\n" } else { "\n" };
                let mut joined = modified_lines.join(line_sep);
                if decoded.text.ends_with("\r\n") {
                    joined.push_str("\r\n");
                } else if decoded.text.ends_with('\n') {
                    joined.push('\n');
                }
                new_full_text = Some(joined);
            }

            let unified_diff = new_full_text
                .as_ref()
                .map(|nt| generate_unified_diff(&display_path, &decoded.text, nt))
                .filter(|d| !d.is_empty());

            // Memory optimization: only retain (raw_bytes, new_bytes) in RAM when performing
            // a live disk/archive write-back (!opts.dry_run) and the content actually changed.
            let write_payload = if !opts.dry_run {
                new_full_text.and_then(|nt| {
                    let new_bytes = encode_text(&nt, decoded.encoding);
                    if new_bytes != raw_bytes {
                        Some((raw_bytes, new_bytes))
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            record_scanned_file(&display_path, total_file_matches);

            let res = FileSearchResult {
                path: display_path,
                file_name,
                extension,
                archive_kind,
                source_root,
                size_bytes,
                encoding: decoded.encoding.as_str().to_string(),
                is_binary: decoded.is_binary,
                match_count: total_file_matches,
                replaced_count: total_file_replacements,
                modified_on_disk: false,
                unified_diff,
                matches: line_matches,
                error: None,
            };
            if total_file_matches > 0 {
                if let Ok(v) = serde_json::to_value(&res) {
                    push_live_result_json(v);
                }
            }

            Some((item, res, write_payload))
        })
        .collect();

    let mut binary_files_skipped = 0usize;
    let mut files_with_matches = 0usize;
    let mut files_modified = 0usize;
    let mut total_matches = 0usize;
    let mut total_replacements = 0usize;
    let mut results = Vec::new();

    let mut tx_info: Option<(String, PathBuf, Vec<BackupFileEntry>)> = None;
    if opts.replace.is_some() && !opts.dry_run && opts.create_backup {
        if let Ok((tx_id, tx_dir)) = TransactionManager::create_transaction(
            &opts.find,
            opts.replace.as_deref().unwrap_or(""),
        ) {
            tx_info = Some((tx_id, tx_dir, Vec::new()));
        }
    }

    for (idx, (item, mut res, payload)) in raw_results.into_iter().enumerate() {
        if res.is_binary {
            binary_files_skipped += 1;
            continue;
        }
        if res.match_count > 0 {
            files_with_matches += 1;
            total_matches += res.match_count;
            total_replacements += res.replaced_count;

            if let Some((orig_bytes, new_bytes)) = payload {
                if !opts.dry_run && orig_bytes != new_bytes {
                    if let Some((_, ref tx_dir, ref mut entries)) = tx_info {
                        if let Ok(entry) = TransactionManager::record_backup(
                            tx_dir,
                            idx,
                            &res.path,
                            &orig_bytes,
                            item.mtime_secs(),
                            res.replaced_count,
                        ) {
                            entries.push(entry);
                        }
                    }
                    match write_item_bytes(&item, &new_bytes, opts.keep_mtime) {
                        Ok(()) => {
                            res.modified_on_disk = true;
                            files_modified += 1;
                        }
                        Err(e) => {
                            res.error = Some(e.to_string());
                        }
                    }
                }
            }
            results.push(res);
        }
    }

    let transaction_id = if let Some((tx_id, tx_dir, entries)) = tx_info {
        let has_entries = !entries.is_empty();
        let _ = TransactionManager::finalize_manifest(
            &tx_dir,
            &tx_id,
            &opts.find,
            opts.replace.as_deref().unwrap_or(""),
            entries,
        );
        if has_entries {
            Some(tx_id)
        } else {
            None
        }
    } else {
        None
    };

    // Preserve any live filename matches discovered before a user cancellation
    for live_val in get_live_results_json() {
        if let Ok(live_res) = serde_json::from_value::<FileSearchResult>(live_val) {
            if !results.iter().any(|r| r.path == live_res.path) {
                files_with_matches += 1;
                total_matches += live_res.match_count;
                results.push(live_res);
            }
        }
    }

    finish_progress_job(if is_progress_cancelled() {
        "Stopped (Showing partial matches found)"
    } else {
        "Completed"
    });

    Ok(SearchReplaceSummary {
        total_files_scanned,
        files_with_matches,
        files_modified,
        binary_files_skipped,
        archive_entries_scanned,
        total_matches,
        total_replacements,
        elapsed_ms: start.elapsed().as_millis(),
        dry_run: opts.dry_run,
        transaction_id,
        cli_equivalents,
        results,
    })
}
