//! ============================================================================
//! Module: `main.rs` — Unified Single-Executable Entry Point (`ffrr`)
//! ============================================================================
//!
//! ### Architecture Overview (For Developers from Any Language)
//! FFRR compiles into a **single standalone executable** (`ffrr` / `ffrr.exe`)
//! that provides 5 user interfaces and 4 core engines:
//! 1. **CLI (`ffrr ...`)**:
//!    - Preprocess layer (`preprocess_cli_args`) translates legacy Windows
//!      `fnr.exe` flags (`--cl`, `--dir`, `--fileMask`, `--useRegEx`, etc.)
//!      into standard `clap` arguments so existing scripts work unchanged.
//!    - Supports Linux/macOS `ripgrep`/`sed`/`fd` ergonomics (`-f`, `-r`, `-d`,
//!      `-m`, `-x`, `-E`, `-F`, `-s`, `-i`, `-w`, `-P`, `-v`, `-B`, `-A`, `-C`).
//! 2. **Interactive Terminal UI (`ffrr tui`)**: Full-screen Ratatui dashboard.
//! 3. **Web Studio & REST API (`ffrr serve`)**: Axum HTTP server + single-page UI.
//! 4. **Native Desktop GUI (`ffrr gui`)**: OS-native WebView window (`tao`+`wry`).
//! 5. **AI Agent MCP Server (`ffrr mcp`)**: JSON-RPC 2.0 stdio server for LLMs.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

mod archive;
mod engine;
mod features;
mod gui;
mod mcp;
mod server;
mod sym;
mod tui;

use crate::archive::{
    create_rar5_archive, delete_connection_profile, detect_system_drives, load_connection_profiles,
    save_connection_profile, split_mask_list, TraversalOptions,
};
use crate::engine::{
    delete_custom_macro, generate_cli_equivalents, list_custom_macros, run_search_replace,
    save_custom_macro, ScopeFilter, SearchReplaceOptions, SearchReplaceSummary, TransactionManager,
};
use crate::features::{
    analyze_intents, execute_intent_pack, find_duplicates, group_files, DuplicateOptions,
    GroupByMode,
};
use crate::sym::*;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub const FFRR_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_ascii_banner() -> String {
    format!(
        r#"  _____ _____ ____  ____  
 |  ___|  ___|  _ \|  _ \   FFRR v{} — Fast Find, Replace & Refactor Engine
 | |_  | |_  | |_) | |_) |  (File Find and Replace in Rust)
 |  _| |  _| |  _ <|  _ <   Multi-Threaded | Archive-Native (.zip/.rar/.gz/.tar.gz/.zst)
 |_|   |_|   |_| \_\_| \_\  Context & Intent Engine | File Grouping & Dedup | CLI+TUI+Web+GUI+MCP
                            Made using vibe coding by Sunil Warrier
===================================================================================="#,
        FFRR_VERSION
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Rich grouped per-file output with line numbers, encoding, and context
    Table,
    /// Compact grep/ripgrep style (`path:line:col: text`)
    Compact,
    /// Unified diff output (`--- a/file` / `+++ b/file`)
    Diff,
    /// Structured JSON report
    Json,
    /// CSV spreadsheet output
    Csv,
    /// Only matching file paths (like `grep -l`)
    Files,
}

#[derive(Parser)]
#[command(
    name = "ffrr",
    version = FFRR_VERSION,
    about = "FFRR — Fast Find, Replace & Refactor Engine (File Find and Replace in Rust — fnr.exe + rg + sed + fd + fdupes + Web/GUI/TUI/MCP)",
    long_about = "High-speed multi-threaded Find, Replace, Refactor, File Grouping & Duplicate Detection engine.\nSearches and replaces across multiple folders, globs, and inside archives (.zip, .rar, .gz, .tar.gz, .zst, .bz2).\n100% drop-in compatible with classic findandreplace.io (fnr.exe --cl --dir ... --fileMask ... --find ... --replace ...) plus modern Linux/macOS flags, lexical scope filtering, smart case-preservation, transactional undo, TUI, Web Studio, Native GUI, and AI MCP."
)]
struct Cli {
    /// Positional search pattern (if `-f / --find` is not specified)
    #[arg(value_name = "PATTERN")]
    positional_pattern: Option<String>,

    /// Positional target directories, files, or archives (if `-d / --dir` is not specified)
    #[arg(value_name = "PATHS")]
    positional_paths: Vec<String>,

    /// Text or regex pattern to find (`-f` or classic `--find`)
    #[arg(short = 'f', long = "find", value_name = "FIND_PATTERN")]
    find: Option<String>,

    /// Replacement string (`-r` or classic `--replace`). Supports `$1` and `{{UPPER}}`, `{{LOWER}}`, `{{SNAKE}}`, `{{CAMEL}}`, `{{PASCAL}}`, `{{KEBAB}}`, `{{SHA256}}`, `{{BLAKE3}}`, `{{REDACT}}`, `{{FILE}}`, `{{LINE}}`
    #[arg(short = 'r', long = "replace", value_name = "REPLACE_WITH")]
    replace: Option<String>,

    /// Target directory, file, glob, or archive (`.zip`, `.rar`, `.gz`, `.tar.gz`, `.zst`) — can be passed multiple times or semicolon-separated
    #[arg(short = 'd', long = "dir", alias = "source", value_name = "DIR_OR_ARCHIVE")]
    dirs: Vec<String>,

    /// Include file mask(s), comma or semicolon separated (e.g. `"*.rs,*.json"` or classic `--fileMask "*.*"`)
    #[arg(short = 'm', long = "file-mask", alias = "include", value_name = "MASK")]
    file_mask: Option<String>,

    /// Exclude file mask(s), comma or semicolon separated (e.g. `"*.dll,*.exe"` or classic `--excludeFileMask`)
    #[arg(short = 'x', long = "exclude-mask", alias = "exclude", value_name = "MASK")]
    exclude_mask: Option<String>,

    /// Exclude directory names, comma or semicolon separated (default: `.git,node_modules,target,.ffrr_backups`)
    #[arg(long = "exclude-dir", value_name = "DIRS")]
    exclude_dir: Option<String>,

    /// Disable recursive subdirectory traversal (by default subdirectories are searched)
    #[arg(long = "no-recursive")]
    no_recursive: bool,

    /// Disable searching inside compressed archives (`.zip`, `.rar`, `.gz`, `.tar.gz`, `.zst`, `.bz2`)
    #[arg(long = "no-archives")]
    no_archives: bool,

    /// Include hidden dot-files and dot-directories
    #[arg(long = "hidden")]
    hidden: bool,

    /// Do not filter files using `.gitignore` / `.ignore`
    #[arg(long = "no-gitignore")]
    no_gitignore: bool,

    /// Minimum file size in bytes
    #[arg(long = "min-size", value_name = "BYTES")]
    min_size: Option<u64>,

    /// Maximum file size in bytes
    #[arg(long = "max-size", value_name = "BYTES")]
    max_size: Option<u64>,

    /// Use regular expressions (`-E` / `--regex` / classic `--useRegEx`)
    #[arg(short = 'E', long = "regex")]
    use_regex: bool,

    /// Treat pattern as a literal fixed string (`-F` / `--fixed-strings`)
    #[arg(short = 'F', long = "fixed-strings")]
    fixed_strings: bool,

    /// Force case-sensitive matching (`-s` / `--case-sensitive` / classic `--caseSensitive`)
    #[arg(short = 's', long = "case-sensitive")]
    case_sensitive: bool,

    /// Force case-insensitive matching (`-i` / `--ignore-case`)
    #[arg(short = 'i', long = "ignore-case")]
    ignore_case: bool,

    /// Match whole words only (`-w` / `--word-regexp`)
    #[arg(short = 'w', long = "word-regexp")]
    whole_word: bool,

    /// Smart case-preserving replacement (`-P` / `--preserve-case`: `FooBar`->`BazQux`, `FOO_BAR`->`BAZ_QUX`, `foo_bar`->`baz_qux`)
    #[arg(short = 'P', long = "preserve-case")]
    preserve_case: bool,

    /// Enable multi-line matching across line breaks (`-U` / `--multiline`)
    #[arg(short = 'U', long = "multiline")]
    multiline: bool,

    /// Interpret escape sequences (`\n`, `\r`, `\t`, `\xHH`) in find & replace strings (classic `--useEscapeChars`)
    #[arg(long = "escape")]
    use_escape_chars: bool,

    /// Invert match: select non-matching lines (`-v` / `--invert-match`)
    #[arg(short = 'v', long = "invert-match")]
    invert_match: bool,

    /// Search only filenames/paths without reading file contents (`--filename-only`)
    #[arg(long = "filename-only")]
    filename_only: bool,

    /// Search only inside file contents, ignoring filename matches (`--content-only`)
    #[arg(long = "content-only")]
    content_only: bool,

    /// Lexical/syntactic context scope filter (`all`, `code`, `comments`, `strings`, `keys`, `values`)
    #[arg(long = "scope", value_enum, default_value_t = ScopeFilter::All)]
    scope: ScopeFilter,

    /// Preview replacements without modifying files on disk (`-n` / `--dry-run`)
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,

    /// Show unified diff of changes (`--diff`)
    #[arg(long = "diff")]
    show_diff: bool,

    /// Skip creating undo backup snapshot in `.ffrr_backups/` before replacing
    #[arg(long = "no-backup")]
    no_backup: bool,

    /// Search binary files as text instead of skipping them (`-a` / `--binary-text`)
    #[arg(short = 'a', long = "binary-text")]
    binary_text: bool,

    /// Force specific file encoding (`utf-8`, `utf-8-bom`, `utf-16le`, `utf-16be`, `windows-1252`, `ascii`)
    #[arg(long = "encoding", value_name = "ENCODING")]
    encoding: Option<String>,

    /// Always use forced encoding even if BOM is present (`--alwaysUseEncoding`)
    #[arg(long = "always-use-encoding")]
    always_use_encoding: bool,

    /// Preserve original file modification timestamp (`--keep-mtime` / classic `--KeepModifiedDate`)
    #[arg(long = "keep-mtime")]
    keep_mtime: bool,

    /// Exit with non-zero status code if any file read/write error occurs (`--strict-errors`)
    #[arg(long = "strict-errors")]
    strict_errors: bool,

    /// Number of context lines before each match (`-B`)
    #[arg(short = 'B', long = "before-context", default_value_t = 0)]
    before_context: usize,

    /// Number of context lines after each match (`-A`)
    #[arg(short = 'A', long = "after-context", default_value_t = 0)]
    after_context: usize,

    /// Number of context lines before and after each match (`-C`)
    #[arg(short = 'C', long = "context")]
    context: Option<usize>,

    /// Print only the count of matches (`-c` / `--count`)
    #[arg(short = 'c', long = "count")]
    count_only: bool,

    /// Print only filenames with matches (`-l` / `--files-with-matches`)
    #[arg(short = 'l', long = "files-with-matches")]
    files_with_matches: bool,

    /// Output format (`table`, `compact`, `diff`, `json`, `csv`, `files`)
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Table)]
    output_format: OutputFormat,

    /// Number of parallel worker threads (`-j` / `--threads`, default: all CPU cores)
    #[arg(short = 'j', long = "threads", global = true, value_name = "NUM_THREADS")]
    threads: Option<usize>,

    /// Write execution log to a file (`--log-file` / classic `--logFile`)
    #[arg(long = "log-file", value_name = "PATH")]
    log_file: Option<String>,

    /// Quiet / silent mode: suppress banner and summary footer (`-q` / `--quiet` / classic `--silent`)
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    /// Force plain ASCII symbols (`--ascii`)
    #[arg(long = "ascii", global = true)]
    ascii: bool,

    /// Load a named configuration profile from `ffrr.config.json`
    #[arg(long = "profile", global = true, value_name = "NAME")]
    profile: Option<String>,

    /// Save current CLI options to `ffrr.config.json` under this profile name
    #[arg(long = "save-profile", global = true, value_name = "NAME")]
    save_profile: Option<String>,

    /// List all saved profiles in `ffrr.config.json`
    #[arg(long = "list-profiles", global = true)]
    list_profiles: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Group and classify files across directories & archives by language, extension, source, directory, size, encoding, or age
    Group {
        /// Target directories, files, or archives
        #[arg(short = 'd', long = "dir", value_name = "PATH")]
        dirs: Vec<String>,

        /// Positional target paths
        #[arg(value_name = "PATHS")]
        targets: Vec<String>,

        /// Dimension to group files by (`language`, `extension`, `source`, `directory`, `size`, `encoding`, `age`)
        #[arg(short = 'b', long = "by", value_enum, default_value_t = GroupByMode::Language)]
        by: GroupByMode,

        /// Include file mask
        #[arg(short = 'm', long = "file-mask")]
        file_mask: Option<String>,

        /// Output as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Find exact (BLAKE3/SHA-256) and fuzzy near-duplicate files across folders and inside .zip/.rar/.tar.gz archives
    #[command(alias = "duplicates")]
    Dupes {
        /// Target directories, files, or archives
        #[arg(short = 'd', long = "dir", value_name = "PATH")]
        dirs: Vec<String>,

        /// Positional target paths
        #[arg(value_name = "PATHS")]
        targets: Vec<String>,

        /// Ignore CRLF vs LF and trailing whitespace differences when hashing
        #[arg(long = "normalized")]
        normalized: bool,

        /// Also detect fuzzy near-duplicate text files using Jaccard 3-gram shingle similarity
        #[arg(long = "near")]
        near: bool,

        /// Minimum similarity ratio for `--near` (0.50 to 1.00, default: 0.80)
        #[arg(long = "similarity", default_value_t = 0.80)]
        similarity: f64,

        /// Minimum file size in bytes (default: 1)
        #[arg(long = "min-bytes", default_value_t = 1)]
        min_bytes: u64,

        /// Delete redundant disk duplicates (keeps primary copy in each exact cluster)
        #[arg(long = "delete-duplicates")]
        delete_duplicates: bool,

        /// Preview duplicate deletion without removing files
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Output as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Discover semantic intents (secrets, PII, insecure HTTP, TODOs, conflicts, localhost ports, deprecated calls) & auto-refactor
    Intent {
        /// Target directories, files, or archives
        #[arg(short = 'd', long = "dir", value_name = "PATH")]
        dirs: Vec<String>,

        /// Positional target paths
        #[arg(value_name = "PATHS")]
        targets: Vec<String>,

        /// Specific intent pack (`secrets`, `pii`, `insecure-http`, `todos`, `conflicts`, `localhost-ports`, `deprecated`, `console-debug`, or `all`)
        #[arg(short = 'p', long = "pack")]
        pack: Option<String>,

        /// Apply the intent pack's suggested refactoring across matching files
        #[arg(long = "apply")]
        apply: bool,

        /// Override the intent pack's default replacement pattern
        #[arg(short = 'r', long = "replace")]
        replace: Option<String>,

        /// Preview intent refactoring without modifying files on disk
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Output as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// List or rollback mass replacement transactions stored in `.ffrr_backups/`
    Undo {
        /// List all recorded backup transactions without rolling back
        #[arg(short = 'l', long = "list")]
        list: bool,

        /// Specific transaction ID to rollback (defaults to most recent transaction)
        #[arg(long = "tx", value_name = "TX_ID")]
        tx_id: Option<String>,
    },

    /// Generate ready-to-copy CLI commands for `ffrr`, `fnr.exe`, `ripgrep+sed`, and `PowerShell`
    GenCmd {
        #[arg(short = 'f', long = "find")]
        find: String,
        #[arg(short = 'r', long = "replace")]
        replace: Option<String>,
        #[arg(short = 'd', long = "dir", default_value = ".")]
        dir: String,
        #[arg(short = 'm', long = "file-mask", default_value = "*.*")]
        file_mask: String,
        #[arg(short = 'E', long = "regex")]
        use_regex: bool,
        #[arg(short = 's', long = "case-sensitive")]
        case_sensitive: bool,
        #[arg(short = 'P', long = "preserve-case")]
        preserve_case: bool,
    },

    /// Generate sample workspace (`samples/`) with code, configs, duplicates, UTF-16LE, and `.zip`, `.rar`, `.tar.gz`, `.gz`, `.zst` archives
    Samples {
        /// Target folder to populate with sample datasets (default: `samples`)
        #[arg(short = 'd', long = "dir", default_value = "samples")]
        dir: String,
    },

    /// Launch interactive terminal UI dashboard (Ratatui TUI)
    Tui {
        /// Initial source folder, file, or archive
        #[arg(short = 'd', long = "dir", default_value = "samples")]
        dir: String,

        /// Initial search pattern
        #[arg(short = 'f', long = "find")]
        find: Option<String>,
    },

    /// Start the HTTP REST API server and Web Studio UI (`http://127.0.0.1:8090`)
    Serve {
        /// Address and port to bind HTTP server to
        #[arg(long, default_value = "127.0.0.1:8090", value_name = "IP:PORT")]
        bind: String,

        /// Default source path to preload in FFRR Studio
        #[arg(long, value_name = "PATH")]
        source: Option<String>,
    },

    /// Launch the native cross-platform desktop application (FFRR Studio GUI)
    Gui {
        /// Default source path to preload
        #[arg(long, value_name = "PATH")]
        source: Option<String>,
    },

    /// Start Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio for AI agents & LLMs
    Mcp {
        /// Print ready-to-paste MCP server configuration JSON for Claude Desktop, Cursor, Windsurf & Devin
        #[arg(long = "config")]
        config: bool,
    },

    /// List, create, or delete user-defined replacement macros (`{{MY_MACRO}}` stored in `ffrr.macros.json`)
    Macros {
        /// Add or update a custom macro (`NAME=TEMPLATE`, e.g. `COPYRIGHT="/* 2026 {{FILE}} */ {{MATCH}}"`)
        #[arg(short = 'a', long = "add", value_name = "NAME=TEMPLATE")]
        add: Option<String>,

        /// Optional description when adding a macro
        #[arg(long = "desc", default_value = "User-defined custom macro")]
        desc: String,

        /// Remove a custom macro by name
        #[arg(short = 'r', long = "remove", value_name = "NAME")]
        remove: Option<String>,
    },

    /// Generate PowerShell, C#, Python, and cURL integration SDK wrappers
    Sdk {
        /// Target SDK (`powershell`, `csharp`, `python`, `curl`, or `all`)
        #[arg(default_value = "all")]
        target: String,
    },

    /// Manage saved SSH, SFTP, SMB, AWS S3, Azure Blob & GCS connection profiles (`@profile_name`) with OS Keychain / DPAPI / Env credential vaulting
    Connections {
        /// Add or update a named connection profile (`NAME=URI`, e.g. `prod-ssh=ssh://ubuntu@10.0.1.50:/var/log` or `logs-s3=s3://my-bucket/logs`)
        #[arg(short = 'a', long = "add", value_name = "NAME=URI")]
        add: Option<String>,

        /// Provider type (`ssh`, `sftp`, `s3`, `azure-blob`, `gcs`, `smb`)
        #[arg(short = 'p', long = "provider", default_value = "ssh")]
        provider: String,

        /// Environment variable name holding the secret/token (e.g. `AWS_SECRET_ACCESS_KEY`)
        #[arg(long = "secret-env", value_name = "ENV_VAR")]
        secret_env: Option<String>,

        /// Store a secret directly into the OS Credential Vault (macOS Keychain, Windows DPAPI, Linux secret-tool)
        #[arg(long = "vault-secret", value_name = "SECRET")]
        vault_secret: Option<String>,

        /// Optional description
        #[arg(long = "desc", default_value = "Saved remote/cloud connection profile")]
        desc: String,

        /// Remove a saved connection profile by name
        #[arg(short = 'r', long = "remove", value_name = "NAME")]
        remove: Option<String>,
    },

    /// List all detected internal drives (Full Mac HDD / Root) and connected USB / external volumes
    Drives,

    /// Display the complete reference manual & cheatsheet
    #[command(name = "help-full", alias = "manual", alias = "cheatsheet")]
    HelpFull,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConfigStore {
    default_profile: Option<String>,
    profiles: BTreeMap<String, SearchReplaceOptions>,
}

/// Preprocess legacy `fnr.exe` (`findandreplace.io`) and Windows-style CLI arguments into standard flags
fn preprocess_cli_args<I: IntoIterator<Item = String>>(raw_args: I) -> Vec<String> {
    let mut out = Vec::new();
    for arg in raw_args {
        let lower = arg.to_lowercase();
        match lower.as_str() {
            "--cl" | "/cl" | "-- includesubdirectories" | "--includesubdirectories"
            | "/includesubdirectories" | "--showencoding" | "/showencoding" => {
                // Enabled by default in FFRR; accepted silently for 100% fnr.exe drop-in script compatibility
            }
            "--dir" | "/dir" => out.push("-d".to_string()),
            "--filemask" | "/filemask" => out.push("-m".to_string()),
            "--excludefilemask" | "/excludefilemask" => out.push("-x".to_string()),
            "--excludedir" | "/excludedir" => out.push("--exclude-dir".to_string()),
            "--casesensitive" | "/casesensitive" => out.push("-s".to_string()),
            "--useregex" | "/useregex" => out.push("-E".to_string()),
            "--find" | "/find" => out.push("-f".to_string()),
            "--replace" | "/replace" => out.push("-r".to_string()),
            "--useescapechars" | "/useescapechars" => out.push("--escape".to_string()),
            "--alwaysuseencoding" | "/alwaysuseencoding" => {
                out.push("--always-use-encoding".to_string())
            }
            "--ignorebinaryfile" | "/ignorebinaryfile" => {
                // Default true
            }
            "--keepmodifieddate" | "/keepmodifieddate" => out.push("--keep-mtime".to_string()),
            "--seterrorlevelifanyfileerrors" | "/seterrorlevelifanyfileerrors" => {
                out.push("--strict-errors".to_string())
            }
            "--silent" | "/silent" => out.push("-q".to_string()),
            "--logfile" | "/logfile" => out.push("--log-file".to_string()),
            _ => {
                // Also support `--find=val` or `/find:val`
                if let Some(v) = arg.strip_prefix("--fileMask=").or_else(|| arg.strip_prefix("/fileMask:")) {
                    out.push("-m".to_string());
                    out.push(v.to_string());
                } else if let Some(v) = arg.strip_prefix("--dir=").or_else(|| arg.strip_prefix("/dir:")) {
                    out.push("-d".to_string());
                    out.push(v.to_string());
                } else if let Some(v) = arg.strip_prefix("--find=").or_else(|| arg.strip_prefix("/find:")) {
                    out.push("-f".to_string());
                    out.push(v.to_string());
                } else if let Some(v) = arg.strip_prefix("--replace=").or_else(|| arg.strip_prefix("/replace:")) {
                    out.push("-r".to_string());
                    out.push(v.to_string());
                } else {
                    out.push(arg);
                }
            }
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = preprocess_cli_args(std::env::args());
    let cli = Cli::parse_from(args);

    if cli.ascii {
        force_ascii();
    }

    // Default to 4 worker threads (low CPU / silent fan policy) unless explicitly overridden with -j / --threads
    let num_threads = cli.threads.unwrap_or(4).max(1);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global();

    if cli.list_profiles {
        let store: ConfigStore = fs::read_to_string("ffrr.config.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        println!("Saved profiles in ffrr.config.json:");
        for (name, prof) in &store.profiles {
            println!(
                "  * {} (sources: {:?}, find: {:?}, replace: {:?})",
                name, prof.traversal.sources, prof.find, prof.replace
            );
        }
        return Ok(());
    }

    match cli.command {
        Some(Commands::Group {
            mut dirs,
            targets,
            by,
            file_mask,
            json,
        }) => {
            dirs.extend(targets);
            let sources = if dirs.is_empty() {
                vec![".".to_string()]
            } else {
                dirs
            };
            let mut traversal = TraversalOptions {
                sources,
                include_archives: !cli.no_archives,
                recursive: !cli.no_recursive,
                include_hidden: cli.hidden,
                respect_gitignore: !cli.no_gitignore,
                ..Default::default()
            };
            if let Some(m) = file_mask.or(cli.file_mask) {
                traversal.file_masks = split_mask_list(&m);
            }
            let report = group_files(&traversal, by)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                if !cli.quiet {
                    eprintln!("{}", get_ascii_banner());
                }
                println!(
                    "\n{SYM_GROUP} File Grouping Report (Grouped by: {}) — {} files ({} bytes, {} lines) in {} ms",
                    report.group_by,
                    report.total_files,
                    report.total_bytes,
                    report.total_lines,
                    report.elapsed_ms
                );
                println!("{:-<96}", "");
                println!(
                    "{:<34} | {:>7} | {:>9} | {:>12} | {:>8} | {:>7}",
                    "Group / Category", "Files", "Archives", "Bytes", "Lines", "Share"
                );
                println!("{:-<96}", "");
                for g in &report.groups {
                    println!(
                        "{:<34} | {:>7} | {:>9} | {:>12} | {:>8} | {:>6.1}%",
                        g.group_key,
                        g.file_count,
                        g.archive_member_count,
                        g.total_bytes,
                        g.total_lines,
                        g.percentage_bytes
                    );
                }
                println!("{:-<96}", "");
            }
            return Ok(());
        }

        Some(Commands::Dupes {
            mut dirs,
            targets,
            normalized,
            near,
            similarity,
            min_bytes,
            delete_duplicates,
            dry_run,
            json,
        }) => {
            dirs.extend(targets);
            let sources = if dirs.is_empty() {
                vec![".".to_string()]
            } else {
                dirs
            };
            let traversal = TraversalOptions {
                sources,
                include_archives: !cli.no_archives,
                recursive: !cli.no_recursive,
                include_hidden: cli.hidden,
                respect_gitignore: !cli.no_gitignore,
                ..Default::default()
            };
            let dopts = DuplicateOptions {
                traversal,
                normalized_whitespace: normalized,
                near_duplicates: near,
                similarity_threshold: similarity,
                min_bytes,
                delete_duplicates,
                dry_run: dry_run || cli.dry_run,
            };
            let report = find_duplicates(&dopts)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                if !cli.quiet {
                    eprintln!("{}", get_ascii_banner());
                }
                println!(
                    "\n{SYM_DUP} Duplicate & Near-Duplicate Report — Scanned {} files in {} ms",
                    report.total_files_scanned, report.elapsed_ms
                );
                println!(
                    "  Exact Clusters: {} | Near-Duplicate Clusters: {} | Redundant Files: {} | Wasted Bytes: {} B",
                    report.exact_clusters,
                    report.near_clusters,
                    report.total_duplicate_files,
                    report.total_wasted_bytes
                );
                println!("{:-<96}", "");
                for (i, c) in report.clusters.iter().enumerate() {
                    println!(
                        "Cluster #{} [{}] — BLAKE3: {} | Size: {} B | Wasted: {} B",
                        i + 1,
                        c.match_kind,
                        c.hash_blake3,
                        c.file_size_bytes,
                        c.wasted_bytes
                    );
                    for f in &c.files {
                        let tag = if f.is_primary {
                            "PRIMARY  "
                        } else if f.deleted {
                            "DELETED  "
                        } else {
                            "DUPLICATE"
                        };
                        println!("  [{}] {} ({})", tag, f.path, f.archive_kind);
                    }
                }
            }
            return Ok(());
        }

        Some(Commands::Intent {
            mut dirs,
            targets,
            pack,
            apply,
            replace,
            dry_run,
            json,
        }) => {
            dirs.extend(targets);
            let sources = if dirs.is_empty() {
                vec![".".to_string()]
            } else {
                dirs
            };
            let traversal = TraversalOptions {
                sources,
                include_archives: !cli.no_archives,
                recursive: !cli.no_recursive,
                include_hidden: cli.hidden,
                respect_gitignore: !cli.no_gitignore,
                ..Default::default()
            };

            if apply {
                let pack_id = pack.as_deref().unwrap_or("insecure-http");
                let summary =
                    execute_intent_pack(&traversal, pack_id, replace, dry_run || cli.dry_run)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    render_search_summary(&summary, OutputFormat::Table, true, false, false, cli.quiet);
                }
            } else {
                let report = analyze_intents(&traversal, pack.as_deref())?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    if !cli.quiet {
                        eprintln!("{}", get_ascii_banner());
                    }
                    println!(
                        "\n{SYM_INTENT} Context & Intent Discovery — Scanned {} files in {} ms ({} findings)",
                        report.total_files_scanned, report.elapsed_ms, report.total_findings
                    );
                    println!("{:-<96}", "");
                    for f in &report.findings {
                        println!(
                            "[{}] {} ({}) — {} matches across {} files",
                            f.severity, f.title, f.pack_id, f.total_matches, f.affected_files
                        );
                        println!("  Description:       {}", f.description);
                        println!("  Suggested Replace: `{}` (run `ffrr intent --pack {} --apply --dry-run`)", f.suggested_replace, f.pack_id);
                        for s in f.sample_matches.iter().take(4) {
                            let ctx = s
                                .semantic_context
                                .as_deref()
                                .map(|c| format!(" [in `{}`]", c))
                                .unwrap_or_default();
                            println!(
                                "    * {}:{}{} -> `{}`",
                                s.file, s.line_number, ctx, s.matched_text
                            );
                        }
                        println!();
                    }
                }
            }
            return Ok(());
        }

        Some(Commands::Undo { list, tx_id }) => {
            if list {
                let manifests = TransactionManager::list_transactions()?;
                if manifests.is_empty() {
                    println!("No backup transactions found in .ffrr_backups/");
                } else {
                    println!("Recorded Backup Transactions (.ffrr_backups/):");
                    for m in manifests {
                        println!(
                            "  * {} ({}) — Find: {:?} -> Replace: {:?} ({} files)",
                            m.transaction_id,
                            m.timestamp_utc,
                            m.find_pattern,
                            m.replace_pattern,
                            m.files.len()
                        );
                    }
                }
            } else {
                let (manifest, restored) = TransactionManager::undo_transaction(tx_id.as_deref())?;
                println!(
                    "{SYM_OK} Rolled back transaction `{}` — Restored {} file(s) to their original state.",
                    manifest.transaction_id, restored
                );
            }
            return Ok(());
        }

        Some(Commands::GenCmd {
            find,
            replace,
            dir,
            file_mask,
            use_regex,
            case_sensitive,
            preserve_case,
        }) => {
            let opts = SearchReplaceOptions {
                traversal: TraversalOptions {
                    sources: vec![dir],
                    file_masks: split_mask_list(&file_mask),
                    ..Default::default()
                },
                find,
                replace,
                use_regex,
                case_sensitive,
                preserve_case,
                ..Default::default()
            };
            let eq = generate_cli_equivalents(&opts);
            println!("# 1. Modern FFRR CLI:");
            println!("{}\n", eq.ffrr_cmd);
            println!("# 2. Classic fnr.exe (findandreplace.io) CLI:");
            println!("{}\n", eq.fnr_exe_cmd);
            println!("# 3. Linux/macOS ripgrep + sed pipeline:");
            println!("{}\n", eq.unix_cmd);
            println!("# 4. Windows PowerShell command:");
            println!("{}", eq.powershell_cmd);
            return Ok(());
        }

        Some(Commands::Samples { dir }) => {
            generate_sample_workspace(Path::new(&dir))?;
            println!(
                "{SYM_OK} Generated multi-source & multi-archive sample workspace in `{}` (.zip, .rar, .tar.gz, .gz, .zst, UTF-16LE, configs, source code, and duplicates).",
                dir
            );
            return Ok(());
        }

        Some(Commands::Tui { dir, find }) => {
            return tui::run_tui(&dir, find);
        }

        Some(Commands::Serve { bind, source }) => {
            return server::run_http_server(&bind, source).await;
        }

        Some(Commands::Gui { source }) => {
            return gui::launch_native_desktop_gui(source);
        }

        Some(Commands::Mcp { config }) => {
            if config {
                let exe_path = std::env::current_exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "ffrr".to_string());
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "mcpServers": {
                            "ffrr": {
                                "command": exe_path,
                                "args": ["mcp"],
                                "description": "FFRR High-Speed Find, Replace, Archive Search, File Reader & Duplicate Engine"
                            }
                        }
                    }))?
                );
                return Ok(());
            }
            return mcp::run_mcp_stdio_server();
        }

        Some(Commands::Macros { add, desc, remove }) => {
            if let Some(rem) = remove {
                let list = delete_custom_macro(&rem)?;
                println!("{SYM_OK} Removed macro `{}`. Remaining custom macros: {}", rem, list.len());
                return Ok(());
            }
            if let Some(spec) = add {
                if let Some((name, tpl)) = spec.split_once('=') {
                    save_custom_macro(name, tpl, &desc)?;
                    println!(
                        "{SYM_OK} Saved custom macro `{{{{{}}}}}` -> `{}` in ffrr.macros.json",
                        name.trim().to_uppercase(),
                        tpl
                    );
                } else {
                    anyhow::bail!("Use format: ffrr macros --add NAME=\"template\"");
                }
            }
            println!("{SYM_ROCKET} Built-In & Custom Replacement Macros:");
            println!("  Built-in: {{{{UPPER}}}}, {{{{LOWER}}}}, {{{{SNAKE}}}}, {{{{CAMEL}}}}, {{{{PASCAL}}}}, {{{{KEBAB}}}}, {{{{SHA256}}}}, {{{{BLAKE3}}}}, {{{{REDACT}}}}, {{{{BASE64}}}}, {{{{FILE}}}}, {{{{LINE}}}}, {{{{MATCH_INDEX}}}}, {{{{DATE}}}}, {{{{TIMESTAMP}}}}, {{{{URLENCODE}}}}, {{{{URLDECODE}}}}, {{{{REVERSE}}}}, {{{{LEN}}}}, {{{{ENV:VAR}}}}");
            println!("\n  User-Defined Custom Macros (ffrr.macros.json):");
            for m in list_custom_macros() {
                println!("    * {{{{{}}}}} => `{}` ({})", m.name, m.template, m.description);
            }
            return Ok(());
        }

        Some(Commands::Sdk { target }) => {
            print_sdk_templates(&target);
            return Ok(());
        }

        Some(Commands::Connections {
            add,
            provider,
            secret_env,
            vault_secret,
            desc,
            remove,
        }) => {
            if let Some(rem) = remove {
                let list = delete_connection_profile(&rem)?;
                println!(
                    "{SYM_OK} Removed connection profile `@{}`. Remaining: {}",
                    rem.trim_start_matches('@'),
                    list.len()
                );
                return Ok(());
            }
            if let Some(spec) = add {
                if let Some((name, uri)) = spec.split_once('=') {
                    save_connection_profile(
                        name,
                        &provider,
                        uri,
                        vault_secret.as_deref(),
                        secret_env.as_deref(),
                        &desc,
                    )?;
                    println!(
                        "{SYM_OK} Saved connection profile `@{}` -> `{}` (use `-d @{}` in any search/group/dupes command)",
                        name.trim().trim_start_matches('@'),
                        uri,
                        name.trim().trim_start_matches('@')
                    );
                } else {
                    anyhow::bail!("Use format: ffrr connections --add NAME=\"ssh://user@host:/path\"");
                }
            }
            let list = load_connection_profiles();
            println!("{SYM_ROCKET} Saved Remote & Cloud Connection Profiles (ffrr.connections.json):");
            if list.is_empty() {
                println!("  (No profiles saved yet. Add one with: ffrr connections --add prod-ssh=\"ssh://ubuntu@host:/var/log\")");
            } else {
                for c in list {
                    println!(
                        "  * @{:<16} [{}] -> {} (secret: {})",
                        c.name,
                        c.provider,
                        c.uri,
                        c.secret_ref.as_deref().unwrap_or("SSH Agent / Default CLI Auth")
                    );
                }
            }
            return Ok(());
        }

        Some(Commands::Drives) => {
            let drives = detect_system_drives();
            println!("{SYM_ROCKET} Detected System Drives & Connected USB / External Volumes:");
            println!("{:-<84}", "");
            for d in &drives {
                println!("  [{:<8}] {:<36} -> {}", d.kind.to_uppercase(), d.name, d.path);
            }
            println!("{:-<84}", "");
            println!("Example (Search Full Mac HDD + Connected USB Drive simultaneously):");
            let usb_example = drives
                .iter()
                .find(|d| d.kind == "usb")
                .map(|d| d.path.as_str())
                .unwrap_or("/Volumes/MyUSB");
            println!("  ffrr -f \"pattern\" -d \"/\" -d {:?}", usb_example);
            println!("  ffrr dupes -d \"/Users/sunil\" -d {:?}", usb_example);
            return Ok(());
        }

        Some(Commands::HelpFull) => {
            print_full_manual();
            return Ok(());
        }

        None => {}
    }

    // Default command: Find & Replace execution
    let mut sources: Vec<String> = cli
        .dirs
        .iter()
        .flat_map(|s| s.split(';').map(|p| p.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    sources.extend(cli.positional_paths.clone());
    if sources.is_empty() {
        sources.push(".".to_string());
    }

    let find_pattern = cli.find.or(cli.positional_pattern).unwrap_or_default();
    if find_pattern.is_empty() && cli.profile.is_none() {
        println!("{}", get_ascii_banner());
        println!("\nQuick Start Examples:");
        println!("  ffrr -f \"http://\" -r \"https://\" -d samples --dry-run       # Preview find & replace across folders & archives");
        println!("  ffrr \"TODO\" samples/                                       # Fast multi-threaded ripgrep-style search (incl. .zip/.rar/.gz)");
        println!("  ffrr -f \"user_id\" -r \"account_id\" -P --scope code -d src   # Case-preserving code-only refactor");
        println!("  ffrr --cl --dir samples --fileMask \"*.*\" --find \"ERROR\"    # 100% fnr.exe drop-in CLI compatibility");
        println!("  ffrr group -d samples --by language                        # Group files by language, encoding, size, or archive");
        println!("  ffrr dupes -d samples --near --normalized                  # Find exact & fuzzy near-duplicate files");
        println!("  ffrr intent -d samples                                     # Scan for secrets, PII, HTTP URLs, TODOs & conflicts");
        println!("  ffrr serve --bind 127.0.0.1:8090                           # Launch FFRR Web Studio UI & REST API");
        println!("  ffrr tui                                                   # Launch Interactive Terminal Dashboard");
        println!("  ffrr help-full                                             # Full manual & cheatsheet");
        return Ok(());
    }

    let mut traversal = TraversalOptions {
        sources,
        recursive: !cli.no_recursive,
        include_archives: !cli.no_archives,
        include_hidden: cli.hidden,
        respect_gitignore: !cli.no_gitignore,
        min_size: cli.min_size,
        max_size: cli.max_size,
        ..Default::default()
    };
    if let Some(ref m) = cli.file_mask {
        traversal.file_masks = split_mask_list(m);
    }
    if let Some(ref x) = cli.exclude_mask {
        traversal.exclude_masks = split_mask_list(x);
    }
    if let Some(ref ed) = cli.exclude_dir {
        traversal.exclude_dirs = split_mask_list(ed);
    }

    let ctx_before = cli.context.unwrap_or(cli.before_context);
    let ctx_after = cli.context.unwrap_or(cli.after_context);

    let search_target = if cli.filename_only {
        "filename".to_string()
    } else if cli.content_only {
        "content".to_string()
    } else {
        "both".to_string()
    };

    let mut opts = SearchReplaceOptions {
        traversal,
        find: find_pattern,
        replace: cli.replace,
        search_target,
        use_regex: cli.use_regex && !cli.fixed_strings,
        case_sensitive: cli.case_sensitive,
        smart_case: !cli.case_sensitive && !cli.ignore_case,
        whole_word: cli.whole_word,
        multiline: cli.multiline,
        use_escape_chars: cli.use_escape_chars,
        preserve_case: cli.preserve_case,
        invert_match: cli.invert_match,
        ignore_binary: !cli.binary_text,
        forced_encoding: cli.encoding,
        always_use_encoding: cli.always_use_encoding,
        show_encoding: true,
        keep_mtime: cli.keep_mtime,
        dry_run: cli.dry_run,
        create_backup: !cli.no_backup,
        context_before: ctx_before,
        context_after: ctx_after,
        semantic_context: true,
        scope: cli.scope,
        max_matches_per_file: None,
    };

    if let Some(ref prof_name) = cli.profile {
        if let Ok(raw) = fs::read_to_string("ffrr.config.json") {
            if let Ok(store) = serde_json::from_str::<ConfigStore>(&raw) {
                if let Some(saved) = store.profiles.get(prof_name) {
                    opts = saved.clone();
                }
            }
        }
    }

    if let Some(ref save_name) = cli.save_profile {
        let mut store: ConfigStore = fs::read_to_string("ffrr.config.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        store.profiles.insert(save_name.clone(), opts.clone());
        fs::write("ffrr.config.json", serde_json::to_string_pretty(&store)?)?;
    }

    let summary = run_search_replace(&opts)?;

    if let Some(ref log_path) = cli.log_file {
        let log_text = format!(
            "FFRR Execution Log\nScanned: {} files ({} archive entries) in {} ms\nMatches: {} across {} files | Replacements: {} (dry_run={})\n",
            summary.total_files_scanned,
            summary.archive_entries_scanned,
            summary.elapsed_ms,
            summary.total_matches,
            summary.files_with_matches,
            summary.total_replacements,
            summary.dry_run
        );
        let _ = fs::write(log_path, log_text);
    }

    let eff_output = if cli.show_diff {
        OutputFormat::Diff
    } else if cli.files_with_matches {
        OutputFormat::Files
    } else {
        cli.output_format
    };

    render_search_summary(
        &summary,
        eff_output,
        cli.show_diff,
        cli.count_only,
        cli.files_with_matches,
        cli.quiet,
    );

    if cli.strict_errors && summary.results.iter().any(|r| r.error.is_some()) {
        std::process::exit(2);
    }

    Ok(())
}

fn render_search_summary(
    summary: &SearchReplaceSummary,
    format: OutputFormat,
    show_diff: bool,
    count_only: bool,
    files_only: bool,
    quiet: bool,
) {
    if count_only {
        println!("{}", summary.total_matches);
        return;
    }

    if files_only || format == OutputFormat::Files {
        for r in &summary.results {
            println!("{}", r.path);
        }
        return;
    }

    match format {
        OutputFormat::Files => {}
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(summary).unwrap_or_default()
            );
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            let _ = wtr.write_record([
                "file",
                "archive_kind",
                "encoding",
                "line",
                "column",
                "scope",
                "semantic_context",
                "line_text",
                "replaced_line_text",
            ]);
            for r in &summary.results {
                for m in &r.matches {
                    let _ = wtr.write_record([
                        &r.path,
                        &r.archive_kind,
                        &r.encoding,
                        &m.line_number.to_string(),
                        &m.column.to_string(),
                        &m.scope_kind,
                        m.semantic_context.as_deref().unwrap_or(""),
                        &m.line_text,
                        m.replaced_line_text.as_deref().unwrap_or(""),
                    ]);
                }
            }
            let _ = wtr.flush();
        }
        OutputFormat::Compact => {
            for r in &summary.results {
                for m in &r.matches {
                    println!("{}:{}:{}:{}", r.path, m.line_number, m.column, m.line_text);
                }
            }
        }
        OutputFormat::Diff => {
            for r in &summary.results {
                if let Some(ref diff) = r.unified_diff {
                    print!("{}", diff);
                }
            }
        }
        OutputFormat::Table => {
            if !quiet {
                eprintln!("{}", get_ascii_banner());
            }
            for r in &summary.results {
                println!(
                    "\n{SYM_SEARCH} {} [{}] (Encoding: {}, Size: {} B, Matches: {}{})",
                    r.path,
                    r.archive_kind,
                    r.encoding,
                    r.size_bytes,
                    r.match_count,
                    if r.modified_on_disk {
                        ", MODIFIED"
                    } else if r.replaced_count > 0 && summary.dry_run {
                        ", DRY-RUN PREVIEW"
                    } else {
                        ""
                    }
                );
                for m in &r.matches {
                    for b in &m.context_before {
                        println!("      {:>5} |   {}", b.line_number, b.line_text);
                    }
                    let ctx_badge = m
                        .semantic_context
                        .as_deref()
                        .map(|c| format!(" [{}]", c))
                        .unwrap_or_default();
                    println!(
                        "  {SYM_ARROW} {:>5}:{:<3} [{}]{} {}",
                        m.line_number, m.column, m.scope_kind, ctx_badge, m.line_text
                    );
                    if let Some(ref repl) = m.replaced_line_text {
                        println!("  {SYM_REPLACE} {:>5}     => {}", m.line_number, repl);
                    }
                    for a in &m.context_after {
                        println!("      {:>5} |   {}", a.line_number, a.line_text);
                    }
                }
                if show_diff {
                    if let Some(ref diff) = r.unified_diff {
                        println!("{}", diff);
                    }
                }
            }

            if !quiet {
                eprintln!("\n{:-<84}", "");
                eprintln!(
                    "{SYM_DONE} Scanned {} files ({} archive entries, {} binary skipped) in {} ms",
                    summary.total_files_scanned,
                    summary.archive_entries_scanned,
                    summary.binary_files_skipped,
                    summary.elapsed_ms
                );
                eprintln!(
                    "       Matched {} occurrence(s) across {} file(s) | Replacements: {} ({})",
                    summary.total_matches,
                    summary.files_with_matches,
                    summary.total_replacements,
                    if summary.dry_run {
                        "dry-run preview"
                    } else {
                        "written to disk"
                    }
                );
                if let Some(ref tx) = summary.transaction_id {
                    eprintln!(
                        "       Backup Transaction ID: `{}` (run `ffrr undo` to rollback)",
                        tx
                    );
                }
            }
        }
    }
}

pub fn generate_sample_workspace(root: &Path) -> Result<()> {
    let config_dir = root.join("config");
    let src_dir = root.join("src_code");
    let dupes_dir = root.join("duplicates");
    let arc_dir = root.join("archives");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&dupes_dir)?;
    fs::create_dir_all(&arc_dir)?;

    // 1. Config files (JSON, YAML, .env, UTF-16LE Windows config)
    fs::write(
        config_dir.join("appsettings.json"),
        r#"{
  "ServiceName": "PaymentGateway",
  "ApiEndpoint": "http://api.internal-payments.example.com/v1/charge",
  "WebhookUrl": "http://hooks.example.com/notify",
  "BindAddress": "localhost:8080",
  "LegacyUserId": "legacy_user_id",
  "ApiKey": "sk-live9876543210abcdef123456",
  "SupportEmail": "ops-alerts@example.com"
}
"#,
    )?;

    fs::write(
        config_dir.join("deployment.yaml"),
        r#"# Production deployment configuration
# TODO: Migrate http:// endpoints to https:// before Q4 audit
service:
  name: order-worker
  upstream_url: "http://orders.internal.example.com/api"
  bind_host: "127.0.0.1:9090"
  admin_contact: "secops@example.com"
"#,
    )?;

    // UTF-16LE encoded Windows configuration file
    let utf16_text = "[Database]\r\nConnectionString=http://sql-legacy.example.com:1433\r\nLegacyUserId=legacy_user_id\r\n";
    let utf16_bytes = crate::archive::encode_text(utf16_text, crate::archive::FileEncoding::Utf16Le);
    fs::write(config_dir.join("win_service_utf16.ini"), utf16_bytes)?;

    // 2. Source code files (Rust, Python, TypeScript)
    fs::write(
        src_dir.join("auth_service.rs"),
        r#"// Authentication & User Identity Service
// TODO: Replace legacy_user_id with account_id across all handlers

pub struct UserSession {
    pub legacy_user_id: String,
    pub LegacyUserId: u64,
    pub LEGACY_USER_ID: &'static str,
}

pub fn verify_token(legacy_user_id: &str) -> bool {
    let endpoint = "http://auth.example.com/verify";
    // Note: legacy_user_id inside comment can be filtered out with --scope code
    println!("Verifying {} against {}", legacy_user_id, endpoint);
    !legacy_user_id.is_empty()
}
"#,
    )?;

    fs::write(
        src_dir.join("worker.py"),
        r#"# Background sync worker
# FIXME: remove hardcoded token and upgrade http:// URL

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def sync_records(legacy_user_id: str):
    target_url = "http://sync.example.com/v2/ingest"
    return f"{target_url}?user={legacy_user_id}"
"#,
    )?;

    // 3. Exact & Near-Duplicate files
    let dup_content_a = "server_host=10.0.0.12\nserver_port=8080\ntimeout_ms=5000\nretry_count=3\nmode=production\n";
    fs::write(dupes_dir.join("node_config_primary.conf"), dup_content_a)?;
    fs::write(dupes_dir.join("node_config_backup_copy.conf"), dup_content_a)?;
    // CRLF whitespace-normalized duplicate
    fs::write(
        dupes_dir.join("node_config_windows_crlf.conf"),
        "server_host=10.0.0.12\r\nserver_port=8080  \r\ntimeout_ms=5000\r\nretry_count=3\r\nmode=production\r\n",
    )?;
    // Near-duplicate (90%+ token shingle overlap)
    let near_a = "fn process_order(order_id: u64, customer_id: u64, amount_cents: u64, currency: &str) -> bool {\n    if amount_cents == 0 { return false; }\n    let tax = amount_cents * 20 / 100;\n    let total = amount_cents + tax;\n    log_transaction(order_id, customer_id, total, currency);\n    true\n}\n";
    let near_b = "fn process_order(order_id: u64, customer_id: u64, amount_cents: u64, currency: &str) -> bool {\n    if amount_cents == 0 { return false; }\n    let tax = amount_cents * 20 / 100;\n    let total = amount_cents + tax;\n    log_transaction(order_id, customer_id, total, \"USD\");\n    true\n}\n";
    fs::write(dupes_dir.join("billing_v1.rs"), near_a)?;
    fs::write(dupes_dir.join("billing_v2_clone.rs"), near_b)?;

    // 4. Archives: .zip, .rar (RAR v5), .tar.gz, .gz, .zst
    // 4a. bundle.zip
    {
        let zip_file = File::create(arc_dir.join("bundle.zip"))?;
        let mut zip = zip::ZipWriter::new(zip_file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("zip_inner/gateway.json", opts)?;
        zip.write_all(b"{\n  \"upstream\": \"http://zip-service.example.com/api\",\n  \"legacy_user_id\": \"USR-900\"\n}\n")?;
        zip.start_file("zip_inner/node_config_in_zip.conf", opts)?;
        zip.write_all(dup_content_a.as_bytes())?;
        zip.finish()?;
    }

    // 4b. legacy_pack.rar (RAR v5 archive)
    create_rar5_archive(
        &arc_dir.join("legacy_pack.rar"),
        &[
            (
                "rar_inner/legacy_client.cs",
                b"// C# Client inside RAR archive\npublic class LegacyClient {\n    public string Endpoint = \"http://rar-api.example.com/v1\";\n    public string legacy_user_id = \"RAR-42\";\n}\n",
            ),
            (
                "rar_inner/rar_settings.ini",
                b"[Server]\nUrl=http://rar-backup.example.com/status\n",
            ),
        ],
    )?;

    // 4c. release.tar.gz (POSIX tar inside gzip)
    {
        let tar_gz_file = File::create(arc_dir.join("release.tar.gz"))?;
        let mut gz = GzEncoder::new(tar_gz_file, flate2::Compression::default());
        let tar_bytes = build_simple_tar(&[(
            "tar_inner/manifest.yaml",
            b"release: 1.0\ndownload_url: http://tar-mirror.example.com/pkg.tar.gz\nlegacy_user_id: tar_admin\n",
        )]);
        gz.write_all(&tar_bytes)?;
        gz.finish()?;
    }

    // 4d. app.log.gz
    {
        let gz_file = File::create(arc_dir.join("app.log.gz"))?;
        let mut gz = GzEncoder::new(gz_file, flate2::Compression::default());
        gz.write_all(b"2026-10-19T10:00:01Z INFO Connecting to http://gz-log-endpoint.example.com/stream user=legacy_user_id\n")?;
        gz.finish()?;
    }

    // 4e. audit.log.zst
    {
        let zst_file = File::create(arc_dir.join("audit.log.zst"))?;
        let mut zst = zstd::stream::write::Encoder::new(zst_file, 3)?;
        zst.write_all(b"2026-10-19T10:05:00Z WARN Insecure callback http://zst-audit.example.com/hook user=legacy_user_id\n")?;
        zst.finish()?;
    }

    Ok(())
}

fn build_simple_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(99);
        header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        let size_octal = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[136..148].copy_from_slice(b"14716000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let cksum: u32 = header.iter().map(|&b| b as u32).sum();
        let ck_str = format!("{:06o}\0 ", cksum);
        header[148..156].copy_from_slice(ck_str.as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat(0u8).take(512 - rem));
        }
    }
    out.extend(std::iter::repeat(0u8).take(1024));
    out
}

fn print_sdk_templates(target: &str) {
    let t = target.to_lowercase();
    if t == "all" || t == "powershell" || t == "ps" {
        println!(
            r#"# ==============================================================================
# PowerShell Integration Wrapper for FFRR
# ==============================================================================
function Invoke-FfrrSearch {{
    param(
        [Parameter(Mandatory=$true)][string]$Find,
        [string]$Replace = "",
        [string]$Dir = ".",
        [string]$FileMask = "*.*",
        [switch]$Regex,
        [switch]$PreserveCase,
        [switch]$DryRun
    )
    $argsList = @("-f", $Find, "-d", $Dir, "-m", $FileMask, "-o", "json", "-q")
    if ($Replace -ne "") {{ $argsList += @("-r", $Replace) }}
    if ($Regex) {{ $argsList += "-E" }}
    if ($PreserveCase) {{ $argsList += "-P" }}
    if ($DryRun) {{ $argsList += "--dry-run" }}
    $raw = & ffrr @argsList
    return ($raw | ConvertFrom-Json)
}}"#
        );
    }
    if t == "all" || t == "csharp" || t == "dotnet" {
        println!(
            r#"
// ==============================================================================
// .NET / C# Client for FFRR REST API (`ffrr serve --bind 127.0.0.1:8090`)
// ==============================================================================
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class FfrrClient {{
    private readonly HttpClient _http = new HttpClient();
    private readonly string _baseUrl;
    public FfrrClient(string baseUrl = "http://127.0.0.1:8090") => _baseUrl = baseUrl;

    public async Task<string> SearchAndReplaceAsync(string source, string find, string? replace = null, bool dryRun = true) {{
        var payload = JsonSerializer.Serialize(new {{ source, find, replace, dry_run = dryRun }});
        var res = await _http.PostAsync($"{{_baseUrl}}/v1/search", new StringContent(payload, Encoding.UTF8, "application/json"));
        return await res.Content.ReadAsStringAsync();
    }}
}}"#
        );
    }
    if t == "all" || t == "curl" {
        println!(
            r#"
# ==============================================================================
# cURL REST API Examples (`ffrr serve --bind 127.0.0.1:8090`)
# ==============================================================================
curl -s -X POST http://127.0.0.1:8090/v1/search \
  -H "Content-Type: application/json" \
  -d '{{"source":"samples","find":"http://","replace":"https://","dry_run":true}}'

curl -s -X POST http://127.0.0.1:8090/v1/group \
  -H "Content-Type: application/json" \
  -d '{{"source":"samples","group_by":"language"}}'

curl -s -X POST http://127.0.0.1:8090/v1/duplicates \
  -H "Content-Type: application/json" \
  -d '{{"source":"samples","near_duplicates":true,"normalized_whitespace":true}}'"#
        );
    }
}

fn print_full_manual() {
    println!("{}", get_ascii_banner());
    print!(
        r#"
====================================================================================
FFRR COMPLETE REFERENCE MANUAL — ALL CLI SWITCHES, SUBCOMMANDS & INTEGRATIONS
====================================================================================

1. CORE FIND & REPLACE SWITCHES (MODERN + LINUX/MACOS FLAGS)
   ---------------------------------------------------------------------------------
   -f, --find <PATTERN>          Text or regular expression to find (or 1st positional arg)
   -r, --replace <TEXT>          Replacement string (omit for Find-Only mode)
   -d, --dir <PATH_OR_URI>       Target folder, file, archive, @profile, or remote URI
                                 (Repeat `-d` or separate with `;`, e.g. `-d "src;/Volumes/USB"`)
   -m, --file-mask <MASKS>       Include file masks, comma/semicolon separated (`"*.rs,*.json"`)
   -x, --exclude-mask <MASKS>    Exclude file masks (`"*.dll,*.exe,*.min.js"`)
       --exclude-dir <DIRS>      Exclude directory names (`.git,node_modules,target`)
       --no-recursive            Do not traverse subdirectories (default: recursive ON)
       --no-archives             Do not search inside `.zip/.rar/.tar.gz/.gz/.zst` archives
       --hidden                  Include hidden dot-files and dot-directories
       --no-gitignore            Ignore `.gitignore` and `.ignore` rules
       --min-size <BYTES>        Only scan files >= BYTES
       --max-size <BYTES>        Only scan files <= BYTES

2. MATCHING, CASE, REGEX & SCOPE SWITCHES
   ---------------------------------------------------------------------------------
   -E, --regex                   Enable regular expression matching (`$1`, `${{name}}` captures)
   -F, --fixed-strings           Force literal fixed-string matching
   -s, --case-sensitive          Force case-sensitive matching
   -i, --ignore-case             Force case-insensitive matching (default: Smart Case)
   -w, --word-regexp             Match whole words only (`\b...\b`)
   -P, --preserve-case           Smart case-preserving replacement:
                                 `legacy_id` -> `account_id`, `LegacyId` -> `AccountId`,
                                 `LEGACY_ID` -> `ACCOUNT_ID`, `legacyId` -> `accountId`
   -U, --multiline               Allow `.` and patterns to match across line breaks
       --escape                  Interpret `\n`, `\r`, `\t`, `\xHH` in find & replace strings
   -v, --invert-match            Select non-matching lines
       --filename-only           Instant Filename/Path-only search (0 content bytes read)
       --content-only            Search only inside file contents (ignore filename matches)
       --scope <SCOPE>           Lexical context scope filter:
                                   * `all`      : Match anywhere in file (default)
                                   * `code`     : Executable code only (skips comments & strings)
                                   * `comments` : Inside comments only (`//`, `#`, `/* */`)
                                   * `strings`  : Inside quoted string literals only
                                   * `keys`     : Config keys only (left of `:` or `=`)
                                   * `values`   : Config values only (right of `:` or `=`)

3. OUTPUT, PREVIEW, ENCODING & EXECUTION SWITCHES
   ---------------------------------------------------------------------------------
   -n, --dry-run                 Preview replacements without modifying files on disk
       --diff                    Print unified diff (`--- a/file` / `+++ b/file`)
       --no-backup               Skip creating `.ffrr_backups/<tx_id>/` undo snapshot
   -a, --binary-text             Search binary files as text instead of skipping them
       --encoding <ENC>          Force encoding (`utf-8`, `utf-8-bom`, `utf-16le`, `utf-16be`,
                                 `windows-1252`, `ascii`)
       --always-use-encoding     Use forced encoding even if BOM header is present
       --keep-mtime              Preserve original file modification date/time on replace
       --strict-errors           Exit with code 2 if any file read/write error occurs
   -B, --before-context <N>      Print N lines of leading context before each match
   -A, --after-context <N>       Print N lines of trailing context after each match
   -C, --context <N>             Print N lines of leading and trailing context
   -c, --count                   Print only the total match count
   -l, --files-with-matches      Print only matching file paths
   -o, --output <FORMAT>         Output format (`table`, `compact`, `diff`, `json`, `csv`, `files`)
   -j, --threads <N>             Number of parallel Rayon worker threads (default: 4)
       --log-file <PATH>         Write execution summary log to PATH
   -q, --quiet                   Suppress startup banner and summary footer
       --ascii                   Force plain 7-bit ASCII badges
       --profile <NAME>          Load saved search profile from `ffrr.config.json`
       --save-profile <NAME>     Save current options to `ffrr.config.json`
       --list-profiles           List all saved profiles in `ffrr.config.json`

4. 100% DROP-IN CLASSIC `fnr.exe` (findandreplace.io) SWITCHES
   ---------------------------------------------------------------------------------
   Accepted directly without modification:
   `--cl`, `--dir`, `--fileMask`, `--excludeFileMask`, `--excludeDir`,
   `--includeSubDirectories`, `--caseSensitive`, `--useRegEx`, `--find`, `--replace`,
   `--useEscapeChars`, `--encoding`, `--alwaysUseEncoding`, `--showEncoding`,
   `--ignoreBinaryFile`, `--KeepModifiedDate`, `--setErrorLevelIfAnyFileErrors`,
   `--silent`, `--logFile` (both `--flag` and Windows `/flag` styles supported).

5. BUILT-IN & CUSTOM REPLACEMENT MACROS (`--replace` / `ffrr macros`)
   ---------------------------------------------------------------------------------
   {{{{UPPER}}}}       Uppercase matched text      {{{{LOWER}}}}       Lowercase matched text
   {{{{SNAKE}}}}       snake_case conversion       {{{{CAMEL}}}}       camelCase conversion
   {{{{PASCAL}}}}      PascalCase conversion       {{{{KEBAB}}}}       kebab-case conversion
   {{{{SHA256}}}}      Deterministic 16-hex hash   {{{{BLAKE3}}}}      BLAKE3 16-hex hash
   {{{{REDACT}}}}      Smart prefix-preserving mask {{{{BASE64}}}}     Base64 encode match
   {{{{FILE}}}}        Current filename            {{{{LINE}}}}        1-based line number
   {{{{MATCH_INDEX}}}} Match counter in file       {{{{LEN}}}}         Character length of match
   {{{{DATE}}}}        UTC date (YYYY-MM-DD)       {{{{TIMESTAMP}}}}   ISO-8601 UTC timestamp
   {{{{URLENCODE}}}}   URL-percent encode          {{{{URLDECODE}}}}   URL-percent decode
   {{{{REVERSE}}}}     Reverse characters          {{{{ENV:VAR}}}}     Environment variable value
   {{{{CUSTOM_NAME}}}} Any user-defined macro saved via `ffrr macros --add NAME="template"`

6. ARCHIVES, DRIVES & REMOTE / CLOUD URI SOURCES
   ---------------------------------------------------------------------------------
   * Archives : `.zip`, `.rar` (RAR4/RAR5), `.tar.gz`/`.tgz`, `.tar`, `.tar.zst`, `.tar.bz2`, `.gz`, `.zst`, `.bz2`
   * SSH/SFTP : `ssh://user@host[:port]/path` or `sftp://user@host[:port]/path`
   * SMB/UNC  : `smb://server/share/path` or `\\server\share\path`
   * AWS S3   : `s3://bucket/prefix` (also MinIO / Cloudflare R2)
   * Azure    : `az://container/prefix` or `abfs://container@account/prefix`
   * GCP GCS  : `gs://bucket/prefix`
   * HTTPS    : `https://example.com/file.log` (or Pre-Signed S3 / Azure SAS URL)
   * Profiles : `@profile_name` (saved via `ffrr connections --add name=uri`)

7. SUBCOMMANDS
   ---------------------------------------------------------------------------------
   ffrr group -d <PATH> --by <language|extension|source|directory|size|encoding|age>
   ffrr dupes -d <PATH> [--normalized] [--near] [--similarity 0.80] [--delete-duplicates]
   ffrr intent -d <PATH> [--pack secrets|pii|insecure-http|todos|conflicts|localhost-ports|deprecated|console-debug] [--apply]
   ffrr undo [--list] [--tx <TX_ID>]
   ffrr macros [--add NAME="template"] [--remove NAME]
   ffrr connections [--add NAME="uri"] [--provider ssh|s3|az|gs] [--secret-env VAR] [--vault-secret SEC]
   ffrr drives
   ffrr gen-cmd -f "old" -r "new" -d src -m "*.rs"
   ffrr samples [-d samples]
   ffrr tui [-d samples]
   ffrr serve [--bind 127.0.0.1:8090]
   ffrr gui
   ffrr mcp [--config]
   ffrr sdk [powershell|csharp|curl|all]
   ffrr help-full
"#
    );
}
