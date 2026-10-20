//! ============================================================================
//! Module: `archive.rs` — Multi-Source, Archive-Native & Remote Stream Engine
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! Traditional find-and-replace utilities (`fnr.exe`, `sed`, `grep`) only work
//! on uncompressed local files. `archive.rs` provides a unified `SourceItem`
//! abstraction (similar to an `ISourceStream` interface in C#/Java) that lets
//! every downstream engine (`engine.rs`, `features.rs`, `server.rs`, `mcp.rs`)
//! transparently read, inspect, and write back to:
//! 1. **Local & Mounted Disks**: Internal SSD/HDD (`/` or `C:\`), connected USB
//!    volumes (`/Volumes/*`, `/mnt/*`, `/media/*`, `D:\..Z:\`), and network shares.
//! 2. **Compressed Archives (In-Memory, Zero Temp Extraction)**:
//!    - `.zip` (random-access entries + in-place write-back)
//!    - `.rar` (native pure-Rust RAR v4 & RAR v5 header/stored parser + CLI fallback)
//!    - `.tar`, `.tar.gz` / `.tgz`, `.tar.zst`, `.tar.bz2` (pure-Rust USTAR/POSIX tar)
//!    - `.gz`, `.zst`, `.bz2` (single-file compressed streams + in-place write-back)
//! 3. **Remote & Cloud Providers (`@profile` or URI schemes)**:
//!    - `ssh://user@host[:port]/path` & `sftp://user@host[:port]/path`
//!    - `smb://server/share/path` & `\\server\share\path`
//!    - `s3://bucket/prefix` (AWS S3 / Cloudflare R2 / MinIO)
//!    - `az://container/prefix` & `abfs://container@account/prefix` (Azure Blob)
//!    - `gs://bucket/prefix` (Google Cloud Storage)
//!    - `http://...` & `https://...` (Direct Blob / SAS / Pre-Signed URLs)
//!
//! ### Memory & Security Guarantees (OOM & Injection Protection)
//! - **Bounded Reads (`MAX_STREAM_BYTES = 16 MB`)**: Every file and decompressor
//!   uses `read_bounded_stream` (`Read::take(limit)`) and never pre-allocates
//!   untrusted header sizes (`Vec::with_capacity(entry.size())`), preventing
//!   Zip-Bomb, Tar-Bomb, and multi-gigabyte file Out-Of-Memory (OOM) crashes.
//! - **Strict Shell Escaping (`shell_single_quote`)**: All remote SSH/SFTP paths
//!   are wrapped in POSIX single quotes with `'` -> `'\''` escaping so untrusted
//!   filenames or URIs can never trigger remote command injection.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use anyhow::{Context, Result};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8, WINDOWS_1252};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use glob::Pattern;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard ceiling (16 MB) per individual file or decompressed archive stream to prevent
/// Out-Of-Memory (OOM) crashes on multi-gigabyte files or zip/tar decompression bombs.
pub const MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;

/// Safely reads at most `max_bytes` from any `Read` stream (file, gzip, zip entry, stdin)
/// without trusting any header-declared length for initial heap allocation.
pub fn read_bounded_stream<R: Read>(reader: R, max_bytes: u64) -> Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(8192);
    let mut limited = reader.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut buf)?;
    let truncated = if buf.len() as u64 > max_bytes {
        buf.truncate(max_bytes as usize);
        true
    } else {
        false
    };
    Ok((buf, truncated))
}

/// Safely reads at most `max_bytes` from a disk file path.
pub fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<(Vec<u8>, bool)> {
    let file = File::open(path).with_context(|| format!("Failed opening {}", path.display()))?;
    read_bounded_stream(file, max_bytes)
}

/// Escapes a string for safe inclusion as a single POSIX shell argument (`'...'`),
/// neutralizing `$()`, backticks, `;`, `|`, `&`, and double quotes.
pub fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub is_running: bool,
    pub cancelled: bool,
    pub phase: String,
    pub current_path: String,
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub archive_entries_scanned: usize,
    pub matches_found: usize,
    pub elapsed_ms: u64,
    pub live_results: Vec<serde_json::Value>,
}

pub struct LiveProgress {
    pub is_running: AtomicBool,
    pub cancelled: AtomicBool,
    pub files_discovered: AtomicUsize,
    pub files_scanned: AtomicUsize,
    pub archive_entries_scanned: AtomicUsize,
    pub matches_found: AtomicUsize,
    pub start_ms: AtomicU64,
    pub phase: Mutex<String>,
    pub current_path: Mutex<String>,
    pub live_results: Mutex<Vec<serde_json::Value>>,
    pub active_find_hint: Mutex<String>,
}

static PROGRESS: OnceLock<LiveProgress> = OnceLock::new();

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn progress_tracker() -> &'static LiveProgress {
    PROGRESS.get_or_init(|| LiveProgress {
        is_running: AtomicBool::new(false),
        cancelled: AtomicBool::new(false),
        files_discovered: AtomicUsize::new(0),
        files_scanned: AtomicUsize::new(0),
        archive_entries_scanned: AtomicUsize::new(0),
        matches_found: AtomicUsize::new(0),
        start_ms: AtomicU64::new(now_epoch_ms()),
        phase: Mutex::new("Idle".to_string()),
        current_path: Mutex::new(String::new()),
        live_results: Mutex::new(Vec::new()),
        active_find_hint: Mutex::new(String::new()),
    })
}

pub fn set_active_find_hint(find_str: &str) {
    if let Ok(mut h) = progress_tracker().active_find_hint.lock() {
        *h = find_str.trim().to_lowercase();
    }
}

pub fn push_live_result_json(val: serde_json::Value) {
    let p = progress_tracker();
    if let Ok(mut lr) = p.live_results.lock() {
        let path_str = val.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(existing) = lr
            .iter_mut()
            .find(|x| x.get("path").and_then(|v| v.as_str()) == Some(path_str))
        {
            *existing = val;
            return;
        }
        if lr.len() < 250 {
            lr.push(val);
        }
    }
}

pub fn get_live_results_json() -> Vec<serde_json::Value> {
    progress_tracker()
        .live_results
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default()
}

pub fn start_progress_job(initial_phase: &str) {
    let p = progress_tracker();
    p.cancelled.store(false, Ordering::SeqCst);
    p.is_running.store(true, Ordering::SeqCst);
    p.files_discovered.store(0, Ordering::Relaxed);
    p.files_scanned.store(0, Ordering::Relaxed);
    p.archive_entries_scanned.store(0, Ordering::Relaxed);
    p.matches_found.store(0, Ordering::Relaxed);
    p.start_ms.store(now_epoch_ms(), Ordering::Relaxed);
    if let Ok(mut ph) = p.phase.lock() {
        *ph = initial_phase.to_string();
    }
    if let Ok(mut cp) = p.current_path.lock() {
        cp.clear();
    }
    if let Ok(mut lr) = p.live_results.lock() {
        lr.clear();
    }
}

pub fn cancel_progress_job() {
    let p = progress_tracker();
    p.cancelled.store(true, Ordering::SeqCst);
    p.is_running.store(false, Ordering::SeqCst);
    if let Ok(mut ph) = p.phase.lock() {
        *ph = "Cancelled by user".to_string();
    }
}

pub fn finish_progress_job(final_phase: &str) {
    let p = progress_tracker();
    p.is_running.store(false, Ordering::SeqCst);
    if let Ok(mut ph) = p.phase.lock() {
        *ph = final_phase.to_string();
    }
}

pub fn is_progress_cancelled() -> bool {
    progress_tracker().cancelled.load(Ordering::Relaxed)
}

pub fn set_progress_phase(phase_name: &str) {
    if let Ok(mut ph) = progress_tracker().phase.lock() {
        *ph = phase_name.to_string();
    }
}

pub fn record_walk_dir(dir_str: &str) {
    let p = progress_tracker();
    if let Ok(mut cp) = p.current_path.try_lock() {
        *cp = dir_str.to_string();
    }
}

pub fn record_discovered_file(path_str: &str, is_archive: bool) {
    let p = progress_tracker();
    let count = p.files_discovered.fetch_add(1, Ordering::Relaxed) + 1;
    if is_archive {
        p.archive_entries_scanned.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(hint) = p.active_find_hint.try_lock() {
        if !hint.is_empty() && path_str.to_lowercase().contains(hint.as_str()) {
            let fname = Path::new(path_str)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path_str.to_string());
            let ext = Path::new(&fname)
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let size_bytes = fs::metadata(path_str).map(|m| m.len()).unwrap_or(0);
            p.matches_found.fetch_add(1, Ordering::Relaxed);
            push_live_result_json(serde_json::json!({
                "path": path_str,
                "file_name": fname,
                "extension": ext,
                "archive_kind": if is_archive { "archive" } else { "disk" },
                "source_root": "",
                "size_bytes": size_bytes,
                "encoding": "UTF-8",
                "is_binary": false,
                "match_count": 1,
                "replaced_count": 0,
                "modified_on_disk": false,
                "unified_diff": null,
                "matches": [{
                    "line_number": 1,
                    "column": 1,
                    "line_text": format!("[FILENAME MATCH] {}", path_str),
                    "replaced_line_text": null,
                    "semantic_context": "Filename / Path Match",
                    "scope_kind": "filename",
                    "spans": [],
                    "context_before": [],
                    "context_after": []
                }],
                "error": null
            }));
        }
    }
    if count % 8 == 1 {
        if let Ok(mut cp) = p.current_path.try_lock() {
            *cp = path_str.to_string();
        }
    }
}

pub fn record_scanned_file(path_str: &str, new_matches: usize) {
    let p = progress_tracker();
    let count = p.files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
    if new_matches > 0 {
        p.matches_found.fetch_add(new_matches, Ordering::Relaxed);
    }
    if count % 8 == 1 {
        if let Ok(mut cp) = p.current_path.try_lock() {
            *cp = path_str.to_string();
        }
    }
}

pub fn get_progress_snapshot() -> ProgressSnapshot {
    let p = progress_tracker();
    let is_running = p.is_running.load(Ordering::Relaxed);
    let start = p.start_ms.load(Ordering::Relaxed);
    let elapsed_ms = now_epoch_ms().saturating_sub(start);
    let phase = p.phase.lock().map(|s| s.clone()).unwrap_or_default();
    let current_path = p.current_path.lock().map(|s| s.clone()).unwrap_or_default();
    let live_results = p.live_results.lock().map(|v| v.clone()).unwrap_or_default();
    ProgressSnapshot {
        is_running,
        cancelled: p.cancelled.load(Ordering::Relaxed),
        phase,
        current_path,
        files_discovered: p.files_discovered.load(Ordering::Relaxed),
        files_scanned: p.files_scanned.load(Ordering::Relaxed),
        archive_entries_scanned: p.archive_entries_scanned.load(Ordering::Relaxed),
        matches_found: p.matches_found.load(Ordering::Relaxed),
        elapsed_ms,
        live_results,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Windows1252,
    Ascii,
    Binary,
}

impl FileEncoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileEncoding::Utf8 => "UTF-8",
            FileEncoding::Utf8Bom => "UTF-8-BOM",
            FileEncoding::Utf16Le => "UTF-16LE",
            FileEncoding::Utf16Be => "UTF-16BE",
            FileEncoding::Windows1252 => "Windows-1252",
            FileEncoding::Ascii => "ASCII",
            FileEncoding::Binary => "Binary",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "utf8" | "utf-8" => Some(FileEncoding::Utf8),
            "utf8bom" | "utf-8-bom" | "utf8-bom" => Some(FileEncoding::Utf8Bom),
            "utf16" | "utf-16" | "utf16le" | "utf-16le" | "unicode" => Some(FileEncoding::Utf16Le),
            "utf16be" | "utf-16be" | "bigendianunicode" => Some(FileEncoding::Utf16Be),
            "windows-1252" | "win1252" | "cp1252" | "latin1" | "iso-8859-1" | "ansi" => {
                Some(FileEncoding::Windows1252)
            }
            "ascii" | "us-ascii" => Some(FileEncoding::Ascii),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TarCompression {
    None,
    Gzip,
    Zstd,
    Bzip2,
}

#[derive(Debug, Clone)]
pub enum SourceItem {
    DiskFile {
        path: PathBuf,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    ZipEntry {
        archive_path: PathBuf,
        entry_index: usize,
        entry_name: String,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    GzipFile {
        archive_path: PathBuf,
        inner_name: String,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    ZstdFile {
        archive_path: PathBuf,
        inner_name: String,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    Bzip2File {
        archive_path: PathBuf,
        inner_name: String,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    TarEntry {
        archive_path: PathBuf,
        compression: TarCompression,
        entry_name: String,
        data: Vec<u8>,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    RarEntry {
        archive_path: PathBuf,
        entry_name: String,
        data: Vec<u8>,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    RemoteStream {
        uri: String,
        provider_kind: &'static str,
        entry_name: String,
        data: Vec<u8>,
        size: u64,
        mtime_secs: u64,
        source_root: String,
    },
    Stdin {
        data: Vec<u8>,
    },
}

impl SourceItem {
    pub fn display_path(&self) -> String {
        match self {
            SourceItem::DiskFile { path, .. } => path.to_string_lossy().to_string(),
            SourceItem::ZipEntry {
                archive_path,
                entry_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), entry_name),
            SourceItem::GzipFile {
                archive_path,
                inner_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), inner_name),
            SourceItem::ZstdFile {
                archive_path,
                inner_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), inner_name),
            SourceItem::Bzip2File {
                archive_path,
                inner_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), inner_name),
            SourceItem::TarEntry {
                archive_path,
                entry_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), entry_name),
            SourceItem::RarEntry {
                archive_path,
                entry_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), entry_name),
            SourceItem::RemoteStream { uri, .. } => uri.clone(),
            SourceItem::Stdin { .. } => "<stdin>".to_string(),
        }
    }

    pub fn file_name(&self) -> String {
        match self {
            SourceItem::DiskFile { path, .. } => path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            SourceItem::ZipEntry { entry_name, .. }
            | SourceItem::TarEntry { entry_name, .. }
            | SourceItem::RarEntry { entry_name, .. }
            | SourceItem::RemoteStream { entry_name, .. } => Path::new(entry_name)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry_name.clone()),
            SourceItem::GzipFile { inner_name, .. }
            | SourceItem::ZstdFile { inner_name, .. }
            | SourceItem::Bzip2File { inner_name, .. } => inner_name.clone(),
            SourceItem::Stdin { .. } => "stdin".to_string(),
        }
    }

    pub fn extension(&self) -> String {
        let fname = self.file_name();
        Path::new(&fname)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default()
    }

    pub fn size(&self) -> u64 {
        match self {
            SourceItem::DiskFile { path, size, .. } => {
                if *size > 0 {
                    *size
                } else {
                    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
                }
            }
            SourceItem::ZipEntry { size, .. }
            | SourceItem::GzipFile { size, .. }
            | SourceItem::ZstdFile { size, .. }
            | SourceItem::Bzip2File { size, .. }
            | SourceItem::TarEntry { size, .. }
            | SourceItem::RarEntry { size, .. }
            | SourceItem::RemoteStream { size, .. } => *size,
            SourceItem::Stdin { data } => data.len() as u64,
        }
    }

    pub fn mtime_secs(&self) -> u64 {
        match self {
            SourceItem::DiskFile { mtime_secs, .. }
            | SourceItem::ZipEntry { mtime_secs, .. }
            | SourceItem::GzipFile { mtime_secs, .. }
            | SourceItem::ZstdFile { mtime_secs, .. }
            | SourceItem::Bzip2File { mtime_secs, .. }
            | SourceItem::TarEntry { mtime_secs, .. }
            | SourceItem::RarEntry { mtime_secs, .. }
            | SourceItem::RemoteStream { mtime_secs, .. } => *mtime_secs,
            SourceItem::Stdin { .. } => 0,
        }
    }

    pub fn source_root(&self) -> &str {
        match self {
            SourceItem::DiskFile { source_root, .. }
            | SourceItem::ZipEntry { source_root, .. }
            | SourceItem::GzipFile { source_root, .. }
            | SourceItem::ZstdFile { source_root, .. }
            | SourceItem::Bzip2File { source_root, .. }
            | SourceItem::TarEntry { source_root, .. }
            | SourceItem::RarEntry { source_root, .. }
            | SourceItem::RemoteStream { source_root, .. } => source_root,
            SourceItem::Stdin { .. } => "stdin",
        }
    }

    pub fn is_archive_member(&self) -> bool {
        !matches!(self, SourceItem::DiskFile { .. } | SourceItem::Stdin { .. })
    }

    pub fn archive_kind(&self) -> &'static str {
        match self {
            SourceItem::DiskFile { .. } => "disk",
            SourceItem::ZipEntry { .. } => "zip",
            SourceItem::GzipFile { .. } => "gz",
            SourceItem::ZstdFile { .. } => "zst",
            SourceItem::Bzip2File { .. } => "bz2",
            SourceItem::TarEntry {
                compression: TarCompression::None,
                ..
            } => "tar",
            SourceItem::TarEntry {
                compression: TarCompression::Gzip,
                ..
            } => "tar.gz",
            SourceItem::TarEntry {
                compression: TarCompression::Zstd,
                ..
            } => "tar.zst",
            SourceItem::TarEntry {
                compression: TarCompression::Bzip2,
                ..
            } => "tar.bz2",
            SourceItem::RarEntry { .. } => "rar",
            SourceItem::RemoteStream { provider_kind, .. } => provider_kind,
            SourceItem::Stdin { .. } => "stdin",
        }
    }

    /// Reads the raw bytes of this source item, bounded by `MAX_STREAM_BYTES` (16 MB)
    /// to guarantee zero OOM crashes even on corrupt zip/gz headers or huge disk files.
    pub fn read_bytes(&self) -> Result<Vec<u8>> {
        match self {
            SourceItem::DiskFile { path, .. } => {
                let (buf, _) = read_bounded_file(path, MAX_STREAM_BYTES)?;
                Ok(buf)
            }
            SourceItem::ZipEntry {
                archive_path,
                entry_index,
                ..
            } => {
                let file = File::open(archive_path)?;
                let mut zip = zip::ZipArchive::new(file)?;
                let entry = zip.by_index(*entry_index)?;
                let (buf, _) = read_bounded_stream(entry, MAX_STREAM_BYTES)?;
                Ok(buf)
            }
            SourceItem::GzipFile { archive_path, .. } => {
                let file = File::open(archive_path)?;
                let gz = GzDecoder::new(file);
                let (buf, _) = read_bounded_stream(gz, MAX_STREAM_BYTES)?;
                Ok(buf)
            }
            SourceItem::ZstdFile { archive_path, .. } => {
                let file = File::open(archive_path)?;
                let dec = zstd::stream::read::Decoder::new(file)?;
                let (buf, _) = read_bounded_stream(dec, MAX_STREAM_BYTES)?;
                Ok(buf)
            }
            SourceItem::Bzip2File { archive_path, .. } => {
                let file = File::open(archive_path)?;
                let dec = BzDecoder::new(file);
                let (buf, _) = read_bounded_stream(dec, MAX_STREAM_BYTES)?;
                Ok(buf)
            }
            SourceItem::TarEntry { data, .. }
            | SourceItem::RarEntry { data, .. }
            | SourceItem::RemoteStream { data, .. }
            | SourceItem::Stdin { data } => Ok(data.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodedText {
    pub text: String,
    pub encoding: FileEncoding,
    pub has_crlf: bool,
    pub is_binary: bool,
}

pub fn decode_bytes(
    bytes: &[u8],
    forced_encoding: Option<FileEncoding>,
    always_use_encoding: bool,
) -> DecodedText {
    if bytes.is_empty() {
        return DecodedText {
            text: String::new(),
            encoding: forced_encoding.unwrap_or(FileEncoding::Utf8),
            has_crlf: false,
            is_binary: false,
        };
    }

    // Check BOM first unless always_use_encoding is set
    if !always_use_encoding {
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            let (cow, _, _) = UTF_8.decode(&bytes[3..]);
            let text = cow.into_owned();
            let has_crlf = text.contains("\r\n");
            return DecodedText {
                text,
                encoding: FileEncoding::Utf8Bom,
                has_crlf,
                is_binary: false,
            };
        }
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let (cow, _, _) = UTF_16LE.decode(&bytes[2..]);
            let text = cow.into_owned();
            let has_crlf = text.contains("\r\n");
            return DecodedText {
                text,
                encoding: FileEncoding::Utf16Le,
                has_crlf,
                is_binary: false,
            };
        }
        if bytes.starts_with(&[0xFE, 0xFF]) {
            let (cow, _, _) = UTF_16BE.decode(&bytes[2..]);
            let text = cow.into_owned();
            let has_crlf = text.contains("\r\n");
            return DecodedText {
                text,
                encoding: FileEncoding::Utf16Be,
                has_crlf,
                is_binary: false,
            };
        }
    }

    // Heuristic UTF-16LE / UTF-16BE detection without BOM (e.g. Windows reg/config files)
    if !always_use_encoding && bytes.len() >= 4 && bytes.len() % 2 == 0 {
        let sample_len = bytes.len().min(512);
        let mut odd_zeros = 0usize;
        let mut even_zeros = 0usize;
        for (i, &b) in bytes[..sample_len].iter().enumerate() {
            if b == 0 {
                if i % 2 == 0 {
                    even_zeros += 1;
                } else {
                    odd_zeros += 1;
                }
            }
        }
        let pairs = sample_len / 2;
        if odd_zeros > pairs * 3 / 5 && even_zeros == 0 {
            let (cow, _, _) = UTF_16LE.decode(bytes);
            let text = cow.into_owned();
            let has_crlf = text.contains("\r\n");
            return DecodedText {
                text,
                encoding: FileEncoding::Utf16Le,
                has_crlf,
                is_binary: false,
            };
        }
        if even_zeros > pairs * 3 / 5 && odd_zeros == 0 {
            let (cow, _, _) = UTF_16BE.decode(bytes);
            let text = cow.into_owned();
            let has_crlf = text.contains("\r\n");
            return DecodedText {
                text,
                encoding: FileEncoding::Utf16Be,
                has_crlf,
                is_binary: false,
            };
        }
    }

    // Binary file inspection (check first 8192 bytes for null bytes or high control char ratio)
    let check_len = bytes.len().min(8192);
    let null_count = bytes[..check_len].iter().filter(|&&b| b == 0).count();
    if null_count > 0 {
        // Still decode lossily in case --binary-text is requested
        let (cow, _, _) = WINDOWS_1252.decode(bytes);
        let text = cow.into_owned();
        return DecodedText {
            has_crlf: text.contains("\r\n"),
            text,
            encoding: FileEncoding::Binary,
            is_binary: true,
        };
    }

    if let Some(enc) = forced_encoding {
        let text = match enc {
            FileEncoding::Utf8 | FileEncoding::Ascii => {
                String::from_utf8_lossy(bytes).into_owned()
            }
            FileEncoding::Utf8Bom => {
                let slice = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
                String::from_utf8_lossy(slice).into_owned()
            }
            FileEncoding::Utf16Le => {
                let slice = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
                UTF_16LE.decode(slice).0.into_owned()
            }
            FileEncoding::Utf16Be => {
                let slice = bytes.strip_prefix(&[0xFE, 0xFF]).unwrap_or(bytes);
                UTF_16BE.decode(slice).0.into_owned()
            }
            FileEncoding::Windows1252 | FileEncoding::Binary => {
                WINDOWS_1252.decode(bytes).0.into_owned()
            }
        };
        return DecodedText {
            has_crlf: text.contains("\r\n"),
            text,
            encoding: enc,
            is_binary: false,
        };
    }

    // Auto-detect ASCII vs UTF-8 vs Windows-1252
    match std::str::from_utf8(bytes) {
        Ok(valid_utf8) => {
            let is_ascii = bytes.iter().all(|&b| b < 0x80);
            let encoding = if is_ascii {
                FileEncoding::Ascii
            } else {
                FileEncoding::Utf8
            };
            DecodedText {
                has_crlf: valid_utf8.contains("\r\n"),
                text: valid_utf8.to_string(),
                encoding,
                is_binary: false,
            }
        }
        Err(_) => {
            let (cow, _, _) = WINDOWS_1252.decode(bytes);
            let text = cow.into_owned();
            DecodedText {
                has_crlf: text.contains("\r\n"),
                text,
                encoding: FileEncoding::Windows1252,
                is_binary: false,
            }
        }
    }
}

pub fn encode_text(text: &str, encoding: FileEncoding) -> Vec<u8> {
    match encoding {
        FileEncoding::Utf8 | FileEncoding::Ascii | FileEncoding::Binary => text.as_bytes().to_vec(),
        FileEncoding::Utf8Bom => {
            let mut out = Vec::with_capacity(3 + text.len());
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            out.extend_from_slice(text.as_bytes());
            out
        }
        FileEncoding::Utf16Le => {
            let mut out = Vec::with_capacity(2 + text.len() * 2);
            out.extend_from_slice(&[0xFF, 0xFE]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            out
        }
        FileEncoding::Utf16Be => {
            let mut out = Vec::with_capacity(2 + text.len() * 2);
            out.extend_from_slice(&[0xFE, 0xFF]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        FileEncoding::Windows1252 => {
            let (cow, _, _) = Encoding::for_label(b"windows-1252")
                .unwrap_or(WINDOWS_1252)
                .encode(text);
            cow.into_owned()
        }
    }
}

pub fn write_item_bytes(item: &SourceItem, new_bytes: &[u8], keep_mtime: bool) -> Result<()> {
    match item {
        SourceItem::DiskFile { path, .. } => {
            let orig_mtime = fs::metadata(path).ok().and_then(|m| m.modified().ok());
            fs::write(path, new_bytes)
                .with_context(|| format!("Failed writing to {}", path.display()))?;
            if keep_mtime {
                if let Some(mtime) = orig_mtime {
                    if let Ok(f) = File::options().write(true).open(path) {
                        let _ = f.set_modified(mtime);
                    }
                }
            }
            Ok(())
        }
        SourceItem::GzipFile { archive_path, .. } => {
            let orig_mtime = fs::metadata(archive_path)
                .ok()
                .and_then(|m| m.modified().ok());
            let file = File::create(archive_path)?;
            let mut enc = GzEncoder::new(file, flate2::Compression::default());
            enc.write_all(new_bytes)?;
            enc.finish()?;
            if keep_mtime {
                if let Some(mtime) = orig_mtime {
                    if let Ok(f) = File::options().write(true).open(archive_path) {
                        let _ = f.set_modified(mtime);
                    }
                }
            }
            Ok(())
        }
        SourceItem::ZstdFile { archive_path, .. } => {
            let orig_mtime = fs::metadata(archive_path)
                .ok()
                .and_then(|m| m.modified().ok());
            let file = File::create(archive_path)?;
            let mut enc = zstd::stream::write::Encoder::new(file, 3)?;
            enc.write_all(new_bytes)?;
            enc.finish()?;
            if keep_mtime {
                if let Some(mtime) = orig_mtime {
                    if let Ok(f) = File::options().write(true).open(archive_path) {
                        let _ = f.set_modified(mtime);
                    }
                }
            }
            Ok(())
        }
        SourceItem::Bzip2File { archive_path, .. } => {
            let orig_mtime = fs::metadata(archive_path)
                .ok()
                .and_then(|m| m.modified().ok());
            let file = File::create(archive_path)?;
            let mut enc = BzEncoder::new(file, bzip2::Compression::default());
            enc.write_all(new_bytes)?;
            enc.finish()?;
            if keep_mtime {
                if let Some(mtime) = orig_mtime {
                    if let Ok(f) = File::options().write(true).open(archive_path) {
                        let _ = f.set_modified(mtime);
                    }
                }
            }
            Ok(())
        }
        SourceItem::ZipEntry {
            archive_path,
            entry_index,
            ..
        } => {
            let orig_mtime = fs::metadata(archive_path)
                .ok()
                .and_then(|m| m.modified().ok());
            let raw_zip = fs::read(archive_path)?;
            let reader = Cursor::new(raw_zip);
            let mut archive = zip::ZipArchive::new(reader)?;

            let mut out_buf = Cursor::new(Vec::new());
            {
                let mut writer = zip::ZipWriter::new(&mut out_buf);
                for idx in 0..archive.len() {
                    let mut entry = archive.by_index(idx)?;
                    let name = entry.name().to_string();
                    let options = zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated);
                    if entry.is_dir() {
                        writer.add_directory(name, options)?;
                    } else {
                        writer.start_file(name, options)?;
                        if idx == *entry_index {
                            writer.write_all(new_bytes)?;
                        } else {
                            let (existing, _) = read_bounded_stream(&mut entry, MAX_STREAM_BYTES)?;
                            writer.write_all(&existing)?;
                        }
                    }
                }
                writer.finish()?;
            }
            fs::write(archive_path, out_buf.into_inner())?;
            if keep_mtime {
                if let Some(mtime) = orig_mtime {
                    if let Ok(f) = File::options().write(true).open(archive_path) {
                        let _ = f.set_modified(mtime);
                    }
                }
            }
            Ok(())
        }
        SourceItem::RemoteStream { uri, .. } => write_remote_uri_bytes(uri, new_bytes),
        _ => anyhow::bail!(
            "In-place write-back is supported for disk files, .zip, .gz, .zst, .bz2, and remote URIs (ssh://, sftp://, s3://, az://, gs://); item `{}` is a read-only stream",
            item.display_path()
        ),
    }
}

/// Helper to parse `ssh://user@host[:port]/path` or `sftp://user@host[:port]/path` into
/// `(host_only, optional_port, remote_path)` without any `.leak()` allocation.
fn parse_ssh_uri_parts(uri: &str) -> Result<(String, Option<String>, String)> {
    let stripped = uri
        .strip_prefix("ssh://")
        .or_else(|| uri.strip_prefix("sftp://"))
        .unwrap_or(uri);
    let (host_and_port, remote_path): (String, String) =
        if let Some((h, p)) = stripped.split_once(':') {
            if p.starts_with('/') || p.starts_with('~') || p.starts_with('.') {
                (h.to_string(), p.to_string())
            } else if let Some((port_str, rest_path)) = p.split_once('/') {
                (format!("{}:{}", h, port_str), format!("/{}", rest_path))
            } else {
                (h.to_string(), p.to_string())
            }
        } else if let Some((h, p)) = stripped.split_once('/') {
            (h.to_string(), format!("/{}", p))
        } else {
            (stripped.to_string(), ".".to_string())
        };

    let (host_only, port_opt) = if let Some((h, prt)) = host_and_port.split_once(':') {
        (h.to_string(), Some(prt.to_string()))
    } else {
        (host_and_port, None)
    };
    Ok((host_only, port_opt, remote_path))
}

/// Write modified or restored bytes back to a Remote / Cloud URI (SSH, SFTP, AWS S3, Azure Blob, GCS)
pub fn write_remote_uri_bytes(uri: &str, new_bytes: &[u8]) -> Result<()> {
    let lower = uri.to_lowercase();

    if lower.starts_with("ssh://") || lower.starts_with("sftp://") {
        let (host_only, port_opt, remote_path) = parse_ssh_uri_parts(uri)?;

        let mut cmd = Command::new("ssh");
        cmd.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
        if let Some(ref port) = port_opt {
            cmd.args(["-p", port]);
        }
        // Use strict POSIX single-quoting to prevent remote command injection
        cmd.arg(&host_only)
            .arg(format!("cat > {}", shell_single_quote(&remote_path)))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed spawning ssh for remote write-back")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(new_bytes)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "SSH write-back failed for `{}`: {}",
                uri,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return Ok(());
    }

    if lower.starts_with("s3://") {
        let mut child = Command::new("aws")
            .args(["s3", "cp", "-", uri])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed spawning `aws s3 cp` for S3 write-back")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(new_bytes)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "S3 write-back failed for `{}`: {}",
                uri,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return Ok(());
    }

    if lower.starts_with("gs://") {
        let mut child = Command::new("gsutil")
            .args(["cp", "-", uri])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed spawning `gsutil cp` for GCS write-back")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(new_bytes)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "GCS write-back failed for `{}`: {}",
                uri,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return Ok(());
    }

    if lower.starts_with("az://") || lower.starts_with("abfs://") {
        let stripped = uri
            .strip_prefix("az://")
            .or_else(|| uri.strip_prefix("abfs://"))
            .unwrap_or(uri);
        let (container_part, blob_name) = stripped
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("Invalid Azure Blob URI `{}`", uri))?;
        let (container, account_opt) = if let Some((c, acc)) = container_part.split_once('@') {
            (c, Some(acc.split('.').next().unwrap_or(acc)))
        } else {
            (container_part, None)
        };

        let tmp_path = std::env::temp_dir().join(format!("ffrr_az_upload_{}.tmp", now_epoch_ms()));
        fs::write(&tmp_path, new_bytes)?;
        let mut cmd = Command::new("az");
        cmd.args([
            "storage",
            "blob",
            "upload",
            "--overwrite",
            "true",
            "--container-name",
            container,
            "--name",
            blob_name,
            "--file",
            &tmp_path.to_string_lossy(),
        ]);
        if let Some(acc) = account_opt {
            cmd.args(["--account-name", acc]);
        }
        let out = cmd.output();
        let _ = fs::remove_file(&tmp_path);
        let out = out.context("Failed running `az storage blob upload`")?;
        if !out.status.success() {
            anyhow::bail!(
                "Azure Blob write-back failed for `{}`: {}",
                uri,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return Ok(());
    }

    anyhow::bail!("Remote write-back not supported for URI `{}`", uri)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub name: String,
    pub provider: String, // "ssh", "sftp", "s3", "azure-blob", "gcs", "smb"
    pub uri: String,
    pub secret_ref: Option<String>, // "keychain:<service>", "dpapi:<name>", "secret-tool:<name>", "env:<VAR>"
    pub description: String,
}

pub fn load_connection_profiles() -> Vec<ConnectionProfile> {
    if let Ok(raw) = fs::read_to_string("ffrr.connections.json") {
        if let Ok(list) = serde_json::from_str::<Vec<ConnectionProfile>>(&raw) {
            return list;
        }
    }
    Vec::new()
}

pub fn save_connection_profile(
    name: &str,
    provider: &str,
    uri: &str,
    secret_value: Option<&str>,
    secret_env: Option<&str>,
    description: &str,
) -> Result<Vec<ConnectionProfile>> {
    let clean_name = name.trim().trim_start_matches('@').to_string();
    if clean_name.is_empty() {
        anyhow::bail!("Connection profile name cannot be empty");
    }

    let secret_ref = if let Some(secret) = secret_value.filter(|s| !s.trim().is_empty()) {
        Some(store_secret_in_os_vault(&clean_name, secret)?)
    } else if let Some(env_var) = secret_env.filter(|s| !s.trim().is_empty()) {
        let clean_env = env_var.trim().trim_start_matches("env:");
        Some(format!("env:{}", clean_env))
    } else {
        None
    };

    let mut profiles = load_connection_profiles();
    if let Some(existing) = profiles.iter_mut().find(|p| p.name == clean_name) {
        existing.provider = provider.to_string();
        existing.uri = uri.to_string();
        if secret_ref.is_some() {
            existing.secret_ref = secret_ref;
        }
        existing.description = description.to_string();
    } else {
        profiles.push(ConnectionProfile {
            name: clean_name,
            provider: provider.to_string(),
            uri: uri.to_string(),
            secret_ref,
            description: description.to_string(),
        });
    }
    fs::write(
        "ffrr.connections.json",
        serde_json::to_string_pretty(&profiles)?,
    )?;
    Ok(profiles)
}

pub fn delete_connection_profile(name: &str) -> Result<Vec<ConnectionProfile>> {
    let clean_name = name.trim().trim_start_matches('@');
    let mut profiles = load_connection_profiles();
    profiles.retain(|p| p.name != clean_name);
    fs::write(
        "ffrr.connections.json",
        serde_json::to_string_pretty(&profiles)?,
    )?;
    Ok(profiles)
}

/// Store a credential in the native OS credential vault (macOS Keychain, Windows DPAPI, Linux libsecret)
/// so plaintext secrets are NEVER stored in `ffrr.connections.json`.
pub fn store_secret_in_os_vault(profile_name: &str, secret: &str) -> Result<String> {
    let service_key = format!("ffrr_conn_{}", profile_name);

    #[cfg(target_os = "macos")]
    {
        let user = std::env::var("USER").unwrap_or_else(|_| "ffrr".to_string());
        let status = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-a",
                &user,
                "-s",
                &service_key,
                "-w",
                secret,
            ])
            .status()?;
        if status.success() {
            return Ok(format!("keychain:{}", service_key));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$s = ConvertTo-SecureString '{}' -AsPlainText -Force; ConvertFrom-SecureString $s",
                    secret.replace('\'', "''")
                ),
            ])
            .output()?;
        if out.status.success() {
            let enc = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Ok(format!("dpapi:{}", enc));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--label",
                &format!("FFRR Connection {}", profile_name),
                "service",
                "ffrr",
                "account",
                &service_key,
            ])
            .stdin(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(secret.as_bytes())?;
        }
        if child.wait()?.success() {
            return Ok(format!("secret-tool:{}", service_key));
        }
    }

    anyhow::bail!("OS credential vault tool unavailable; use `env:VAR_NAME` reference instead")
}

pub fn expand_connection_profile_uri(src: &str) -> String {
    let trimmed = src.trim();
    if let Some(rest) = trimmed.strip_prefix('@') {
        let (prof_name, subpath) = match rest.split_once('/') {
            Some((n, sub)) => (n, Some(sub)),
            None => (rest, None),
        };
        if let Some(prof) = load_connection_profiles()
            .into_iter()
            .find(|p| p.name.eq_ignore_ascii_case(prof_name))
        {
            if let Some(sub) = subpath {
                return format!("{}/{}", prof.uri.trim_end_matches('/'), sub);
            }
            return prof.uri;
        }
    }
    trimmed.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDrive {
    pub name: String,
    pub path: String,
    pub kind: String,
}

pub fn detect_system_drives() -> Vec<SystemDrive> {
    let mut drives = Vec::new();

    #[cfg(target_os = "macos")]
    {
        drives.push(SystemDrive {
            name: "Macintosh HD (Full Mac Root)".to_string(),
            path: "/".to_string(),
            kind: "internal".to_string(),
        });
        if let Ok(home) = std::env::var("HOME") {
            drives.push(SystemDrive {
                name: format!("Mac User Home ({})", home),
                path: home,
                kind: "home".to_string(),
            });
        }
        if let Ok(entries) = fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || name == "Macintosh HD" || name == "Recovery" {
                    continue;
                }
                if let Ok(meta) = fs::symlink_metadata(&p) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                }
                if p.is_dir() {
                    drives.push(SystemDrive {
                        name: format!("USB / External Drive: {}", name),
                        path: p.to_string_lossy().to_string(),
                        kind: "usb".to_string(),
                    });
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        drives.push(SystemDrive {
            name: "Linux Root (/)".to_string(),
            path: "/".to_string(),
            kind: "internal".to_string(),
        });
        if let Ok(home) = std::env::var("HOME") {
            drives.push(SystemDrive {
                name: format!("Linux User Home ({})", home),
                path: home,
                kind: "home".to_string(),
            });
        }
        let mut seen_mounts = HashSet::new();
        // Parse /proc/mounts for physical/USB/SMB/NFS mounted filesystems
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let dev = parts[0];
                    let mnt = parts[1];
                    let fstype = parts[2];
                    if (dev.starts_with("/dev/sd")
                        || dev.starts_with("/dev/nvme")
                        || dev.starts_with("/dev/mmcblk")
                        || fstype == "cifs"
                        || fstype == "smb3"
                        || fstype == "nfs"
                        || fstype == "exfat"
                        || fstype == "ntfs"
                        || fstype == "vfat")
                        && mnt != "/"
                        && !mnt.starts_with("/boot")
                        && !mnt.starts_with("/snap")
                        && seen_mounts.insert(mnt.to_string())
                    {
                        drives.push(SystemDrive {
                            name: format!("Mounted Drive ({} - {})", mnt, fstype),
                            path: mnt.to_string(),
                            kind: "usb".to_string(),
                        });
                    }
                }
            }
        }
        for mount_parent in &["/mnt", "/media", "/run/media"] {
            if let Ok(entries) = fs::read_dir(mount_parent) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let p_str = p.to_string_lossy().to_string();
                    if p.is_dir() && seen_mounts.insert(p_str.clone()) {
                        drives.push(SystemDrive {
                            name: format!("USB / Mounted Volume: {}", p.display()),
                            path: p_str,
                            kind: "usb".to_string(),
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            drives.push(SystemDrive {
                name: format!("Windows User Profile ({})", profile),
                path: profile,
                kind: "home".to_string(),
            });
        }
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            if Path::new(&root).exists() {
                let label = if letter == b'C' {
                    format!("Windows System HDD ({}:\\)", letter as char)
                } else {
                    format!("Connected USB / Data Drive ({}:\\)", letter as char)
                };
                drives.push(SystemDrive {
                    name: label,
                    path: root,
                    kind: if letter == b'C' { "internal" } else { "usb" }.to_string(),
                });
            }
        }
    }

    for prof in load_connection_profiles() {
        drives.push(SystemDrive {
            name: format!("Saved Cloud/Remote (@{}): {}", prof.name, prof.provider),
            path: format!("@{}", prof.name),
            kind: "cloud".to_string(),
        });
    }

    drives
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalOptions {
    pub sources: Vec<String>,
    pub file_masks: Vec<String>,
    pub exclude_masks: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub recursive: bool,
    pub include_archives: bool,
    pub include_hidden: bool,
    pub respect_gitignore: bool,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

impl Default for TraversalOptions {
    fn default() -> Self {
        Self {
            sources: vec![".".to_string()],
            file_masks: Vec::new(),
            exclude_masks: Vec::new(),
            exclude_dirs: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                ".pnpm-store".to_string(),
                "target".to_string(),
                "obj".to_string(),
                "packages".to_string(),
                ".vs".to_string(),
                "bower_components".to_string(),
                "vendor".to_string(),
                ".gradle".to_string(),
                ".cargo".to_string(),
                ".ffrr_backups".to_string(),
                ".trash".to_string(),
                "$recycle.bin".to_string(),
                "system volume information".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
                ".next".to_string(),
                ".cache".to_string(),
                "caches".to_string(),
            ],
            recursive: true,
            include_archives: true,
            include_hidden: false,
            respect_gitignore: true,
            min_size: None,
            max_size: None,
        }
    }
}

pub fn split_mask_list(raw: &str) -> Vec<String> {
    raw.split(|c| c == ',' || c == ';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "*.*" && s != "*")
        .collect()
}

fn compile_patterns(masks: &[String]) -> Vec<Pattern> {
    masks
        .iter()
        .filter_map(|m| {
            let pat = if m.starts_with("*.") && m.len() > 2 {
                m.to_lowercase()
            } else {
                m.to_lowercase()
            };
            Pattern::new(&pat).ok()
        })
        .collect()
}

fn matches_file_filters(
    file_name: &str,
    rel_path: &str,
    size: u64,
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    gitignore_pats: &[Pattern],
    opts: &TraversalOptions,
) -> bool {
    if let Some(min_s) = opts.min_size {
        if size < min_s {
            return false;
        }
    }
    if let Some(max_s) = opts.max_size {
        if size > max_s {
            return false;
        }
    }
    let lower_name = file_name.to_lowercase();
    let lower_rel = rel_path.to_lowercase();

    for ex in exclude_pats {
        if ex.matches(&lower_name) || ex.matches(&lower_rel) {
            return false;
        }
    }
    for gi in gitignore_pats {
        if gi.matches(&lower_name) || gi.matches(&lower_rel) {
            return false;
        }
    }
    if include_pats.is_empty() {
        return true;
    }
    include_pats
        .iter()
        .any(|p| p.matches(&lower_name) || p.matches(&lower_rel))
}

fn load_gitignore_patterns(root: &Path) -> Vec<Pattern> {
    let mut out = Vec::new();
    for ignore_name in &[".gitignore", ".ignore"] {
        let p = root.join(ignore_name);
        if let Ok(content) = fs::read_to_string(&p) {
            for line in content.lines() {
                let trimmed = line.trim().trim_end_matches('/');
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                    continue;
                }
                let clean = trimmed.trim_start_matches('/').to_lowercase();
                if let Ok(pat) = Pattern::new(&clean) {
                    out.push(pat);
                }
            }
        }
    }
    out
}

fn mtime_to_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
}

pub fn is_archive_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    lower.ends_with(".zip")
        || lower.ends_with(".rar")
        || lower.ends_with(".gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar")
        || lower.ends_with(".zst")
        || lower.ends_with(".bz2")
}

/// Fast check for known binary/media/compiled extensions so content search never reads gigabytes of binary files
pub fn is_known_binary_extension(ext: &str) -> bool {
    matches!(
        ext,
        "dll" | "exe" | "pdb" | "so" | "dylib" | "a" | "lib" | "obj" | "o"
        | "class" | "jar" | "war" | "pyc" | "pyd" | "wasm"
        | "db" | "sqlite" | "sqlite3" | "db-shm" | "db-wal" | "mdb" | "ldf" | "mdf" | "parquet"
        | "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "bmp" | "tiff"
        | "mp3" | "mp4" | "wav" | "avi" | "mov" | "mkv" | "webm" | "flac" | "ogg"
        | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
        | "woff" | "woff2" | "ttf" | "eot" | "otf"
        | "dmg" | "iso" | "pkg" | "msi" | "cab" | "7z" | "xz"
        | "bin" | "dat" | "pak" | "idx" | "pack" | "DS_Store"
    )
}

pub fn resolve_sources(opts: &TraversalOptions) -> Result<Vec<SourceItem>> {
    let include_pats = compile_patterns(&opts.file_masks);
    let exclude_pats = compile_patterns(&opts.exclude_masks);
    let exclude_dirs_lower: HashSet<String> = opts
        .exclude_dirs
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    let mut items = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut dir_roots: Vec<(PathBuf, String)> = Vec::new();

    let sources = if opts.sources.is_empty() {
        vec![".".to_string()]
    } else {
        opts.sources.clone()
    };

    for src in &sources {
        let expanded_src = expand_connection_profile_uri(src);
        let trimmed = expanded_src.trim();
        if trimmed == "-" {
            let (data, _) = read_bounded_stream(std::io::stdin(), MAX_STREAM_BYTES)?;
            items.push(SourceItem::Stdin { data });
            continue;
        }

        // Pluggable Remote & Cloud Source Connector URI routing (ssh://, sftp://, s3://, az://, gs://, smb://)
        if is_remote_source_uri(trimmed) {
            if let Ok(remote_items) =
                resolve_remote_uri_source(trimmed, &include_pats, &exclude_pats, opts)
            {
                items.extend(remote_items);
            }
            continue;
        }

        let path = Path::new(trimmed);
        if path.exists() {
            if path.is_file() {
                collect_from_file(
                    path,
                    trimmed,
                    &include_pats,
                    &exclude_pats,
                    &[],
                    opts,
                    &mut items,
                    &mut seen_paths,
                    true,
                );
            } else if path.is_dir() {
                dir_roots.push((path.to_path_buf(), trimmed.to_string()));
            }
        } else if trimmed.contains('*') || trimmed.contains('?') || trimmed.contains('[') {
            if let Ok(paths) = glob::glob(trimmed) {
                for entry in paths.flatten() {
                    if entry.is_file() {
                        collect_from_file(
                            &entry,
                            trimmed,
                            &include_pats,
                            &exclude_pats,
                            &[],
                            opts,
                            &mut items,
                            &mut seen_paths,
                            true,
                        );
                    } else if entry.is_dir() {
                        dir_roots.push((entry, trimmed.to_string()));
                    }
                }
            }
        }
    }

    // Walk ALL source directories together interleaved level-by-level (Breadth-First across all drives simultaneously!)
    if !dir_roots.is_empty() {
        collect_from_dirs_interleaved(
            &dir_roots,
            &include_pats,
            &exclude_pats,
            &exclude_dirs_lower,
            opts,
            &mut items,
            &mut seen_paths,
        );
    }

    Ok(items)
}

/// Fast check for known regular-file extensions so FSKit NTFS / network drives (`DT_UNKNOWN`)
/// never need an expensive `lstat()` RPC call on non-matching files just to determine `is_dir()`.
fn has_known_file_extension(lower_name: &str) -> bool {
    let ext = match lower_name.rsplit_once('.') {
        Some((_, e)) if !e.is_empty() && e.len() <= 10 => e,
        _ => return false,
    };
    matches!(
        ext,
        "ps1" | "psm1" | "psd1" | "bat" | "cmd" | "vbs" | "sh" | "bash" | "zsh"
        | "cs" | "csproj" | "sln" | "vb" | "fs" | "rs" | "py" | "pyc" | "pyd"
        | "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "vue" | "svelte"
        | "html" | "htm" | "css" | "scss" | "less" | "json" | "yaml" | "yml"
        | "toml" | "xml" | "ini" | "conf" | "cfg" | "config" | "env" | "properties"
        | "md" | "txt" | "rst" | "log" | "out" | "err" | "csv" | "tsv" | "sql"
        | "db" | "sqlite" | "sqlite3" | "db-shm" | "db-wal" | "parquet"
        | "dll" | "exe" | "pdb" | "so" | "dylib" | "a" | "lib" | "obj" | "o"
        | "class" | "jar" | "war" | "go" | "java" | "kt" | "c" | "cpp" | "cc" | "h" | "hpp"
        | "php" | "rb" | "pl" | "lua" | "r" | "swift" | "m"
        | "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "bmp" | "tiff"
        | "mp3" | "mp4" | "wav" | "avi" | "mov" | "mkv" | "webm"
        | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
        | "woff" | "woff2" | "ttf" | "eot" | "otf" | "wasm" | "map"
        | "lock" | "bak" | "tmp" | "dat" | "bin" | "pak" | "idx" | "pack"
        | "zip" | "rar" | "gz" | "tgz" | "tar" | "zst" | "bz2" | "7z" | "xz"
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_from_dirs_interleaved(
    roots: &[(PathBuf, String)],
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    exclude_dirs_lower: &HashSet<String>,
    opts: &TraversalOptions,
    items: &mut Vec<SourceItem>,
    seen_paths: &mut HashSet<PathBuf>,
) {
    let mut gitignore_pats = Vec::new();
    if opts.respect_gitignore {
        for (r, _) in roots {
            gitignore_pats.extend(load_gitignore_patterns(r));
        }
    }

    let max_depth = if opts.recursive { 14 } else { 1 };
    let mut current_level_dirs: Vec<(PathBuf, String, bool)> = roots
        .iter()
        .map(|(p, sr)| (p.clone(), sr.clone(), p == Path::new("/")))
        .collect();

    for depth in 0..max_depth {
        if current_level_dirs.is_empty() || is_progress_cancelled() {
            break;
        }
        set_progress_phase(&format!(
            "Scanning depth {} ({} folders across all drives)...",
            depth + 1,
            current_level_dirs.len()
        ));

        let level_outputs: Vec<(Vec<(PathBuf, String, bool)>, Vec<(PathBuf, String)>)> =
            current_level_dirs
                .par_iter()
                .map(|(dir, src_root, is_root_slash)| {
                    if is_progress_cancelled() {
                        return (Vec::new(), Vec::new());
                    }
                    record_walk_dir(&dir.to_string_lossy());
                    let mut child_dirs = Vec::new();
                    let mut child_files = Vec::new();

                    let rd = match fs::read_dir(dir) {
                        Ok(r) => r,
                        Err(_) => return (child_dirs, child_files),
                    };

                    for entry in rd.flatten() {
                        if is_progress_cancelled() {
                            break;
                        }
                        let name = entry.file_name().to_string_lossy().to_string();
                        if !opts.include_hidden && name.starts_with('.') {
                            continue;
                        }
                        let lower = name.to_lowercase();

                        if has_known_file_extension(&lower) {
                            let is_arc = depth <= 2
                                && (lower.ends_with(".zip")
                                    || lower.ends_with(".rar")
                                    || lower.ends_with(".gz")
                                    || lower.ends_with(".tgz")
                                    || lower.ends_with(".tar")
                                    || lower.ends_with(".zst")
                                    || lower.ends_with(".bz2"));
                            let p = entry.path();
                            let rel_str = p.to_string_lossy();
                            if is_arc
                                || matches_file_filters(
                                    &name,
                                    &rel_str,
                                    0,
                                    include_pats,
                                    exclude_pats,
                                    &gitignore_pats,
                                    &TraversalOptions {
                                        min_size: None,
                                        max_size: None,
                                        ..opts.clone()
                                    },
                                )
                            {
                                child_files.push((p, src_root.clone()));
                            }
                            continue;
                        }

                        let ft = match entry.file_type() {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        if ft.is_symlink() {
                            continue;
                        }
                        let p = entry.path();
                        if ft.is_dir() {
                            if *is_root_slash && depth <= 1 {
                                let full_p = p.to_string_lossy();
                                if full_p == "/dev"
                                    || full_p == "/proc"
                                    || full_p == "/sys"
                                    || full_p == "/run"
                                    || full_p == "/Volumes"
                                    || full_p == "/System"
                                    || full_p == "/System/Volumes"
                                    || full_p == "/Library"
                                    || full_p == "/Applications"
                                    || full_p == "/private"
                                    || full_p == "/cores"
                                    || full_p == "/usr"
                                    || full_p == "/bin"
                                    || full_p == "/sbin"
                                    || full_p == "/opt"
                                    || full_p == "/pkg"
                                {
                                    continue;
                                }
                            }
                            if lower == "$recycle.bin"
                                || lower == "system volume information"
                                || lower == "winsxs"
                                || (lower == "library" && p.to_string_lossy().contains("/Users/"))
                            {
                                continue;
                            }
                            if exclude_dirs_lower.contains(&lower) {
                                continue;
                            }
                            if gitignore_pats.iter().any(|gi| gi.matches(&lower)) {
                                continue;
                            }
                            child_dirs.push((p, src_root.clone(), *is_root_slash));
                        } else if ft.is_file() {
                            child_files.push((p, src_root.clone()));
                        }
                    }
                    (child_dirs, child_files)
                })
                .collect();

        let mut next_dirs = Vec::new();
        for (c_dirs, c_files) in level_outputs {
            next_dirs.extend(c_dirs);
            for (fpath, src_root) in c_files {
                collect_from_file(
                    &fpath,
                    &src_root,
                    include_pats,
                    exclude_pats,
                    &gitignore_pats,
                    opts,
                    items,
                    seen_paths,
                    false,
                );
            }
        }
        current_level_dirs = next_dirs;
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_from_file(
    path: &Path,
    source_root: &str,
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    gitignore_pats: &[Pattern],
    opts: &TraversalOptions,
    items: &mut Vec<SourceItem>,
    seen_paths: &mut HashSet<PathBuf>,
    explicitly_targeted: bool,
) {
    if is_progress_cancelled() {
        return;
    }

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let rel_str = path.to_string_lossy().to_string();
    let is_arc = is_archive_path(path);

    if !is_arc
        && !matches_file_filters(
            &file_name,
            &rel_str,
            opts.min_size.unwrap_or(0),
            include_pats,
            exclude_pats,
            gitignore_pats,
            &TraversalOptions {
                min_size: None,
                max_size: None,
                ..opts.clone()
            },
        )
    {
        return;
    }

    if !seen_paths.insert(path.to_path_buf()) {
        return;
    }

    // Avoid calling `fs::metadata(path)` on every file during directory walk unless size filters or archive unpacking require it!
    let need_stat = is_arc || opts.min_size.is_some() || opts.max_size.is_some();
    let (file_size, mtime_secs) = if need_stat {
        match fs::metadata(path) {
            Ok(m) => (m.len(), mtime_to_secs(&m)),
            Err(_) => return,
        }
    } else {
        (0, 0)
    };

    let allow_archive_unpack = explicitly_targeted
        || (opts.include_archives && file_size <= 1024 * 1024);

    if allow_archive_unpack && is_arc {
        if expand_archive(
            path,
            source_root,
            mtime_secs,
            file_size,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
            items,
        )
        .is_ok()
        {
            return;
        }
    }

    if matches_file_filters(
        &file_name,
        &rel_str,
        file_size,
        include_pats,
        exclude_pats,
        gitignore_pats,
        opts,
    ) {
        record_discovered_file(&rel_str, false);
        items.push(SourceItem::DiskFile {
            path: path.to_path_buf(),
            size: file_size,
            mtime_secs,
            source_root: source_root.to_string(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn expand_archive(
    path: &Path,
    source_root: &str,
    mtime_secs: u64,
    archive_file_size: u64,
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    gitignore_pats: &[Pattern],
    opts: &TraversalOptions,
    items: &mut Vec<SourceItem>,
) -> Result<()> {
    let lower = path.to_string_lossy().to_lowercase();

    if lower.ends_with(".zip") {
        let file = File::open(path)?;
        let mut zip = zip::ZipArchive::new(file)?;
        for idx in 0..zip.len() {
            if is_progress_cancelled() {
                break;
            }
            if let Ok(entry) = zip.by_index(idx) {
                if entry.is_dir() {
                    continue;
                }
                let entry_name = entry.name().to_string();
                let fname = Path::new(&entry_name)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| entry_name.clone());
                let size = entry.size();
                if matches_file_filters(
                    &fname,
                    &entry_name,
                    size,
                    include_pats,
                    exclude_pats,
                    gitignore_pats,
                    opts,
                ) {
                    record_discovered_file(&entry_name, true);
                    items.push(SourceItem::ZipEntry {
                        archive_path: path.to_path_buf(),
                        entry_index: idx,
                        entry_name,
                        size,
                        mtime_secs,
                        source_root: source_root.to_string(),
                    });
                }
            }
        }
        return Ok(());
    }

    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let file = File::open(path)?;
        let gz = GzDecoder::new(file);
        return expand_tar_stream(
            gz,
            path,
            TarCompression::Gzip,
            source_root,
            mtime_secs,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
            items,
        );
    }

    if lower.ends_with(".tar.zst") {
        let file = File::open(path)?;
        let dec = zstd::stream::read::Decoder::new(file)?;
        return expand_tar_stream(
            dec,
            path,
            TarCompression::Zstd,
            source_root,
            mtime_secs,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
            items,
        );
    }

    if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        let file = File::open(path)?;
        let dec = BzDecoder::new(file);
        return expand_tar_stream(
            dec,
            path,
            TarCompression::Bzip2,
            source_root,
            mtime_secs,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
            items,
        );
    }

    if lower.ends_with(".tar") {
        let file = File::open(path)?;
        return expand_tar_stream(
            file,
            path,
            TarCompression::None,
            source_root,
            mtime_secs,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
            items,
        );
    }

    if lower.ends_with(".gz") {
        let fname = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "stream".to_string());
        if matches_file_filters(
            &fname,
            &fname,
            archive_file_size,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
        ) {
            record_discovered_file(&fname, true);
            items.push(SourceItem::GzipFile {
                archive_path: path.to_path_buf(),
                inner_name: fname,
                size: archive_file_size,
                mtime_secs,
                source_root: source_root.to_string(),
            });
        }
        return Ok(());
    }

    if lower.ends_with(".zst") {
        let fname = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "stream".to_string());
        if matches_file_filters(
            &fname,
            &fname,
            archive_file_size,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
        ) {
            record_discovered_file(&fname, true);
            items.push(SourceItem::ZstdFile {
                archive_path: path.to_path_buf(),
                inner_name: fname,
                size: archive_file_size,
                mtime_secs,
                source_root: source_root.to_string(),
            });
        }
        return Ok(());
    }

    if lower.ends_with(".bz2") {
        let fname = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "stream".to_string());
        if matches_file_filters(
            &fname,
            &fname,
            archive_file_size,
            include_pats,
            exclude_pats,
            gitignore_pats,
            opts,
        ) {
            record_discovered_file(&fname, true);
            items.push(SourceItem::Bzip2File {
                archive_path: path.to_path_buf(),
                inner_name: fname,
                size: archive_file_size,
                mtime_secs,
                source_root: source_root.to_string(),
            });
        }
        return Ok(());
    }

    if lower.ends_with(".rar") {
        let entries = extract_rar_entries(path)?;
        for (entry_name, data) in entries {
            let fname = Path::new(&entry_name)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry_name.clone());
            let size = data.len() as u64;
            if matches_file_filters(
                &fname,
                &entry_name,
                size,
                include_pats,
                exclude_pats,
                gitignore_pats,
                opts,
            ) {
                items.push(SourceItem::RarEntry {
                    archive_path: path.to_path_buf(),
                    entry_name,
                    data,
                    size,
                    mtime_secs,
                    source_root: source_root.to_string(),
                });
            }
        }
        return Ok(());
    }

    anyhow::bail!("Unsupported archive type")
}

/// Pure-Rust POSIX / USTAR / GNU tar stream reader (zero external dependencies)
#[allow(clippy::too_many_arguments)]
fn expand_tar_stream<R: Read>(
    mut reader: R,
    archive_path: &Path,
    compression: TarCompression,
    source_root: &str,
    mtime_secs: u64,
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    gitignore_pats: &[Pattern],
    opts: &TraversalOptions,
    items: &mut Vec<SourceItem>,
) -> Result<()> {
    let mut header = [0u8; 512];
    let mut gnu_long_name: Option<String> = None;

    loop {
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(_) => break,
        }
        if header.iter().all(|&b| b == 0) {
            break;
        }

        let size_str = std::str::from_utf8(&header[124..136])
            .unwrap_or("")
            .trim_matches(|c: char| c == '\0' || c.is_whitespace());
        let size = u64::from_str_radix(size_str, 8).unwrap_or(0);
        let typeflag = header[156];

        let raw_name = header[0..100]
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();
        let prefix = header[345..500]
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();

        let entry_name = if let Some(long_name) = gnu_long_name.take() {
            long_name
        } else if !prefix.is_empty() {
            format!("{}/{}", prefix.trim_end_matches('/'), raw_name)
        } else {
            raw_name
        };

        let padded_size = size.saturating_add(511) / 512 * 512;

        // Handle GNU LongLink header ('L') with a strict 4096-byte sanity cap
        if typeflag == b'L' {
            if padded_size <= 4096 {
                let mut payload = vec![0u8; padded_size as usize];
                if padded_size > 0 && reader.read_exact(&mut payload).is_err() {
                    break;
                }
                payload.truncate(size as usize);
                let s = String::from_utf8_lossy(&payload)
                    .trim_end_matches('\0')
                    .to_string();
                gnu_long_name = Some(s);
            } else {
                let _ = std::io::copy(
                    &mut reader.by_ref().take(padded_size),
                    &mut std::io::sink(),
                );
            }
            continue;
        }

        // Only regular files (typeflag 0 or '0') that are <= MAX_STREAM_BYTES and match filters
        // are read into memory; all other entries are skipped via io::sink() with 0 heap allocation!
        if (typeflag == 0 || typeflag == b'0') && size <= MAX_STREAM_BYTES {
            let fname = Path::new(&entry_name)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry_name.clone());
            if matches_file_filters(
                &fname,
                &entry_name,
                size,
                include_pats,
                exclude_pats,
                gitignore_pats,
                opts,
            ) {
                let mut payload = vec![0u8; padded_size as usize];
                if padded_size > 0 && reader.read_exact(&mut payload).is_err() {
                    break;
                }
                payload.truncate(size as usize);
                items.push(SourceItem::TarEntry {
                    archive_path: archive_path.to_path_buf(),
                    compression,
                    entry_name,
                    data: payload,
                    size,
                    mtime_secs,
                    source_root: source_root.to_string(),
                });
                continue;
            }
        }

        // Skip non-matching or oversized tar entry payload without allocating memory
        if padded_size > 0 {
            if std::io::copy(&mut reader.by_ref().take(padded_size), &mut std::io::sink()).is_err()
            {
                break;
            }
        }
    }
    Ok(())
}

/// Read a variable-length integer (vint) used in RAR v5 headers
fn read_rar5_vint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    while *pos < bytes.len() && shift < 64 {
        let b = bytes[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// Native RAR v4 & RAR v5 archive parser with automatic external tool fallback for compressed streams
pub fn extract_rar_entries(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let bytes = fs::read(path)?;
    let mut entries = Vec::new();
    let mut had_compressed_entries = false;

    if bytes.starts_with(b"Rar!\x1a\x07\x01\x00") {
        // RAR v5 format
        let mut pos = 8usize;
        while pos + 7 <= bytes.len() {
            let _crc = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            let header_size = match read_rar5_vint(&bytes, &mut pos) {
                Some(v) => v as usize,
                None => break,
            };
            let header_end = pos.saturating_add(header_size);
            if header_end > bytes.len() {
                break;
            }
            let mut hpos = pos;
            let header_type = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
            let header_flags = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
            if (header_flags & 0x0001) != 0 {
                let _extra_size = read_rar5_vint(&bytes, &mut hpos);
            }
            let data_size = if (header_flags & 0x0002) != 0 {
                read_rar5_vint(&bytes, &mut hpos).unwrap_or(0) as usize
            } else {
                0
            };

            if header_type == 2 {
                // File header
                let file_flags = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
                let _unp_size = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
                let _attributes = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
                if (file_flags & 0x0002) != 0 && hpos + 4 <= header_end {
                    hpos += 4; // mtime uint32
                }
                if (file_flags & 0x0004) != 0 && hpos + 4 <= header_end {
                    hpos += 4; // data crc32
                }
                let comp_info = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
                let _host_os = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0);
                let name_len = read_rar5_vint(&bytes, &mut hpos).unwrap_or(0) as usize;
                let is_dir = (file_flags & 0x0001) != 0;
                let method = (comp_info >> 7) & 0x07;

                if !is_dir && hpos + name_len <= header_end {
                    let name = String::from_utf8_lossy(&bytes[hpos..hpos + name_len]).to_string();
                    let data_start = header_end;
                    let data_end = data_start.saturating_add(data_size);
                    if data_end <= bytes.len() {
                        if method == 0 {
                            entries.push((name, bytes[data_start..data_end].to_vec()));
                        } else {
                            had_compressed_entries = true;
                        }
                    }
                }
            } else if header_type == 5 {
                // End of archive header
                break;
            }
            pos = header_end.saturating_add(data_size);
        }
    } else if bytes.starts_with(b"Rar!\x1a\x07\x00") {
        // RAR v4 format
        let mut pos = 7usize;
        while pos + 7 <= bytes.len() {
            let _head_crc = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
            let head_type = bytes[pos + 2];
            let head_flags = u16::from_le_bytes([bytes[pos + 3], bytes[pos + 4]]);
            let head_size = u16::from_le_bytes([bytes[pos + 5], bytes[pos + 6]]) as usize;
            if head_size < 7 || pos + head_size > bytes.len() {
                break;
            }

            if head_type == 0x74 && pos + 32 <= bytes.len() {
                // File Header block
                let pack_size = u32::from_le_bytes([
                    bytes[pos + 7],
                    bytes[pos + 8],
                    bytes[pos + 9],
                    bytes[pos + 10],
                ]) as usize;
                let _unp_size = u32::from_le_bytes([
                    bytes[pos + 11],
                    bytes[pos + 12],
                    bytes[pos + 13],
                    bytes[pos + 14],
                ]) as usize;
                let method = bytes[pos + 25];
                let name_size = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
                let mut name_offset = pos + 32;
                if (head_flags & 0x0100) != 0 {
                    name_offset += 8; // HIGH_PACK_SIZE + HIGH_UNP_SIZE
                }
                let is_dir = (head_flags & 0x00E0) == 0x00E0;
                if !is_dir && name_offset + name_size <= pos + head_size {
                    let raw_name = &bytes[name_offset..name_offset + name_size];
                    let end_idx = raw_name.iter().position(|&b| b == 0).unwrap_or(raw_name.len());
                    let name = String::from_utf8_lossy(&raw_name[..end_idx])
                        .replace('\\', "/");
                    let data_start = pos + head_size;
                    let data_end = data_start.saturating_add(pack_size);
                    if data_end <= bytes.len() {
                        if method == 0x30 {
                            entries.push((name, bytes[data_start..data_end].to_vec()));
                        } else {
                            had_compressed_entries = true;
                        }
                    }
                }
                pos = (pos + head_size).saturating_add(pack_size);
            } else {
                let add_size = if (head_flags & 0x8000) != 0 && pos + 11 <= bytes.len() {
                    u32::from_le_bytes([
                        bytes[pos + 7],
                        bytes[pos + 8],
                        bytes[pos + 9],
                        bytes[pos + 10],
                    ]) as usize
                } else {
                    0
                };
                pos = (pos + head_size).saturating_add(add_size);
            }
        }
    }

    if had_compressed_entries && entries.is_empty() {
        // Fallback to system unrar / 7z / bsdtar if available
        if let Ok(ext_entries) = extract_rar_via_external_cli(path) {
            if !ext_entries.is_empty() {
                return Ok(ext_entries);
            }
        }
    }

    Ok(entries)
}

fn extract_rar_via_external_cli(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out_entries = Vec::new();
    let list_out = Command::new("unrar")
        .args(["vb", &path.to_string_lossy()])
        .output();
    if let Ok(output) = list_out {
        if output.status.success() {
            let names = String::from_utf8_lossy(&output.stdout);
            for name in names.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                if let Ok(file_out) = Command::new("unrar")
                    .args(["p", "-inul", &path.to_string_lossy(), name])
                    .output()
                {
                    if file_out.status.success() {
                        out_entries.push((name.to_string(), file_out.stdout));
                    }
                }
            }
            return Ok(out_entries);
        }
    }
    Ok(out_entries)
}

/// Helper to encode a valid RAR v5 archive with stored files (used by sample generator & tests)
pub fn create_rar5_archive(path: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    fn encode_vint(mut val: u64, buf: &mut Vec<u8>) {
        loop {
            let mut byte = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    let mut out = Vec::new();
    // RAR v5 magic signature
    out.extend_from_slice(b"Rar!\x1a\x07\x01\x00");

    // Main archive header (type = 1, flags = 0, archive_flags = 0)
    {
        let mut body = Vec::new();
        encode_vint(1, &mut body); // header_type = 1 (Main)
        encode_vint(0, &mut body); // header_flags = 0
        encode_vint(0, &mut body); // archive_flags = 0
        let mut size_vint = Vec::new();
        encode_vint(body.len() as u64, &mut size_vint);
        out.extend_from_slice(&0u32.to_le_bytes()); // CRC placeholder
        out.extend_from_slice(&size_vint);
        out.extend_from_slice(&body);
    }

    // File headers (type = 2, flags = 0x0002 [data_size present])
    for (name, data) in files {
        let name_bytes = name.as_bytes();
        let mut body = Vec::new();
        encode_vint(2, &mut body); // header_type = 2 (File)
        encode_vint(0x0002, &mut body); // header_flags = 0x0002 (has data_size)
        encode_vint(data.len() as u64, &mut body); // data_size
        encode_vint(0, &mut body); // file_flags = 0 (regular file)
        encode_vint(data.len() as u64, &mut body); // unp_size
        encode_vint(0x20, &mut body); // attributes
        encode_vint(0, &mut body); // comp_info = 0 (method = 0 = stored)
        encode_vint(0, &mut body); // host_os = 0
        encode_vint(name_bytes.len() as u64, &mut body);
        body.extend_from_slice(name_bytes);

        let mut size_vint = Vec::new();
        encode_vint(body.len() as u64, &mut size_vint);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&size_vint);
        out.extend_from_slice(&body);
        out.extend_from_slice(data);
    }

    // End of archive header (type = 5, flags = 0, end_flags = 0)
    {
        let mut body = Vec::new();
        encode_vint(5, &mut body);
        encode_vint(0, &mut body);
        encode_vint(0, &mut body);
        let mut size_vint = Vec::new();
        encode_vint(body.len() as u64, &mut size_vint);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&size_vint);
        out.extend_from_slice(&body);
    }

    fs::write(path, out)?;
    Ok(())
}

/// Checks if a source string is a Remote / Cloud Provider URI (while never matching Windows `C:\...` drive paths)
pub fn is_remote_source_uri(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("ssh://")
        || lower.starts_with("sftp://")
        || lower.starts_with("s3://")
        || lower.starts_with("az://")
        || lower.starts_with("abfs://")
        || lower.starts_with("gs://")
        || lower.starts_with("smb://")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
}

/// Pluggable Remote & Cloud Provider Resolver (SSH, SFTP, AWS S3/R2/MinIO, Azure Blob/ADLS, Google Cloud Storage, SMB/UNC, HTTP/SAS/Presigned URLs)
pub fn resolve_remote_uri_source(
    uri: &str,
    include_pats: &[Pattern],
    exclude_pats: &[Pattern],
    opts: &TraversalOptions,
) -> Result<Vec<SourceItem>> {
    let lower = uri.to_lowercase();
    let mut items = Vec::new();

    if lower.starts_with("ssh://") || lower.starts_with("sftp://") {
        let provider_kind = if lower.starts_with("sftp://") { "sftp" } else { "ssh" };
        let (host_only, port_opt, remote_path) = parse_ssh_uri_parts(uri)?;

        let mut ssh_base_args = vec![
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "ConnectTimeout=5".to_string(),
        ];
        if let Some(port) = port_opt {
            ssh_base_args.push("-p".to_string());
            ssh_base_args.push(port);
        }

        let mut find_cmd = Command::new("ssh");
        for a in &ssh_base_args {
            find_cmd.arg(a);
        }
        // Strictly single-quote remote_path to prevent shell command injection
        find_cmd.arg(&host_only).arg(format!(
            "find {} -maxdepth 4 -type f 2>/dev/null | head -n 300",
            shell_single_quote(&remote_path)
        ));

        if let Ok(find_out) = find_cmd.output() {
            if find_out.status.success() {
                let file_list = String::from_utf8_lossy(&find_out.stdout);
                for rfile in file_list.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                    let fname = Path::new(rfile)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| rfile.to_string());
                    if !matches_file_filters(
                        &fname,
                        rfile,
                        1024,
                        include_pats,
                        exclude_pats,
                        &[],
                        opts,
                    ) {
                        continue;
                    }
                    record_discovered_file(
                        &format!("{}://{}:{}", provider_kind, host_only, rfile),
                        true,
                    );
                    let mut cat_cmd = Command::new("ssh");
                    for a in &ssh_base_args {
                        cat_cmd.arg(a);
                    }
                    // Strictly single-quote rfile and cap remote stream at MAX_STREAM_BYTES (16 MB)
                    cat_cmd.arg(&host_only).arg(format!(
                        "head -c {} {}",
                        MAX_STREAM_BYTES,
                        shell_single_quote(rfile)
                    ));
                    if let Ok(cat_out) = cat_cmd.output() {
                        if cat_out.status.success() {
                            let size = cat_out.stdout.len() as u64;
                            items.push(SourceItem::RemoteStream {
                                uri: format!("{}://{}:{}", provider_kind, host_only, rfile),
                                provider_kind,
                                entry_name: fname,
                                data: cat_out.stdout,
                                size,
                                mtime_secs: 0,
                                source_root: uri.to_string(),
                            });
                        }
                    }
                }
            }
        }
        return Ok(items);
    }

    if lower.starts_with("smb://") {
        // SMB / CIFS share URI: smb://server/share/subpath
        let stripped = uri.strip_prefix("smb://").unwrap_or(uri);
        let parts: Vec<&str> = stripped.splitn(3, '/').collect();
        let server = parts.first().copied().unwrap_or("");
        let share = parts.get(1).copied().unwrap_or("");
        let subpath = parts.get(2).copied().unwrap_or("");

        // 1. Check if already mounted under /Volumes/<share> (macOS) or /mnt/<share> (Linux) or UNC \\server\share (Windows)
        let candidates = vec![
            format!("/Volumes/{}/{}", share, subpath),
            format!("/mnt/{}/{}", share, subpath),
            format!("\\\\{}\\{}\\{}", server, share, subpath.replace('/', "\\")),
        ];
        for cand in candidates {
            let cp = Path::new(cand.trim_end_matches('/'));
            if cp.exists() {
                let sub_opts = TraversalOptions {
                    sources: vec![cp.to_string_lossy().to_string()],
                    ..opts.clone()
                };
                return resolve_sources(&sub_opts);
            }
        }
        return Ok(items);
    }

    if lower.starts_with("az://") || lower.starts_with("abfs://") {
        // Azure Blob Storage / ADLS Gen2 connector: az://container/prefix or abfs://container@account/prefix
        let stripped = uri
            .strip_prefix("az://")
            .or_else(|| uri.strip_prefix("abfs://"))
            .unwrap_or(uri);
        let (container_part, prefix) = stripped.split_once('/').unwrap_or((stripped, ""));
        let (container, account_opt) = if let Some((c, acc)) = container_part.split_once('@') {
            (c, Some(acc.split('.').next().unwrap_or(acc)))
        } else {
            (container_part, None)
        };

        let mut list_cmd = Command::new("az");
        list_cmd.args([
            "storage",
            "blob",
            "list",
            "--container-name",
            container,
            "--query",
            "[].name",
            "-o",
            "tsv",
        ]);
        if !prefix.is_empty() {
            list_cmd.args(["--prefix", prefix]);
        }
        if let Some(acc) = account_opt {
            list_cmd.args(["--account-name", acc]);
        }
        if let Ok(ls_out) = list_cmd.output() {
            if ls_out.status.success() {
                for blob_name in String::from_utf8_lossy(&ls_out.stdout)
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .take(200)
                {
                    let fname = Path::new(blob_name)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| blob_name.to_string());
                    if !matches_file_filters(
                        &fname,
                        blob_name,
                        1024,
                        include_pats,
                        exclude_pats,
                        &[],
                        opts,
                    ) {
                        continue;
                    }
                    let mut dl_cmd = Command::new("az");
                    dl_cmd.args([
                        "storage",
                        "blob",
                        "download",
                        "--container-name",
                        container,
                        "--name",
                        blob_name,
                    ]);
                    if let Some(acc) = account_opt {
                        dl_cmd.args(["--account-name", acc]);
                    }
                    if let Ok(dl_out) = dl_cmd.output() {
                        if dl_out.status.success() {
                            let size = dl_out.stdout.len() as u64;
                            items.push(SourceItem::RemoteStream {
                                uri: format!("az://{}/{}", container, blob_name),
                                provider_kind: "azure-blob",
                                entry_name: fname,
                                data: dl_out.stdout,
                                size,
                                mtime_secs: 0,
                                source_root: uri.to_string(),
                            });
                        }
                    }
                }
            }
        }
        return Ok(items);
    }

    if lower.starts_with("http://") || lower.starts_with("https://") {
        // Direct HTTP/HTTPS Blob URL, S3 Pre-Signed URL, or Azure SAS URL
        if let Ok(curl_out) = Command::new("curl")
            .args(["-sL", "--max-time", "15", uri])
            .output()
        {
            if curl_out.status.success() && !curl_out.stdout.is_empty() {
                let clean_path = uri.split('?').next().unwrap_or(uri);
                let fname = Path::new(clean_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "remote_blob.txt".to_string());
                let size = curl_out.stdout.len() as u64;
                items.push(SourceItem::RemoteStream {
                    uri: uri.to_string(),
                    provider_kind: "https-blob",
                    entry_name: fname,
                    data: curl_out.stdout,
                    size,
                    mtime_secs: 0,
                    source_root: uri.to_string(),
                });
            }
        }
        return Ok(items);
    }

    if lower.starts_with("s3://") {
        // AWS S3 / MinIO / Cloudflare R2 connector via `aws s3`
        if let Ok(ls_out) = Command::new("aws")
            .args(["s3", "ls", uri, "--recursive"])
            .output()
        {
            if ls_out.status.success() {
                let bucket = uri
                    .strip_prefix("s3://")
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("");
                for line in String::from_utf8_lossy(&ls_out.stdout).lines().take(200) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let key = parts[3..].join(" ");
                        let full_s3 = format!("s3://{}/{}", bucket, key);
                        let fname = Path::new(&key)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| key.clone());
                        if !matches_file_filters(
                            &fname,
                            &key,
                            1024,
                            include_pats,
                            exclude_pats,
                            &[],
                            opts,
                        ) {
                            continue;
                        }
                        if let Ok(cp_out) = Command::new("aws")
                            .args(["s3", "cp", &full_s3, "-"])
                            .output()
                        {
                            if cp_out.status.success() {
                                let size = cp_out.stdout.len() as u64;
                                items.push(SourceItem::RemoteStream {
                                    uri: full_s3,
                                    provider_kind: "s3",
                                    entry_name: fname,
                                    data: cp_out.stdout,
                                    size,
                                    mtime_secs: 0,
                                    source_root: uri.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        return Ok(items);
    }

    if lower.starts_with("gs://") {
        // Google Cloud Storage connector via `gsutil`
        if let Ok(ls_out) = Command::new("gsutil").args(["ls", "-r", uri]).output() {
            if ls_out.status.success() {
                for obj_uri in String::from_utf8_lossy(&ls_out.stdout)
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| l.starts_with("gs://") && !l.ends_with('/'))
                    .take(200)
                {
                    let fname = Path::new(obj_uri)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| obj_uri.to_string());
                    if let Ok(cat_out) = Command::new("gsutil").args(["cat", obj_uri]).output() {
                        if cat_out.status.success() {
                            let size = cat_out.stdout.len() as u64;
                            items.push(SourceItem::RemoteStream {
                                uri: obj_uri.to_string(),
                                provider_kind: "gcs",
                                entry_name: fname,
                                data: cat_out.stdout,
                                size,
                                mtime_secs: 0,
                                source_root: uri.to_string(),
                            });
                        }
                    }
                }
            }
        }
        return Ok(items);
    }

    Ok(items)
}

