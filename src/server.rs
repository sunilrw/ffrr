//! ============================================================================
//! Module: `server.rs` — HTTP REST API & Embedded Web Studio (`ffrr serve`)
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! This module implements an asynchronous HTTP server using `axum` (similar to
//! ASP.NET Core Minimal APIs in C#, FastAPI in Python, or Express in Node.js).
//!
//! - `GET  /`               : Serves the single-page Web Studio (`src/ui.html`)
//!                            compiled directly into the binary via `include_str!`.
//! - `GET  /v1/info`        : Returns version, intent packs, and sample paths.
//! - `GET  /v1/progress`    : Real-time polling endpoint returning active scan
//!                            telemetry (`files_discovered`, `files_scanned`,
//!                            `matches_found`, `current_path`, `live_results`).
//! - `POST /v1/cancel`      : Signals atomic cancellation to stop any active scan.
//! - `POST /v1/search`      : Runs multi-threaded Find & Replace (`spawn_blocking`).
//! - `POST /v1/group`       : Runs File Grouping (`spawn_blocking`).
//! - `POST /v1/duplicates`  : Runs Exact & Near-Duplicate detection (`spawn_blocking`).
//! - `POST /v1/intent`      : Runs Context & Intent discovery or refactoring.
//! - `POST /v1/undo`        : Lists or rolls back `.ffrr_backups/` transactions.
//! - `POST /v1/browse`      : Browses local folders, connected USB drives & archives.
//! - `POST /v1/read-file`   : Memory-bounded (512 KB) built-in file/archive reader.
//! - `POST /v1/open-os`     : Reveals file in Finder/Explorer or opens in Editor/Terminal.
//! - `GET|POST /v1/macros`  : Lists, creates, or deletes custom `{{MACRO}}` definitions.
//! - `GET|POST /v1/connections`: Manages saved `@profile` remote/cloud connections.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use crate::archive::{
    cancel_progress_job, decode_bytes, delete_connection_profile, detect_system_drives,
    get_progress_snapshot, is_archive_path, load_connection_profiles, read_bounded_file,
    resolve_sources, save_connection_profile, split_mask_list, SystemDrive, TraversalOptions,
};
use crate::engine::{
    delete_custom_macro, list_custom_macros, run_search_replace, save_custom_macro, ScopeFilter,
    SearchReplaceOptions, TransactionManager,
};
use crate::features::{
    analyze_intents, execute_intent_pack, find_duplicates, group_files, list_intent_packs,
    DuplicateOptions, GroupByMode,
};
use crate::sym::*;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct AppState {
    pub total_requests: AtomicU64,
    pub default_source: Option<String>,
}

#[derive(Deserialize)]
pub struct WebSearchRequest {
    pub sources: Option<Vec<String>>,
    pub source: Option<String>,
    pub file_mask: Option<String>,
    pub exclude_mask: Option<String>,
    pub exclude_dir: Option<String>,
    pub recursive: Option<bool>,
    pub include_archives: Option<bool>,
    pub include_hidden: Option<bool>,
    pub respect_gitignore: Option<bool>,
    pub find: String,
    pub replace: Option<String>,
    pub search_target: Option<String>,
    pub use_regex: Option<bool>,
    pub case_sensitive: Option<bool>,
    pub smart_case: Option<bool>,
    pub whole_word: Option<bool>,
    pub multiline: Option<bool>,
    pub use_escape_chars: Option<bool>,
    pub preserve_case: Option<bool>,
    pub invert_match: Option<bool>,
    pub ignore_binary: Option<bool>,
    pub encoding: Option<String>,
    pub keep_mtime: Option<bool>,
    pub dry_run: Option<bool>,
    pub create_backup: Option<bool>,
    pub context_lines: Option<usize>,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub struct WebGroupRequest {
    pub sources: Option<Vec<String>>,
    pub source: Option<String>,
    pub file_mask: Option<String>,
    pub exclude_mask: Option<String>,
    pub include_archives: Option<bool>,
    pub group_by: Option<String>,
}

#[derive(Deserialize)]
pub struct WebDuplicatesRequest {
    pub sources: Option<Vec<String>>,
    pub source: Option<String>,
    pub file_mask: Option<String>,
    pub exclude_mask: Option<String>,
    pub include_archives: Option<bool>,
    pub normalized_whitespace: Option<bool>,
    pub near_duplicates: Option<bool>,
    pub similarity_threshold: Option<f64>,
    pub min_bytes: Option<u64>,
}

#[derive(Deserialize)]
pub struct WebIntentRequest {
    pub sources: Option<Vec<String>>,
    pub source: Option<String>,
    pub file_mask: Option<String>,
    pub exclude_mask: Option<String>,
    pub include_archives: Option<bool>,
    pub pack: Option<String>,
    pub apply: Option<bool>,
    pub dry_run: Option<bool>,
    pub custom_replace: Option<String>,
}

#[derive(Deserialize)]
pub struct WebUndoRequest {
    pub transaction_id: Option<String>,
    pub list_only: Option<bool>,
}

#[derive(Deserialize)]
pub struct BrowseRequest {
    pub path: Option<String>,
}

#[derive(Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Deserialize)]
pub struct OpenOsRequest {
    pub path: String,
    pub action: Option<String>,
    pub line: Option<usize>,
}

#[derive(Deserialize)]
pub struct MacroRequest {
    pub action: Option<String>, // "list", "save", "delete"
    pub name: Option<String>,
    pub template: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct ConnectionRequest {
    pub action: Option<String>, // "list", "save", "delete"
    pub name: Option<String>,
    pub provider: Option<String>,
    pub uri: Option<String>,
    pub secret_value: Option<String>,
    pub secret_env: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_archive: bool,
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct BrowseResponse {
    pub current_dir: String,
    pub parent_dir: Option<String>,
    pub drives: Vec<SystemDrive>,
    pub entries: Vec<FileEntry>,
}

pub async fn run_http_server(bind_addr: &str, default_source: Option<String>) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        total_requests: AtomicU64::new(0),
        default_source,
    });

    let app = Router::new()
        .route("/", get(serve_web_ui))
        .route("/v1/info", get(handle_info))
        .route("/v1/progress", get(handle_progress))
        .route("/v1/cancel", post(handle_cancel))
        .route("/v1/search", post(handle_search))
        .route("/v1/group", post(handle_group))
        .route("/v1/duplicates", post(handle_duplicates))
        .route("/v1/intent", post(handle_intent))
        .route("/v1/undo", post(handle_undo))
        .route("/v1/browse", post(handle_browse))
        .route("/v1/read-file", post(handle_read_file))
        .route("/v1/open-os", post(handle_open_os))
        .route("/v1/macros", get(handle_macros_get).post(handle_macros_post))
        .route(
            "/v1/connections",
            get(handle_connections_get).post(handle_connections_post),
        )
        .route("/metrics", get(handle_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    eprintln!(
        "{SYM_ROCKET} FFRR Studio v{} listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        bind_addr
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_web_ui() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

fn parse_sources_list(
    sources: Option<Vec<String>>,
    single: Option<String>,
    default_src: Option<String>,
) -> Vec<String> {
    if let Some(arr) = sources {
        let filtered: Vec<String> = arr
            .into_iter()
            .flat_map(|s| {
                s.split(';')
                    .map(|p| p.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }
    if let Some(s) = single {
        let filtered: Vec<String> = s
            .split(';')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }
    if let Some(d) = default_src {
        if !d.trim().is_empty() {
            return vec![d];
        }
    }
    vec!["samples".to_string()]
}

async fn handle_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packs = list_intent_packs();
    let transactions = TransactionManager::list_transactions().unwrap_or_default();
    Json(serde_json::json!({
        "name": "FFRR — Fast Find, Replace & Refactor Engine",
        "version": env!("CARGO_PKG_VERSION"),
        "default_source": state.default_source.clone().unwrap_or_else(|| "samples".to_string()),
        "intent_packs": packs,
        "transactions": transactions,
        "samples": [
            "samples",
            "samples/config",
            "samples/src_code",
            "samples/archives/bundle.zip",
            "samples/archives/release.tar.gz",
            "samples/archives/legacy_pack.rar",
            "samples/archives/app.log.gz",
            "samples/archives/audit.log.zst"
        ]
    }))
}

async fn handle_progress() -> impl IntoResponse {
    Json(get_progress_snapshot())
}

async fn handle_cancel() -> impl IntoResponse {
    cancel_progress_job();
    Json(serde_json::json!({ "status": "cancelled" }))
}

async fn handle_search(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebSearchRequest>,
) -> impl IntoResponse {
    // Cancel any previous running scan before launching the new one
    cancel_progress_job();
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let sources = parse_sources_list(req.sources, req.source, state.default_source.clone());

    let mut traversal = TraversalOptions {
        sources,
        recursive: req.recursive.unwrap_or(true),
        include_archives: req.include_archives.unwrap_or(true),
        include_hidden: req.include_hidden.unwrap_or(false),
        respect_gitignore: req.respect_gitignore.unwrap_or(true),
        ..Default::default()
    };
    if let Some(ref m) = req.file_mask {
        traversal.file_masks = split_mask_list(m);
    }
    if let Some(ref x) = req.exclude_mask {
        traversal.exclude_masks = split_mask_list(x);
    }
    if let Some(ref d) = req.exclude_dir {
        let extra = split_mask_list(d);
        if !extra.is_empty() {
            traversal.exclude_dirs = extra;
        }
    }

    let ctx = req.context_lines.unwrap_or(1);
    let opts = SearchReplaceOptions {
        traversal,
        find: req.find,
        replace: req.replace.filter(|r| !r.is_empty()),
        search_target: req.search_target.unwrap_or_else(|| "both".to_string()),
        use_regex: req.use_regex.unwrap_or(false),
        case_sensitive: req.case_sensitive.unwrap_or(false),
        smart_case: req.smart_case.unwrap_or(true),
        whole_word: req.whole_word.unwrap_or(false),
        multiline: req.multiline.unwrap_or(false),
        use_escape_chars: req.use_escape_chars.unwrap_or(false),
        preserve_case: req.preserve_case.unwrap_or(false),
        invert_match: req.invert_match.unwrap_or(false),
        ignore_binary: req.ignore_binary.unwrap_or(true),
        forced_encoding: req.encoding.filter(|e| !e.is_empty() && e != "auto"),
        always_use_encoding: false,
        show_encoding: true,
        keep_mtime: req.keep_mtime.unwrap_or(false),
        dry_run: req.dry_run.unwrap_or(true),
        create_backup: req.create_backup.unwrap_or(true),
        context_before: ctx,
        context_after: ctx,
        semantic_context: true,
        scope: ScopeFilter::from_str_loose(req.scope.as_deref().unwrap_or("all")),
        max_matches_per_file: None,
    };

    match tokio::task::spawn_blocking(move || run_search_replace(&opts)).await {
        Ok(Ok(mut summary)) => {
            // Keep 100% of engine counts & disk replacements, but cap JSON UI preview arrays
            // so the browser DOM never lags on 100,000+ match repositories
            if summary.results.len() > 500 {
                summary.results.truncate(500);
            }
            for r in &mut summary.results {
                if r.matches.len() > 250 {
                    r.matches.truncate(250);
                }
            }
            (StatusCode::OK, Json(serde_json::to_value(summary).unwrap()))
        }
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebGroupRequest>,
) -> impl IntoResponse {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let sources = parse_sources_list(req.sources, req.source, state.default_source.clone());
    let mut traversal = TraversalOptions {
        sources,
        include_archives: req.include_archives.unwrap_or(true),
        ..Default::default()
    };
    if let Some(ref m) = req.file_mask {
        traversal.file_masks = split_mask_list(m);
    }
    if let Some(ref x) = req.exclude_mask {
        traversal.exclude_masks = split_mask_list(x);
    }
    let mode = GroupByMode::from_str_loose(req.group_by.as_deref().unwrap_or("language"));
    match tokio::task::spawn_blocking(move || group_files(&traversal, mode)).await {
        Ok(Ok(report)) => (StatusCode::OK, Json(serde_json::to_value(report).unwrap())),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_duplicates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebDuplicatesRequest>,
) -> impl IntoResponse {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let sources = parse_sources_list(req.sources, req.source, state.default_source.clone());
    let mut traversal = TraversalOptions {
        sources,
        include_archives: req.include_archives.unwrap_or(true),
        ..Default::default()
    };
    if let Some(ref m) = req.file_mask {
        traversal.file_masks = split_mask_list(m);
    }
    if let Some(ref x) = req.exclude_mask {
        traversal.exclude_masks = split_mask_list(x);
    }

    let dopts = DuplicateOptions {
        traversal,
        normalized_whitespace: req.normalized_whitespace.unwrap_or(false),
        near_duplicates: req.near_duplicates.unwrap_or(true),
        similarity_threshold: req.similarity_threshold.unwrap_or(0.80),
        min_bytes: req.min_bytes.unwrap_or(1),
        delete_duplicates: false,
        dry_run: true,
    };

    match tokio::task::spawn_blocking(move || find_duplicates(&dopts)).await {
        Ok(Ok(report)) => (StatusCode::OK, Json(serde_json::to_value(report).unwrap())),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_intent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebIntentRequest>,
) -> impl IntoResponse {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let sources = parse_sources_list(req.sources, req.source, state.default_source.clone());
    let mut traversal = TraversalOptions {
        sources,
        include_archives: req.include_archives.unwrap_or(true),
        ..Default::default()
    };
    if let Some(ref m) = req.file_mask {
        traversal.file_masks = split_mask_list(m);
    }
    if let Some(ref x) = req.exclude_mask {
        traversal.exclude_masks = split_mask_list(x);
    }

    if req.apply.unwrap_or(false) {
        let pack_id = req.pack.as_deref().unwrap_or("insecure-http");
        let dry_run = req.dry_run.unwrap_or(true);
        match execute_intent_pack(&traversal, pack_id, req.custom_replace, dry_run) {
            Ok(summary) => (StatusCode::OK, Json(serde_json::to_value(summary).unwrap())),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            ),
        }
    } else {
        match analyze_intents(&traversal, req.pack.as_deref()) {
            Ok(report) => (StatusCode::OK, Json(serde_json::to_value(report).unwrap())),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            ),
        }
    }
}

async fn handle_undo(Json(req): Json<WebUndoRequest>) -> impl IntoResponse {
    if req.list_only.unwrap_or(false) {
        let list = TransactionManager::list_transactions().unwrap_or_default();
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "transactions": list })),
        );
    }
    match TransactionManager::undo_transaction(req.transaction_id.as_deref()) {
        Ok((manifest, count)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "restored_files": count,
                "manifest": manifest,
                "transactions": TransactionManager::list_transactions().unwrap_or_default()
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_browse(Json(req): Json<BrowseRequest>) -> impl IntoResponse {
    let raw_path = req
        .path
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| ".".to_string());
    let p = Path::new(&raw_path);
    let target_dir: PathBuf = if p.is_dir() {
        p.to_path_buf()
    } else if let Some(parent) = p.parent() {
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    } else {
        PathBuf::from(".")
    };

    let canonical = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.clone());
    let current_dir = canonical.to_string_lossy().to_string();
    let parent_dir = canonical
        .parent()
        .map(|par| par.to_string_lossy().to_string());

    let mut entries = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&canonical) {
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let is_archive = !is_dir && is_archive_path(&path);
            entries.push(FileEntry {
                name,
                path: path.to_string_lossy().to_string(),
                is_dir,
                is_archive,
                size_bytes,
            });
        }
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));

    Json(BrowseResponse {
        current_dir,
        parent_dir,
        drives: detect_system_drives(),
        entries,
    })
}

async fn handle_read_file(Json(req): Json<ReadFileRequest>) -> impl IntoResponse {
    let raw_path = req.path.trim().to_string();
    let (disk_target, entry_subpath) = if let Some((arc, inner)) = raw_path.split_once("::") {
        (arc.to_string(), Some(inner.to_string()))
    } else {
        (raw_path.clone(), None)
    };

    let max_preview: u64 = 512 * 1024;
    let bytes_res: Result<(Vec<u8>, bool), anyhow::Error> = if let Some(inner) = entry_subpath {
        let t_opts = TraversalOptions {
            sources: vec![disk_target.clone()],
            include_archives: true,
            ..Default::default()
        };
        resolve_sources(&t_opts)
            .ok()
            .and_then(|items| {
                items
                    .into_iter()
                    .find(|it| it.display_path() == raw_path || it.file_name() == inner)
            })
            .and_then(|it| it.read_bytes().ok())
            .map(|mut b| {
                let trunc = b.len() as u64 > max_preview;
                if trunc {
                    b.truncate(max_preview as usize);
                }
                (b, trunc)
            })
            .ok_or_else(|| anyhow::anyhow!("Archive entry `{}` not found", raw_path))
    } else {
        read_bounded_file(Path::new(&disk_target), max_preview)
            .map_err(|e| anyhow::anyhow!("Failed reading `{}`: {}", disk_target, e))
    };

    match bytes_res {
        Ok((bytes, truncated)) => {
            let size_bytes = std::fs::metadata(&disk_target)
                .map(|m| m.len() as usize)
                .unwrap_or(bytes.len());
            let dec = decode_bytes(&bytes, None, false);
            let total_lines = dec.text.lines().count();
            let file_name = Path::new(&raw_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| raw_path.clone());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "path": raw_path,
                    "disk_path": disk_target,
                    "file_name": file_name,
                    "encoding": dec.encoding.as_str(),
                    "is_binary": dec.is_binary,
                    "size_bytes": size_bytes,
                    "total_lines": total_lines,
                    "truncated": truncated,
                    "content": if dec.is_binary {
                        format!("[Binary file — {} bytes. Click 'Open with Default App' or 'Reveal in Finder' above to inspect.]", size_bytes)
                    } else {
                        dec.text
                    }
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_open_os(Json(req): Json<OpenOsRequest>) -> impl IntoResponse {
    use std::process::Command;

    let raw_path = req.path.trim();
    let disk_path = if let Some((arc, _)) = raw_path.split_once("::") {
        arc
    } else {
        raw_path
    };
    let p = Path::new(disk_path);
    if !p.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Path does not exist on disk: {}", disk_path) })),
        );
    }

    let parent_dir = p
        .parent()
        .map(|par| par.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let action = req.action.as_deref().unwrap_or("reveal");
    let line = req.line.unwrap_or(1);

    #[cfg(target_os = "macos")]
    let res = match action {
        "reveal" => Command::new("open").args(["-R", disk_path]).spawn(),
        "open" => Command::new("open").arg(disk_path).spawn(),
        "textedit" => Command::new("open").args(["-t", disk_path]).spawn(),
        "vscode" => Command::new("code")
            .args(["-g", &format!("{}:{}", disk_path, line)])
            .spawn()
            .or_else(|_| Command::new("open").args(["-t", disk_path]).spawn()),
        "terminal" => Command::new("open")
            .args(["-a", "Terminal", &parent_dir])
            .spawn(),
        _ => Command::new("open").args(["-R", disk_path]).spawn(),
    };

    #[cfg(target_os = "windows")]
    let res = match action {
        "reveal" => Command::new("explorer")
            .arg(format!("/select,{}", disk_path))
            .spawn(),
        "open" => Command::new("cmd")
            .args(["/C", "start", "", disk_path])
            .spawn(),
        "textedit" => Command::new("notepad").arg(disk_path).spawn(),
        "vscode" => Command::new("cmd")
            .args(["/C", "code", "-g", &format!("{}:{}", disk_path, line)])
            .spawn()
            .or_else(|_| Command::new("notepad").arg(disk_path).spawn()),
        "terminal" => Command::new("cmd")
            .args([
                "/C",
                "start",
                "powershell",
                "-NoExit",
                "-Command",
                &format!("Set-Location -LiteralPath '{}'", parent_dir.replace('\'', "''")),
            ])
            .spawn(),
        _ => Command::new("explorer")
            .arg(format!("/select,{}", disk_path))
            .spawn(),
    };

    #[cfg(target_os = "linux")]
    let res = match action {
        "reveal" => Command::new("xdg-open").arg(&parent_dir).spawn(),
        "open" | "textedit" => Command::new("xdg-open").arg(disk_path).spawn(),
        "vscode" => Command::new("code")
            .args(["-g", &format!("{}:{}", disk_path, line)])
            .spawn()
            .or_else(|_| Command::new("xdg-open").arg(disk_path).spawn()),
        "terminal" => Command::new("x-terminal-emulator")
            .args(["--working-directory", &parent_dir])
            .spawn(),
        _ => Command::new("xdg-open").arg(&parent_dir).spawn(),
    };

    match res {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ok", "action": action, "path": disk_path })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_macros_get() -> impl IntoResponse {
    Json(serde_json::json!({ "macros": list_custom_macros() }))
}

async fn handle_macros_post(Json(req): Json<MacroRequest>) -> impl IntoResponse {
    let act = req.action.as_deref().unwrap_or("list");
    match act {
        "save" | "add" => {
            let name = req.name.unwrap_or_default();
            let tpl = req.template.unwrap_or_default();
            let desc = req.description.unwrap_or_default();
            match save_custom_macro(&name, &tpl, &desc) {
                Ok(list) => (StatusCode::OK, Json(serde_json::json!({ "macros": list }))),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                ),
            }
        }
        "delete" | "remove" => {
            let name = req.name.unwrap_or_default();
            match delete_custom_macro(&name) {
                Ok(list) => (StatusCode::OK, Json(serde_json::json!({ "macros": list }))),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                ),
            }
        }
        _ => (
            StatusCode::OK,
            Json(serde_json::json!({ "macros": list_custom_macros() })),
        ),
    }
}

async fn handle_connections_get() -> impl IntoResponse {
    Json(serde_json::json!({ "connections": load_connection_profiles() }))
}

async fn handle_connections_post(Json(req): Json<ConnectionRequest>) -> impl IntoResponse {
    let act = req.action.as_deref().unwrap_or("list");
    match act {
        "save" | "add" => {
            let name = req.name.unwrap_or_default();
            let provider = req.provider.unwrap_or_else(|| "ssh".to_string());
            let uri = req.uri.unwrap_or_default();
            let desc = req.description.unwrap_or_default();
            match save_connection_profile(
                &name,
                &provider,
                &uri,
                req.secret_value.as_deref(),
                req.secret_env.as_deref(),
                &desc,
            ) {
                Ok(list) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "connections": list,
                        "drives": detect_system_drives()
                    })),
                ),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                ),
            }
        }
        "delete" | "remove" => {
            let name = req.name.unwrap_or_default();
            match delete_connection_profile(&name) {
                Ok(list) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "connections": list,
                        "drives": detect_system_drives()
                    })),
                ),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                ),
            }
        }
        _ => (
            StatusCode::OK,
            Json(serde_json::json!({ "connections": load_connection_profiles() })),
        ),
    }
}

async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let total = state.total_requests.load(Ordering::Relaxed);
    format!(
        "# HELP ffrr_requests_total Total API requests processed\n# TYPE ffrr_requests_total counter\nffrr_requests_total {}\n",
        total
    )
}
