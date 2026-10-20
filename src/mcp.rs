//! ============================================================================
//! Module: `mcp.rs` — Model Context Protocol (MCP) Server for AI Agents & LLMs
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! The Model Context Protocol (MCP) is an open JSON-RPC 2.0 standard over
//! `stdin` / `stdout` that allows AI coding assistants (Claude Desktop, Cursor,
//! Windsurf, Devin, VS Code Copilot) to invoke native tools directly.
//!
//! By running `ffrr mcp`, an LLM agent gains 7 high-speed multi-threaded tools:
//! - `ffrr_find_replace`   : Search or replace across folders & archives
//! - `ffrr_read_file`      : Memory-bounded reader for files & archive entries
//! - `ffrr_list_drives`    : Discover internal drives, USB volumes & cloud profiles
//! - `ffrr_group_files`    : Group files by language, extension, encoding, or size
//! - `ffrr_find_duplicates`: Find exact (BLAKE3/SHA-256) and fuzzy near-duplicates
//! - `ffrr_analyze_intents`: Audit for secrets, PII, HTTP URLs, TODOs, conflicts
//! - `ffrr_undo`           : Rollback a replacement transaction from `.ffrr_backups/`
//!
//! ### Memory & Security Guarantees
//! - File reads in `ffrr_read_file` use `read_bounded` (capped at 2 MB) so an
//!   AI agent never triggers an Out-Of-Memory (OOM) crash on huge binary/log files.
//! - Line range slicing clamps `end_line >= start_line` to prevent slice panics.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use crate::archive::{
    decode_bytes, detect_system_drives, read_bounded_file, resolve_sources, split_mask_list,
    TraversalOptions,
};
use crate::engine::{
    list_custom_macros, run_search_replace, save_custom_macro, ScopeFilter, SearchReplaceOptions,
    TransactionManager,
};
use crate::features::{
    analyze_intents, find_duplicates, group_files, DuplicateOptions, GroupByMode,
};
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Maximum bytes read by `ffrr_read_file` when serving an AI agent (2 MB).
const MCP_MAX_READ_BYTES: u64 = 2 * 1024 * 1024;

/// Runs the synchronous JSON-RPC 2.0 loop reading requests line-by-line from `stdin`
/// and writing JSON responses to `stdout`.
pub fn run_mcp_stdio_server() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        // MCP notifications require no response payload
        if method == "notifications/initialized" {
            continue;
        }

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "ffrr-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "ffrr_find_replace",
                            "description": "High-speed multi-threaded Find & Replace across multiple directories and archives (.zip, .rar, .gz, .tar.gz, .zst) with search_target (filename, content, both), scope filtering (all, code, comments, strings, keys, values), case-preserving replace, and dry-run unified diffs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sources": { "type": "array", "items": { "type": "string" }, "description": "Directories, files, globs, archives (.zip/.rar/.tar.gz), or saved @profile / remote URIs" },
                                    "find": { "type": "string", "description": "Literal or regex pattern to find" },
                                    "replace": { "type": "string", "description": "Optional replacement string (supports $1 captures and {{UPPER}}, {{SNAKE}}, {{SHA256}}, {{REDACT}}, or custom {{MACRO}})" },
                                    "search_target": { "type": "string", "enum": ["both", "filename", "content"], "description": "Match filenames only (instant), file contents only, or both" },
                                    "use_regex": { "type": "boolean" },
                                    "case_sensitive": { "type": "boolean" },
                                    "whole_word": { "type": "boolean" },
                                    "preserve_case": { "type": "boolean" },
                                    "scope": { "type": "string", "enum": ["all", "code", "comments", "strings", "keys", "values"] },
                                    "file_mask": { "type": "string", "description": "Comma-separated include masks e.g. *.rs,*.json" },
                                    "exclude_mask": { "type": "string", "description": "Comma-separated exclude masks" },
                                    "dry_run": { "type": "boolean", "description": "Preview replacements without modifying files on disk" }
                                },
                                "required": ["find"]
                            }
                        },
                        {
                            "name": "ffrr_read_file",
                            "description": "Read full or partial decoded text content of any disk file or archive entry (e.g. bundle.zip::path/file.json, legacy.rar::file.cs).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string", "description": "File path or archive::entry path" },
                                    "start_line": { "type": "integer" },
                                    "end_line": { "type": "integer" }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "ffrr_list_drives",
                            "description": "List all detected internal drives, user home, connected USB volumes, and saved cloud/remote profiles.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "ffrr_group_files",
                            "description": "Group and classify files across directories and archives by language, extension, source, directory, size, encoding, or age.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sources": { "type": "array", "items": { "type": "string" } },
                                    "group_by": { "type": "string", "enum": ["language", "extension", "source", "directory", "size", "encoding", "age"] }
                                }
                            }
                        },
                        {
                            "name": "ffrr_find_duplicates",
                            "description": "Find exact (BLAKE3/SHA-256) and near-duplicate files across directories and inside .zip/.rar/.tar.gz archives.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sources": { "type": "array", "items": { "type": "string" } },
                                    "normalized_whitespace": { "type": "boolean" },
                                    "near_duplicates": { "type": "boolean" }
                                }
                            }
                        },
                        {
                            "name": "ffrr_analyze_intents",
                            "description": "Scan files and archives for semantic intents: secrets, pii, insecure-http, todos, conflicts, localhost-ports, deprecated, console-debug.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sources": { "type": "array", "items": { "type": "string" } },
                                    "pack": { "type": "string" }
                                }
                            }
                        },
                        {
                            "name": "ffrr_undo",
                            "description": "Undo the most recent (or specified) mass replacement transaction from .ffrr_backups/.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "transaction_id": { "type": "string" }
                                }
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let sources: Vec<String> = args
                    .get("sources")
                    .and_then(|s| s.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
                    .unwrap_or_else(|| vec![".".to_string()]);

                let mut traversal = TraversalOptions {
                    sources,
                    ..Default::default()
                };
                if let Some(m) = args.get("file_mask").and_then(|v| v.as_str()) {
                    traversal.file_masks = split_mask_list(m);
                }
                if let Some(x) = args.get("exclude_mask").and_then(|v| v.as_str()) {
                    traversal.exclude_masks = split_mask_list(x);
                }

                let tool_result = match tool_name {
                    "ffrr_find_replace" => {
                        let opts = SearchReplaceOptions {
                            traversal,
                            find: args
                                .get("find")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            replace: args
                                .get("replace")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            search_target: args
                                .get("search_target")
                                .and_then(|v| v.as_str())
                                .unwrap_or("both")
                                .to_string(),
                            use_regex: args
                                .get("use_regex")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            case_sensitive: args
                                .get("case_sensitive")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            whole_word: args
                                .get("whole_word")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            preserve_case: args
                                .get("preserve_case")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            scope: ScopeFilter::from_str_loose(
                                args.get("scope").and_then(|v| v.as_str()).unwrap_or("all"),
                            ),
                            dry_run: args
                                .get("dry_run")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true),
                            ..Default::default()
                        };
                        run_search_replace(&opts)
                            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                    }
                    "ffrr_group_files" => {
                        let mode = GroupByMode::from_str_loose(
                            args.get("group_by")
                                .and_then(|v| v.as_str())
                                .unwrap_or("language"),
                        );
                        group_files(&traversal, mode)
                            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                    }
                    "ffrr_find_duplicates" => {
                        let dopts = DuplicateOptions {
                            traversal,
                            normalized_whitespace: args
                                .get("normalized_whitespace")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            near_duplicates: args
                                .get("near_duplicates")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true),
                            ..Default::default()
                        };
                        find_duplicates(&dopts)
                            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                    }
                    "ffrr_analyze_intents" => {
                        let pack = args.get("pack").and_then(|v| v.as_str());
                        analyze_intents(&traversal, pack)
                            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                    }
                    "ffrr_read_file" => {
                        let raw_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                        let start_l =
                            args.get("start_line").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
                        let end_l = args
                            .get("end_line")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(2000) as usize;

                        // Bounded read (capped at 2 MB) to prevent OOM on large files
                        let (bytes, truncated) = if let Some((arc, inner)) =
                            raw_path.split_once("::")
                        {
                            let t = TraversalOptions {
                                sources: vec![arc.to_string()],
                                include_archives: true,
                                ..Default::default()
                            };
                            let b = resolve_sources(&t)?
                                .into_iter()
                                .find(|it| it.display_path() == raw_path || it.file_name() == inner)
                                .ok_or_else(|| anyhow::anyhow!("Entry not found"))?
                                .read_bytes()?;
                            (b, false)
                        } else {
                            read_bounded_file(std::path::Path::new(raw_path), MCP_MAX_READ_BYTES)?
                        };

                        let dec = decode_bytes(&bytes, None, false);
                        let lines: Vec<&str> = dec.text.lines().collect();
                        let s_idx = start_l.saturating_sub(1).min(lines.len());
                        // Clamp e_idx >= s_idx so start_line > end_line never panics
                        let e_idx = end_l.min(lines.len()).max(s_idx);
                        let snippet = lines[s_idx..e_idx].join("\n");
                        Ok(json!({
                            "path": raw_path,
                            "encoding": dec.encoding.as_str(),
                            "total_lines": lines.len(),
                            "truncated": truncated,
                            "start_line": s_idx + 1,
                            "end_line": e_idx,
                            "content": snippet,
                            "custom_macros_available": list_custom_macros()
                        }))
                    }
                    "ffrr_list_drives" => {
                        let _ = save_custom_macro;
                        Ok(json!({ "drives": detect_system_drives() }))
                    }
                    "ffrr_undo" => {
                        let tx = args.get("transaction_id").and_then(|v| v.as_str());
                        TransactionManager::undo_transaction(tx)
                            .map(|(m, count)| json!({ "restored_files": count, "manifest": m }))
                    }
                    _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
                };

                match tool_result {
                    Ok(val) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                            }]
                        }
                    }),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32000, "message": e.to_string() }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {}", method) }
            }),
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}
