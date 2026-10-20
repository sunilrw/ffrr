# FFRR Technical Context & Developer Specification

**Name:** FFRR — Fast Find, Replace & Refactor Engine (File Find and Replace in Rust)
**Version:** 1.0.0
**Attribution:** Made using vibe coding by Sunil Warrier
**License:** MIT OR The Unlicense

---

## 1. Architecture Overview

```
CLI args ──preprocess_cli_args (fnr.exe + modern Unix/macOS flags)──> clap Cli
  ├── Default (Find & Replace):
  │     archive::resolve_sources (Disk, Globs, .zip, .rar [RAR4/RAR5], .tar.gz, .tar, .gz, .zst, .bz2, stdin)
  │     ──> rayon::par_iter across SourceItems
  │     ──> archive::decode_bytes (UTF-8, UTF-8-BOM, UTF-16LE, UTF-16BE, Win-1252, ASCII, Binary detection)
  │     ──> engine::run_search_replace (Regex/Literal, SmartCase, WholeWord, PreserveCase, ScopeFilter,
  │                                     Semantic Context, Dynamic Macros, Unified Diff, Transaction Backup)
  ├── Subcommand `group`:   features::group_files (Language, Extension, Source/Archive, Directory, Size, Encoding, Age)
  ├── Subcommand `dupes`:   features::find_duplicates (Size pre-filter -> BLAKE3 + SHA-256 + Normalized CRLF + Jaccard Near-Dupes)
  ├── Subcommand `intent`:  features::analyze_intents / execute_intent_pack (secrets, pii, insecure-http, todos, conflicts, etc.)
  ├── Subcommand `undo`:    engine::TransactionManager (.ffrr_backups/<tx_id>/manifest.json atomic rollback)
  ├── Subcommand `gen-cmd`: engine::generate_cli_equivalents (ffrr, fnr.exe, ripgrep+sed, PowerShell)
  ├── Subcommand `tui`:     tui::run_tui (Ratatui interactive terminal dashboard)
  ├── Subcommand `serve`:   server::run_http_server (Axum REST API + embedded FFRR Web Studio `src/ui.html`)
  ├── Subcommand `gui`:     gui::launch_native_desktop_gui (tao + wry native window)
  └── Subcommand `mcp`:     mcp::run_mcp_stdio_server (JSON-RPC 2.0 Model Context Protocol server)
```

## 2. Key Capabilities Over Classic `findandreplace.io` (`fnr.exe`)

1. **100% `fnr.exe` Drop-In CLI Compatibility**: Accepts `--cl`, `--dir`, `--fileMask`, `--excludeFileMask`, `--excludeDir`, `--includeSubDirectories`, `--caseSensitive`, `--useRegEx`, `--find`, `--replace`, `--useEscapeChars`, `--encoding`, `--alwaysUseEncoding`, `--showEncoding`, `--ignoreBinaryFile`, `--KeepModifiedDate`, `--setErrorLevelIfAnyFileErrors`, `--silent`, `--logFile`.
2. **Multi-Threaded Parallel Engine (`rayon`)**: Parses directories, decompresses archives, matches patterns, and computes cryptographic hashes across CPU cores (`-j / --threads`).
3. **Archive-Native Search & In-Place Replace**: Directly searches inside `.zip`, `.rar` (RAR v4 & RAR v5), `.tar.gz`/`.tgz`, `.tar`, `.tar.zst`, `.tar.bz2`, `.gz`, `.zst`, and `.bz2` without manual extraction, and supports in-place write-back for `.zip`, `.gz`, `.zst`, `.bz2`, and disk files.
4. **Context & Lexical Scope Understanding**:
   - Enclosing semantic block detection (`fn`, `struct`, `class`, `def`, `[section]`, `# Heading`).
   - Lexical scope filtering (`--scope all|code|comments|strings|keys|values`).
   - Built-in Intent Packs (`secrets`, `pii`, `insecure-http`, `todos`, `conflicts`, `localhost-ports`, `deprecated`, `console-debug`).
5. **Smart Case-Preserving Replace (`-P`) & Dynamic Macros**:
   - Preserves `camelCase`, `PascalCase`, `snake_case`, `kebab-case`, `UPPERCASE`, `lowercase`.
   - Dynamic macros: `{{UPPER}}`, `{{LOWER}}`, `{{SNAKE}}`, `{{CAMEL}}`, `{{PASCAL}}`, `{{KEBAB}}`, `{{SHA256}}`, `{{BLAKE3}}`, `{{REDACT}}`, `{{BASE64}}`, `{{FILE}}`, `{{LINE}}`, `{{MATCH_INDEX}}`.
6. **File Grouping & Exact/Near Duplicate Detection**:
   - Group files by language, extension, source/archive, directory, size tier, encoding, or age.
   - Multi-stage duplicate detection (byte size -> BLAKE3/SHA-256 -> CRLF-normalized -> 3-gram Jaccard shingle near-duplicate clustering).
7. **Transactional Undo Journal (`.ffrr_backups/`)**: Every live replacement automatically snapshots original bytes and metadata so `ffrr undo` restores files cleanly.
