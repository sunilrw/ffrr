# FFRR — Fast Find, Replace & Refactor Engine v1.0.0
**(File Find and Replace in Rust)**

**Modern Multi-Threaded Find, Replace, Archive Search, File Grouping, Duplicate Finder & Context/Intent Refactoring Engine**  
*Single Cross-Platform Executable: CLI + Ratatui TUI + Web Studio + Native Desktop GUI + AI Agent MCP Server*  
**Made using vibe coding by Sunil Warrier**

[![License: MIT OR Unlicense](https://img.shields.io/badge/License-MIT%20%2F%20Unlicense-brightgreen.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](Cargo.toml)
[![Archives: .zip .rar .tar.gz .gz .zst](https://img.shields.io/badge/Archives-.zip%20.rar%20.tar.gz%20.gz%20.zst-blue.svg)](src/archive.rs)

```text
  _____ _____ ____  ____  
 |  ___|  ___|  _ \|  _ \   FFRR v1.0.0 — Fast Find, Replace & Refactor Engine
 | |_  | |_  | |_) | |_) |  (File Find and Replace in Rust)
 |  _| |  _| |  _ <|  _ <   Multi-Threaded | Archive-Native (.zip/.rar/.gz/.tar.gz/.zst)
 |_|   |_|   |_| \_\_| \_\  Context & Intent Engine | File Grouping & Dedup | CLI+TUI+Web+GUI+MCP
                            Made using vibe coding by Sunil Warrier
====================================================================================
```

---

## Overview

`ffrr` is a zero-dependency, single-binary replacement and modernization of **[findandreplace.io](https://findandreplace.io/)** (`zzzprojects/findandreplace` / `fnr.exe`), combined with the best capabilities of Linux/macOS CLI power tools (`ripgrep`, `sed`, `sd`, `fd`, `fdupes`) and our **LPR** single-executable architecture.

---

## Key Features

### 1. 100% Classic `fnr.exe` Compatibility + Modern Linux/macOS CLI Flags
- **Drop-In `fnr.exe` Support**: Accepts `--cl`, `--dir`, `--fileMask`, `--excludeFileMask`, `--excludeDir`, `--includeSubDirectories`, `--caseSensitive`, `--useRegEx`, `--find`, `--replace`, `--useEscapeChars`, `--encoding`, `--alwaysUseEncoding`, `--showEncoding`, `--ignoreBinaryFile`, `--KeepModifiedDate`, `--setErrorLevelIfAnyFileErrors`, `--silent`, and `--logFile`.
- **Command Line Generator (`ffrr gen-cmd` & Web Studio)**: Generates ready-to-copy CLI commands for `ffrr`, `fnr.exe`, `ripgrep + sed`, and `PowerShell`.
- **3 Match Target Modes**:
  - **Both (`Filename + Contents`)**: Matches filenames/paths and searches inside file contents.
  - **Filename / Path Only (`--filename-only`)**: Instant `Everything`/`fd`-style filename search across 350,000+ files without reading content bytes.
  - **File Contents Only (`--content-only`)**: Classic content-only search.

### 2. Archive-Native Search & In-Place Replacement (`.zip`, `.rar`, `.tar.gz`, `.gz`, `.zst`, `.bz2`)
- Directly searches inside `.zip`, `.rar` (native pure-Rust RAR v4 & RAR v5 parser + CLI fallback), `.tar.gz` / `.tgz`, `.tar`, `.tar.zst`, `.tar.bz2`, `.gz`, `.zst`, and `.bz2` without extracting temporary files to disk.
- Supports in-place replacement write-back for `.zip`, `.gz`, `.zst`, `.bz2`, local disk files, and remote URIs (`ssh://`, `sftp://`, `s3://`, `az://`, `gs://`).
- **Memory & Bomb Safe**: All file and archive streams are bounded (`MAX_STREAM_BYTES = 16 MB`) with `Read::take`, protecting against Zip-Bombs, Tar-Bombs, and multi-gigabyte binary files.

### 3. Multi-Drive, USB & Pluggable Cloud/Remote Connectors
- **Cross-Platform Drive & USB Discovery (`ffrr drives`)**: Automatically detects macOS `/` & `/Volumes/*`, Windows `C:\..Z:\` & UNC shares, and Linux `/`, `/mnt/*`, `/media/*`, and `/proc/mounts` partitions.
- **Remote & Cloud URIs + Saved `@Profiles` (`ffrr connections`)**:
  - `ssh://user@host[:port]/path` & `sftp://user@host[:port]/path`
  - `smb://server/share/path` & `\\server\share\path`
  - `s3://bucket/prefix` (AWS S3 / Cloudflare R2 / MinIO)
  - `az://container/prefix` & `abfs://container@account/prefix` (Azure Blob / ADLS Gen2)
  - `gs://bucket/prefix` (Google Cloud Storage)
  - `https://...` (Direct Blob / Pre-Signed S3 / Azure SAS URLs)
  - Credentials can be vaulted in **macOS Keychain**, **Windows DPAPI**, **Linux `secret-tool`**, or `env:VAR_NAME` so no plaintext secrets are stored in `ffrr.connections.json`.

### 4. Context, Lexical Scope & Smart Case-Preserving Refactoring
- **Enclosing Semantic Context**: Reports the nearest enclosing `fn`, `struct`, `class`, `def`, `[section]`, or `# Heading` for each match.
- **Lexical Scope Filtering (`--scope`)**: Restrict matches to `code` (skips comments and strings), `comments` only, `strings` only, config `keys` only, or config `values` only.
- **Smart Case-Preserving Replace (`-P / --preserve-case`)**: Replacing `-f "legacy_user_id" -r "account_id" -P` automatically transforms `legacy_user_id` -> `account_id`, `LegacyUserId` -> `AccountId`, `LEGACY_USER_ID` -> `ACCOUNT_ID`, and `legacyUserId` -> `accountId`.
- **20 Built-In Macros + User-Defined Custom Macros (`ffrr macros`)**:
  - Built-in: `{{UPPER}}`, `{{LOWER}}`, `{{SNAKE}}`, `{{CAMEL}}`, `{{PASCAL}}`, `{{KEBAB}}`, `{{SHA256}}`, `{{BLAKE3}}`, `{{REDACT}}`, `{{BASE64}}`, `{{FILE}}`, `{{LINE}}`, `{{MATCH_INDEX}}`, `{{DATE}}`, `{{TIMESTAMP}}`, `{{URLENCODE}}`, `{{URLDECODE}}`, `{{REVERSE}}`, `{{LEN}}`, `{{ENV:VAR}}`.
  - Custom: Create reusable `{{MY_MACRO}}` templates via `ffrr macros --add 'MY_TAG=/* {{DATE}} */ {{MATCH}}'` or in the Web Studio UI.

### 5. File Grouping, Duplicate Finder, Intent Analyzer & Transactional Undo
- **File Grouping (`ffrr group`)**: Group files across folders and archives by `language`, `extension`, `source`, `directory`, `size`, `encoding`, or `age`.
- **Exact & Near-Duplicate Finder (`ffrr dupes`)**: Finds exact byte-identical files (BLAKE3 + SHA-256), CRLF/whitespace-normalized duplicates (`--normalized`), and fuzzy near-duplicates (`--near`, 3-gram Jaccard shingle similarity).
- **Context & Intent Analyzer (`ffrr intent`)**: Built-in packs for `secrets`, `pii`, `insecure-http`, `todos`, `conflicts`, `localhost-ports`, `deprecated`, and `console-debug`.
- **Transactional Undo (`ffrr undo`)**: Every replacement snapshots original files into `.ffrr_backups/<tx_id>/` for one-command rollback.

### 6. Five Interfaces in One Executable
- **CLI**: `ffrr -f "http://" -r "https://" -d samples --dry-run --diff`
- **Web Studio & REST API**: `ffrr serve --bind 127.0.0.1:8090` (with Live Progress Gauge, Built-In File Reader, and 1-click **Open in Finder / Explorer / VS Code / Terminal**)
- **Interactive Terminal UI**: `ffrr tui`
- **Native Desktop GUI**: `ffrr gui`
- **AI Agent MCP Server**: `ffrr mcp` (run `ffrr mcp --config` to print the JSON config for Claude Desktop, Cursor, Windsurf, or Devin)

---

## Complete CLI Switch Reference

| Switch | Classic `fnr.exe` Equivalent | Description |
|---|---|---|
| `-f, --find <PAT>` | `--find` | Literal or regex pattern to find |
| `-r, --replace <STR>` | `--replace` | Replacement text (supports `$1` and `{{MACROS}}`) |
| `-d, --dir <PATH>` | `--dir` | Target folder, file, archive, `@profile`, or remote URI |
| `-m, --file-mask <M>` | `--fileMask` | Include file masks (`"*.rs,*.cs,*.json"`) |
| `-x, --exclude-mask <M>` | `--excludeFileMask` | Exclude file masks (`"*.dll,*.exe"`) |
| `--exclude-dir <DIRS>` | `--excludeDir` | Exclude directory names |
| `--no-recursive` | *(inverts `--includeSubDirectories`)* | Disable subdirectory recursion |
| `--no-archives` | — | Skip searching inside `.zip/.rar/.tar.gz/.gz/.zst` |
| `-E, --regex` | `--useRegEx` | Regular expression matching |
| `-s, --case-sensitive` | `--caseSensitive` | Case-sensitive matching |
| `-i, --ignore-case` | — | Case-insensitive matching |
| `-w, --word-regexp` | — | Match whole words only |
| `-P, --preserve-case` | — | Smart case-preserving replacement |
| `--escape` | `--useEscapeChars` | Parse `\n`, `\r`, `\t`, `\xHH` escape sequences |
| `--filename-only` | — | Instant filename/path-only search |
| `--content-only` | — | Search inside file contents only |
| `--scope <SCOPE>` | — | `all`, `code`, `comments`, `strings`, `keys`, `values` |
| `-n, --dry-run` | — | Preview replacements without modifying disk |
| `--diff` | — | Print unified diff of changes |
| `--encoding <ENC>` | `--encoding` | Force encoding (`utf-8`, `utf-16le`, `windows-1252`, etc.) |
| `--keep-mtime` | `--KeepModifiedDate` | Preserve original file modification timestamp |
| `-B / -A / -C <N>` | — | Leading, trailing, or combined context lines |
| `-o, --output <FMT>` | — | `table`, `compact`, `diff`, `json`, `csv`, `files` |
| `-j, --threads <N>` | — | Parallel worker threads (default: 4) |
| `-q, --quiet` | `--silent` | Suppress banner and summary footer |
| `--log-file <PATH>` | `--logFile` | Write execution summary log to file |

---

## License

Released under the **MIT License** and **The Unlicense** (dual-licensed).  
**Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software for any purpose, commercial or non-commercial.**

**Made using vibe coding by Sunil Warrier**
