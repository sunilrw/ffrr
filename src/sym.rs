//! ============================================================================
//! Module: `sym.rs` — Cross-Platform Terminal Symbol & Badge Abstraction
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! In C#, Java, Python, or JavaScript, printing Unicode symbols or emojis to a
//! legacy Windows console (`conhost.exe` or PowerShell 5.1) often renders
//! garbled question marks (`?`).
//!
//! This module provides a tiny wrapper struct `Sym(preferred_str, ascii_fallback)`
//! that automatically detects whether the active terminal supports modern text
//! output or requires strict 7-bit ASCII, and implements Rust's `Display` trait
//! (equivalent to `toString()` in Java/C#/JS or `__str__()` in Python).
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

#![allow(dead_code)]
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Global atomic flag storing whether plain ASCII mode is active.
/// `AtomicBool` is thread-safe without needing a heavy mutex lock.
static ASCII_MODE: AtomicBool = AtomicBool::new(false);

/// `OnceLock` ensures terminal detection runs only once on first use
/// (similar to `Lazy<T>` in C# or `sync.Once` in Go).
static DETECTED: OnceLock<()> = OnceLock::new();

/// Inspects environment variables (`FFRR_ASCII`, `NO_EMOJI`, `TERM`, etc.)
/// to decide whether to use compact ASCII badges.
fn detect_ascii() -> bool {
    if std::env::var_os("FFRR_EMOJI").is_some() || std::env::var_os("LPR_EMOJI").is_some() {
        return false;
    }
    if std::env::var_os("FFRR_ASCII").is_some()
        || std::env::var_os("LPR_ASCII").is_some()
        || std::env::var_os("NO_EMOJI").is_some()
    {
        return true;
    }
    if cfg!(windows) {
        // Modern Windows terminals set WT_SESSION (Windows Terminal),
        // TERM_PROGRAM (VS Code), or WEZTERM_EXECUTABLE.
        return std::env::var_os("WT_SESSION").is_none()
            && std::env::var_os("TERM_PROGRAM").is_none()
            && std::env::var_os("WEZTERM_EXECUTABLE").is_none()
            && std::env::var("ConEmuANSI").map(|v| v != "ON").unwrap_or(true);
    }
    matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
}

/// Ensures `detect_ascii()` has been evaluated at least once.
fn ensure_detected() {
    DETECTED.get_or_init(|| ASCII_MODE.store(detect_ascii(), Ordering::Relaxed));
}

/// Explicitly forces ASCII mode on (triggered when user passes `--ascii`).
pub fn force_ascii() {
    ensure_detected();
    ASCII_MODE.store(true, Ordering::Relaxed);
}

/// Returns `true` if plain ASCII output mode is active.
pub fn ascii_mode() -> bool {
    ensure_detected();
    ASCII_MODE.load(Ordering::Relaxed)
}

/// Represents a dual-mode terminal badge:
/// - `.0` is displayed on modern terminals.
/// - `.1` is displayed when `--ascii` or a legacy console is detected.
pub struct Sym(pub &'static str, pub &'static str);

impl Display for Sym {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(if ascii_mode() { self.1 } else { self.0 })
    }
}

impl Sym {
    /// Returns the active string slice directly for TUI widgets.
    pub fn s(&self) -> &'static str {
        if ascii_mode() {
            self.1
        } else {
            self.0
        }
    }
}

pub static SYM_OK: Sym = Sym("[OK]", "[OK]");
pub static SYM_DONE: Sym = Sym("[DONE]", "[OK]");
pub static SYM_FAIL: Sym = Sym("[ERR]", "[X]");
pub static SYM_WARN: Sym = Sym("[WARN]", "[!]");
pub static SYM_TIP: Sym = Sym("[TIP]", "[i]");
pub static SYM_BULLET: Sym = Sym("*", "-");
pub static SYM_ARROW: Sym = Sym("->", "->");
pub static SYM_SEARCH: Sym = Sym("[FIND]", "[?]");
pub static SYM_REPLACE: Sym = Sym("[REPL]", "[R]");
pub static SYM_DUP: Sym = Sym("[DUP]", "[D]");
pub static SYM_GROUP: Sym = Sym("[GRP]", "[G]");
pub static SYM_INTENT: Sym = Sym("[INTENT]", "[I]");
pub static SYM_ARCHIVE: Sym = Sym("[ARC]", "[A]");
pub static SYM_ROCKET: Sym = Sym("[FFRR]", "[*]");
pub static SYM_SEL: Sym = Sym("> ", "> ");
