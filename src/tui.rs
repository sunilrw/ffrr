//! ============================================================================
//! Module: `tui.rs` — Interactive Terminal Dashboard (`ffrr tui`)
//! ============================================================================
//!
//! ### Purpose (For Developers from Any Language)
//! Built with `ratatui` and `crossterm`, this module provides a full-screen
//! keyboard-driven Terminal User Interface (TUI) for SSH sessions or terminal
//! workflows:
//! - `F1`: Find & Replace Studio
//! - `F2`: File Grouping & Classification
//! - `F3`: Exact & Near-Duplicate File Finder
//! - `F4`: Context & Intent Analyzer
//! - `Tab`: Cycle between Sources, File Mask, Find, and Replace fields
//! - `Enter`: Execute active tab
//! - `Ctrl+R` / `Ctrl+S` / `Ctrl+P` / `Ctrl+O`: Toggle Regex, Case, PreserveCase, Scope
//! - `Esc` / `Ctrl+C`: Exit cleanly and restore terminal state
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use crate::archive::{split_mask_list, TraversalOptions};
use crate::engine::{run_search_replace, ScopeFilter, SearchReplaceOptions};
use crate::features::{
    analyze_intents, find_duplicates, group_files, DuplicateOptions, GroupByMode,
};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Terminal,
};
use std::io;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    FindReplace,
    GroupFiles,
    Duplicates,
    Intents,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputField {
    Source,
    Mask,
    Find,
    Replace,
}

impl InputField {
    fn next(self) -> Self {
        match self {
            InputField::Source => InputField::Mask,
            InputField::Mask => InputField::Find,
            InputField::Find => InputField::Replace,
            InputField::Replace => InputField::Source,
        }
    }
}

pub fn run_tui(initial_source: &str, initial_find: Option<String>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut active_tab = ActiveTab::FindReplace;
    let mut active_field = InputField::Find;
    let mut source_input = if initial_source.trim().is_empty() {
        "samples".to_string()
    } else {
        initial_source.to_string()
    };
    let mut mask_input = "*.*".to_string();
    let mut find_input = initial_find.unwrap_or_else(|| "http://".to_string());
    let mut replace_input = String::new();
    let mut use_regex = false;
    let mut case_sensitive = false;
    let mut preserve_case = false;
    let mut scope = ScopeFilter::All;

    let mut status_line = String::from(
        "Enter=Run | Tab=Next Field | F1=Find/Replace | F2=Grouping | F3=Duplicates | F4=Intents | Ctrl+R=Toggle Regex | Esc=Quit",
    );
    let mut table_headers: Vec<String> = vec![
        "File / Archive Entry".into(),
        "Enc".into(),
        "Line".into(),
        "Scope/Context".into(),
        "Match / Preview".into(),
    ];
    let mut table_rows: Vec<Vec<String>> = Vec::new();
    let mut cli_preview = String::new();

    // Run initial query
    execute_current_tab(
        active_tab,
        &source_input,
        &mask_input,
        &find_input,
        &replace_input,
        use_regex,
        case_sensitive,
        preserve_case,
        scope,
        &mut table_headers,
        &mut table_rows,
        &mut status_line,
        &mut cli_preview,
    );

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(6),
                    Constraint::Min(10),
                    Constraint::Length(3),
                ])
                .split(f.area());

            // Top Banner & Mode Tabs
            let tab_spans = vec![
                Span::styled(
                    " [FFRR STUDIO TUI] ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                tab_badge("F1: Find & Replace", active_tab == ActiveTab::FindReplace),
                Span::raw(" "),
                tab_badge("F2: File Grouping", active_tab == ActiveTab::GroupFiles),
                Span::raw(" "),
                tab_badge("F3: Duplicate Finder", active_tab == ActiveTab::Duplicates),
                Span::raw(" "),
                tab_badge("F4: Context & Intents", active_tab == ActiveTab::Intents),
            ];
            let header = Paragraph::new(Line::from(tab_spans)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" FFRR — Fast Find, Replace & Refactor Engine (File Find and Replace in Rust) "),
            );
            f.render_widget(header, chunks[0]);

            // Control / Input Form
            let field_style = |fld: InputField| {
                if active_field == fld {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                }
            };
            let form_lines = vec![
                Line::from(vec![
                    Span::styled(" Sources (-d): ", field_style(InputField::Source)),
                    Span::raw(&source_input),
                    Span::raw("    "),
                    Span::styled("File Mask (-m): ", field_style(InputField::Mask)),
                    Span::raw(&mask_input),
                ]),
                Line::from(vec![
                    Span::styled(" Find (-f):    ", field_style(InputField::Find)),
                    Span::raw(&find_input),
                    Span::raw("    "),
                    Span::styled("Replace (-r):   ", field_style(InputField::Replace)),
                    Span::raw(if replace_input.is_empty() {
                        "<none (search only)>"
                    } else {
                        &replace_input
                    }),
                ]),
                Line::from(vec![
                    Span::styled(" Flags: ", Style::default().fg(Color::Cyan)),
                    Span::raw(format!(
                        "[Regex: {}]  [CaseSensitive: {}]  [PreserveCase: {}]  [Scope: {:?}]  [Archives: ON (.zip/.rar/.gz/.tar.gz/.zst)]",
                        if use_regex { "ON" } else { "OFF" },
                        if case_sensitive { "ON" } else { "OFF" },
                        if preserve_case { "ON" } else { "OFF" },
                        scope
                    )),
                ]),
                Line::from(vec![
                    Span::styled(" Gen CLI: ", Style::default().fg(Color::Green)),
                    Span::raw(&cli_preview),
                ]),
            ];
            let form = Paragraph::new(form_lines)
                .block(Block::default().borders(Borders::ALL).title(" Search, Archive & Refactor Parameters (Tab to switch field, Enter to execute) "))
                .wrap(Wrap { trim: false });
            f.render_widget(form, chunks[1]);

            // Results Table
            let header_cells = table_headers.iter().map(|h| {
                Cell::from(h.as_str()).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            });
            let header_row = Row::new(header_cells).height(1);
            let rows = table_rows.iter().take(200).map(|r| {
                Row::new(r.iter().map(|c| Cell::from(c.as_str()))).height(1)
            });
            let widths = [
                Constraint::Percentage(28),
                Constraint::Percentage(8),
                Constraint::Percentage(7),
                Constraint::Percentage(20),
                Constraint::Percentage(37),
            ];
            let table = Table::new(rows, widths).header(header_row).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Results (Multi-Threaded Engine) "),
            );
            f.render_widget(table, chunks[2]);

            // Status Bar
            let footer = Paragraph::new(status_line.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Status & Shortcuts "),
            );
            f.render_widget(footer, chunks[3]);
        })?;

        if event::poll(std::time::Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Tab => {
                        active_field = active_field.next();
                    }
                    KeyCode::F(1) => {
                        active_tab = ActiveTab::FindReplace;
                        execute_current_tab(
                            active_tab,
                            &source_input,
                            &mask_input,
                            &find_input,
                            &replace_input,
                            use_regex,
                            case_sensitive,
                            preserve_case,
                            scope,
                            &mut table_headers,
                            &mut table_rows,
                            &mut status_line,
                            &mut cli_preview,
                        );
                    }
                    KeyCode::F(2) => {
                        active_tab = ActiveTab::GroupFiles;
                        execute_current_tab(
                            active_tab,
                            &source_input,
                            &mask_input,
                            &find_input,
                            &replace_input,
                            use_regex,
                            case_sensitive,
                            preserve_case,
                            scope,
                            &mut table_headers,
                            &mut table_rows,
                            &mut status_line,
                            &mut cli_preview,
                        );
                    }
                    KeyCode::F(3) => {
                        active_tab = ActiveTab::Duplicates;
                        execute_current_tab(
                            active_tab,
                            &source_input,
                            &mask_input,
                            &find_input,
                            &replace_input,
                            use_regex,
                            case_sensitive,
                            preserve_case,
                            scope,
                            &mut table_headers,
                            &mut table_rows,
                            &mut status_line,
                            &mut cli_preview,
                        );
                    }
                    KeyCode::F(4) => {
                        active_tab = ActiveTab::Intents;
                        execute_current_tab(
                            active_tab,
                            &source_input,
                            &mask_input,
                            &find_input,
                            &replace_input,
                            use_regex,
                            case_sensitive,
                            preserve_case,
                            scope,
                            &mut table_headers,
                            &mut table_rows,
                            &mut status_line,
                            &mut cli_preview,
                        );
                    }
                    KeyCode::Enter => {
                        execute_current_tab(
                            active_tab,
                            &source_input,
                            &mask_input,
                            &find_input,
                            &replace_input,
                            use_regex,
                            case_sensitive,
                            preserve_case,
                            scope,
                            &mut table_headers,
                            &mut table_rows,
                            &mut status_line,
                            &mut cli_preview,
                        );
                    }
                    KeyCode::Backspace => {
                        let target = match active_field {
                            InputField::Source => &mut source_input,
                            InputField::Mask => &mut mask_input,
                            InputField::Find => &mut find_input,
                            InputField::Replace => &mut replace_input,
                        };
                        target.pop();
                    }
                    KeyCode::Char(c) => {
                        if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
                            match c {
                                'r' | 'R' => use_regex = !use_regex,
                                's' | 'S' => case_sensitive = !case_sensitive,
                                'p' | 'P' => preserve_case = !preserve_case,
                                'o' | 'O' => {
                                    scope = match scope {
                                        ScopeFilter::All => ScopeFilter::Code,
                                        ScopeFilter::Code => ScopeFilter::Comments,
                                        ScopeFilter::Comments => ScopeFilter::Strings,
                                        ScopeFilter::Strings => ScopeFilter::Keys,
                                        ScopeFilter::Keys => ScopeFilter::Values,
                                        ScopeFilter::Values => ScopeFilter::All,
                                    };
                                }
                                'c' | 'C' => break,
                                _ => {}
                            }
                        } else {
                            let target = match active_field {
                                InputField::Source => &mut source_input,
                                InputField::Mask => &mut mask_input,
                                InputField::Find => &mut find_input,
                                InputField::Replace => &mut replace_input,
                            };
                            target.push(c);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn tab_badge(label: &str, active: bool) -> Span<'_> {
    if active {
        Span::styled(
            format!(" [{}] ", label),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!("  {}  ", label), Style::default().fg(Color::Gray))
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_current_tab(
    tab: ActiveTab,
    source_input: &str,
    mask_input: &str,
    find_input: &str,
    replace_input: &str,
    use_regex: bool,
    case_sensitive: bool,
    preserve_case: bool,
    scope: ScopeFilter,
    headers: &mut Vec<String>,
    rows: &mut Vec<Vec<String>>,
    status: &mut String,
    cli_preview: &mut String,
) {
    rows.clear();
    let sources: Vec<String> = source_input
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let traversal = TraversalOptions {
        sources,
        file_masks: split_mask_list(mask_input),
        ..Default::default()
    };

    match tab {
        ActiveTab::FindReplace => {
            *headers = vec![
                "File / Archive Entry".into(),
                "Enc".into(),
                "Line".into(),
                "Context / Scope".into(),
                "Matched Line / Preview".into(),
            ];
            let opts = SearchReplaceOptions {
                traversal,
                find: find_input.to_string(),
                replace: if replace_input.is_empty() {
                    None
                } else {
                    Some(replace_input.to_string())
                },
                use_regex,
                case_sensitive,
                preserve_case,
                scope,
                dry_run: true,
                ..Default::default()
            };
            if let Ok(sum) = run_search_replace(&opts) {
                *cli_preview = sum.cli_equivalents.ffrr_cmd.clone();
                for f in &sum.results {
                    for m in &f.matches {
                        let ctx = m
                            .semantic_context
                            .clone()
                            .unwrap_or_else(|| m.scope_kind.clone());
                        let preview = if let Some(ref repl) = m.replaced_line_text {
                            format!("{}  =>  {}", m.line_text.trim(), repl.trim())
                        } else {
                            m.line_text.trim().to_string()
                        };
                        rows.push(vec![
                            f.path.clone(),
                            f.encoding.clone(),
                            m.line_number.to_string(),
                            ctx,
                            preview,
                        ]);
                    }
                }
                *status = format!(
                    "Scanned {} files ({} archive entries) in {} ms | {} matches in {} files | F1=Find F2=Group F3=Dupes F4=Intents Esc=Quit",
                    sum.total_files_scanned,
                    sum.archive_entries_scanned,
                    sum.elapsed_ms,
                    sum.total_matches,
                    sum.files_with_matches
                );
            }
        }
        ActiveTab::GroupFiles => {
            *headers = vec![
                "Group Category".into(),
                "Files".into(),
                "In Archives".into(),
                "Total Bytes".into(),
                "Sample Files".into(),
            ];
            if let Ok(rep) = group_files(&traversal, GroupByMode::Language) {
                for g in rep.groups {
                    rows.push(vec![
                        g.group_key,
                        g.file_count.to_string(),
                        g.archive_member_count.to_string(),
                        format!("{} B ({:.1}%)", g.total_bytes, g.percentage_bytes),
                        g.sample_files.join(", "),
                    ]);
                }
                *status = format!(
                    "Grouped {} files ({} B, {} lines) in {} ms",
                    rep.total_files, rep.total_bytes, rep.total_lines, rep.elapsed_ms
                );
            }
        }
        ActiveTab::Duplicates => {
            *headers = vec![
                "Cluster Hash (BLAKE3)".into(),
                "Match Type".into(),
                "Copies".into(),
                "Wasted Bytes".into(),
                "Duplicate Paths".into(),
            ];
            let dopts = DuplicateOptions {
                traversal,
                near_duplicates: true,
                ..Default::default()
            };
            if let Ok(rep) = find_duplicates(&dopts) {
                for c in rep.clusters {
                    let paths: Vec<String> = c.files.into_iter().map(|f| f.path).collect();
                    rows.push(vec![
                        c.hash_blake3,
                        c.match_kind,
                        paths.len().to_string(),
                        format!("{} B", c.wasted_bytes),
                        paths.join(" == "),
                    ]);
                }
                *status = format!(
                    "Scanned {} files in {} ms | {} exact clusters, {} near-duplicate clusters | {} B wasted",
                    rep.total_files_scanned,
                    rep.elapsed_ms,
                    rep.exact_clusters,
                    rep.near_clusters,
                    rep.total_wasted_bytes
                );
            }
        }
        ActiveTab::Intents => {
            *headers = vec![
                "Intent Pack".into(),
                "Severity".into(),
                "Matches".into(),
                "Files".into(),
                "Suggested Replacement & Description".into(),
            ];
            if let Ok(rep) = analyze_intents(&traversal, None) {
                for f in rep.findings {
                    rows.push(vec![
                        format!("{} ({})", f.pack_id, f.title),
                        f.severity,
                        f.total_matches.to_string(),
                        f.affected_files.to_string(),
                        format!("Replace -> `{}` | {}", f.suggested_replace, f.description),
                    ]);
                }
                *status = format!(
                    "Intent analysis completed across {} files in {} ms | {} findings detected",
                    rep.total_files_scanned, rep.elapsed_ms, rep.total_findings
                );
            }
        }
    }
}
