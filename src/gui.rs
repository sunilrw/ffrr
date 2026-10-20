//! ============================================================================
//! Module: `gui.rs` — Native Cross-Platform Desktop Window (`ffrr gui`)
//! ============================================================================
//!
//! ### How It Works (For Developers from Any Language)
//! Instead of shipping a heavy 200 MB Electron/Chromium bundle, FFRR uses:
//! 1. **Embedded Axum HTTP Server (`server.rs`)**: Runs in a background thread
//!    bound to localhost (`127.0.0.1:18775`).
//! 2. **OS-Native WebView (`tao` + `wry`)**: Opens a lightweight native window
//!    using macOS `WKWebView`, Windows `WebView2`, or Linux `WebKitGTK`.
//!
//! When built without `--features gui` (for headless Linux servers), calling
//! `ffrr gui` prints a clear instruction showing how to launch `ffrr serve`.
//!
//! Made using vibe coding by Sunil Warrier.
//! ============================================================================

use anyhow::Result;

#[cfg(feature = "gui")]
pub fn launch_native_desktop_gui(default_source: Option<String>) -> Result<()> {
    use tao::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };
    use wry::WebViewBuilder;

    let bind_addr = "127.0.0.1:18775";
    let url = format!("http://{}", bind_addr);

    // Spawn the embedded REST API & Web Studio server on a background thread
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(crate::server::run_http_server(bind_addr, default_source));
        }
    });

    // Brief pause to allow the loopback TCP listener to bind before opening WebView
    std::thread::sleep(std::time::Duration::from_millis(200));

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("FFRR Studio — Fast Find, Replace & Refactor Engine")
        .with_inner_size(tao::dpi::LogicalSize::new(1400.0, 900.0))
        .build(&event_loop)?;

    let _webview = WebViewBuilder::new(&window).with_url(&url).build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(not(feature = "gui"))]
pub fn launch_native_desktop_gui(_default_source: Option<String>) -> Result<()> {
    anyhow::bail!(
        "Native desktop GUI was not compiled into this standalone build (compile with `cargo build --features gui`).\nTo access the full FFRR Web Studio right now, run:\n  ffrr serve --bind 127.0.0.1:8090\nand open http://127.0.0.1:8090 in your browser."
    )
}
