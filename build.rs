// Embed the app icon and version info into Windows executables.
fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    // Cross-compiling with MinGW from macOS/Linux.
    if !cfg!(windows) && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed Windows icon: {e}");
    }
}
