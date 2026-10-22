fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let debug = std::env::var_os("BR_DEBUG").is_some();
    if !debug {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let code = std::panic::catch_unwind(|| blastradius::cli::run(argv)).unwrap_or_else(|p| {
        if debug {
            std::panic::resume_unwind(p);
        }
        let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        if msg.contains("Broken pipe") {
            return 0; // br ... | head
        }
        eprintln!("error: internal error{}", if msg.is_empty() { String::new() } else { format!(": {msg}") });
        eprintln!("hint: this is a bug in br; re-run with BR_DEBUG=1 for the stack trace and report it");
        1
    });
    std::process::exit(code);
}
