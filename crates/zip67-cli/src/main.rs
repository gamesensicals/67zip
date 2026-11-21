//! `67z`: the 67zip command line, modelled on 7-Zip's `7z`.

#![forbid(unsafe_code)]

mod args;
mod run;
mod term;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--worker") {
        std::process::exit(zip67_worker::server::run());
    }
    if args.first().map(String::as_str) == Some("--sandbox-selftest") {
        let dir = std::path::PathBuf::from(args.get(1).cloned().unwrap_or_else(|| ".".into()));
        let (status, checks) = zip67_worker::sandbox::selftest(&dir);
        println!("{}", status.describe());
        let mut ok = true;
        for (name, passed) in &checks {
            println!("[{}] {name}", if *passed { "ok" } else { "FAIL" });
            ok &= passed;
        }
        std::process::exit(if ok { 0 } else { 1 });
    }
    std::process::exit(run::main(args));
}
