use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    match foiled_lint::run(&root, foiled_lint::BINDINGS) {
        Err(e) => {
            eprintln!("foiled-lint: {e:#}");
            ExitCode::from(2)
        }
        Ok(report) => {
            for f in &report.findings {
                eprintln!("{f}");
            }
            println!(
                "foiled-lint: {} schema(s), {} data file(s), {} finding(s)",
                report.schemas_checked,
                report.files_checked,
                report.findings.len()
            );
            if report.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
