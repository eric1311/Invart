use std::env;
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).ok();
    let args: Vec<String> = env::args().collect();
    let event = if input.trim().is_empty() { args.get(1).cloned().unwrap_or_default() } else { input };
    let report = check_file_write(&event);
    println!("{}", report);
}

fn check_file_write(event: &str) -> String {
    let lowered = event.to_lowercase();
    if lowered.contains("rm -rf /") || lowered.contains("rm -rf .") || lowered.contains("rm -rf *") {
        return "{\"schema_version\":\"kappaski.rust_shim.v0.13\",\"domain\":\"file-write\",\"effect\":\"deny\",\"finding_id\":\"file.bulk_delete\"}".to_string();
    }
    if lowered.contains("rm ") || lowered.contains("chmod ") || lowered.contains("chown ") || lowered.contains(">") {
        return "{\"schema_version\":\"kappaski.rust_shim.v0.13\",\"domain\":\"file-write\",\"effect\":\"require_approval\",\"finding_id\":\"file.destructive_command\"}".to_string();
    }
    "{\"schema_version\":\"kappaski.rust_shim.v0.13\",\"domain\":\"file-write\",\"effect\":\"allow\",\"finding_id\":null}".to_string()
}
