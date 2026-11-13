// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::{BufRead, stdin};
use std::process::ExitCode;
use string_analyze::analyze_with;
use string_analyze::rules::ALL_RULES;

const HELP: &str = "\
string-analyze — find key strings from cluttered text

Usage:
  string-analyze [OPTIONS]

Options:
  -h, --help     Print this help message
  -V, --version  Print version information

Reads text from stdin line by line and prints highlighted findings for
lines whose risk score is non-zero.

Examples:
  cat dump.txt | string-analyze
  echo 'api_key = \"12345678abcdefgh\"' | string-analyze
";

/// 逐行扫描标准输入，输出风险评分非零的命中报告。
fn scan_stdin() {
    let input = stdin().lock();
    for line in input.lines().map_while(Result::ok) {
        let result = analyze_with(&line, &ALL_RULES);
        if result.score() != 0 {
            println!("{:#}", result);
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|arg| arg == "-V" || arg == "--version") {
        println!("string-analyze {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if let Some(arg) = args.first() {
        eprintln!("error: unexpected argument '{arg}'\n");
        eprint!("{HELP}");
        return ExitCode::FAILURE;
    }

    scan_stdin();
    ExitCode::SUCCESS
}
