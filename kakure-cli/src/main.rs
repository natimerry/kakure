use anyhow::{Result, bail};
use colored::*;
use kakure_core::BinaryAnalysis;
use log::{Level, LevelFilter};
use rustyline::history::DefaultHistory;
use rustyline::{Editor, error::ReadlineError};
use std::fs::File;
use std::io::Write;
use tabled::{Table, Tabled};

fn main() -> Result<()> {
    setup_logger();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <binary>", args[0]);
        std::process::exit(1);
    }

    let input = &args[1];
    let mut analysis = BinaryAnalysis::open(input)?;
    log::info!("Opened binary: {}", input.bright_blue());

    let mut rl = Editor::<(), DefaultHistory>::new()?;
    println!("{}", "🧠 Kakure Interactive Shell".bright_green().bold());
    println!("Type 'help' for a list of commands.");

    loop {
        let line = rl.readline("kakure> ");
        match line {
            Ok(cmd) => {
                rl.add_history_entry(cmd.as_str())?;
                if let Err(e) = handle_command(&cmd, &mut analysis, input) {
                    log::error!("{}", e);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("\nExiting...");
                break;
            }
            Err(e) => {
                log::error!("Readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn analyze_target(analysis: &mut BinaryAnalysis, target: &str) -> Result<()> {
    match target {
        "eh_frame" => {
            log::info!("{}", "Analyzing .eh_frame...".cyan());
            if let Err(e) = analysis.analyze_eh_frame() {
                log::error!("Failed .eh_frame: {e}");
            }
        }
        "symtab" => {
            log::info!("{}", "Analyzing .symtab...".cyan());
            if let Err(e) = analysis.analyze_symtab() {
                log::error!("Failed .symtab: {e}");
            }
        }
        "dynsym" => {
            log::info!("{}", "Analyzing .dynsym...".cyan());
            if let Err(e) = analysis.analyze_dynsym() {
                log::warn!("DynSym analysis failed or unimplemented: {e}");
            }
        }
        _ => log::warn!("Unknown analysis target: {target}"),
    }

    analysis.identify_entry_point();
    analysis.sort_functions();
    analysis.deduplicate_functions();
    log::info!("{}", "Analysis complete!".green());
    Ok(())
}

/// Command handler — radare2 style
fn handle_command(cmd: &str, analysis: &mut BinaryAnalysis, input: &str) -> Result<()> {
    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    match parts[0] {
        "help" => print_help(),
        "afa" => analyze_all(analysis)?,
        "af" => {
            if let Some(arg) = parts.get(1) {
                match *arg {
                    "ehframe" | "eh" => analyze_target(analysis, "eh_frame")?,
                    "symtab" | "sym" => analyze_target(analysis, "symtab")?,
                    "dynsym" | "dyn" => analyze_target(analysis, "dynsym")?,
                    _ => log::warn!(
                        "Unknown analysis type '{}'. Use: ehframe, symtab, dynsym",
                        arg
                    ),
                }
            } else {
                log::warn!("Usage: af <ehframe|symtab|dynsym>");
            }
        }
        "afl" => print_function_table(analysis),
        "afj" => dump_functions_json(analysis, parts.get(1).map(|s| s.to_string()))?,
        "iS" | "lS" => list_sections(input)?,
        "q" | "quit" | "exit" => {
            println!("{}", "Bye 👋".bright_green());
            std::process::exit(0);
        }
        other => log::warn!("Unknown command: '{}'. Try 'help'", other),
    }
    Ok(())
}

fn print_help() {
    println!("\n{}", "Available commands:".bright_yellow().bold());
    println!("  aa       analyze all (.eh_frame, .symtab)");
    println!("  afl      list functions");
    println!("  ij [out] dump functions to JSON (optionally to path)");
    println!("  iS       list sections");
    println!("  help     show this help message");
    println!("  q        quit\n");
}

/// Run both .eh_frame and .symtab analyses
fn analyze_all(analysis: &mut BinaryAnalysis) -> Result<()> {
    log::info!("{}", "Analyzing .eh_frame...".cyan());
    if let Err(e) = analysis.analyze_eh_frame() {
        log::error!("Failed .eh_frame: {e}");
    }
    log::info!("{}", "Analyzing .symtab...".cyan());
    if let Err(e) = analysis.analyze_symtab() {
        log::error!("Failed .symtab: {e}");
    }

    analysis.identify_entry_point();
    analysis.sort_functions();
    analysis.deduplicate_functions();
    log::info!("{}", "Analysis complete!".green());
    Ok(())
}

/// Setup colorful logger
fn setup_logger() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            let level = match record.level() {
                Level::Error => "ERROR".red().bold(),
                Level::Warn => "WARN".yellow().bold(),
                Level::Info => "INFO".cyan().bold(),
                Level::Debug => "DEBUG".blue(),
                Level::Trace => "TRACE".magenta(),
            };
            writeln!(buf, "[{}] {}", level, record.args())
        })
        .init();
}

/// Table-friendly view for functions
#[derive(Tabled)]
struct FunctionRow {
    #[tabled(rename = "Function Name")]
    name: String,
    #[tabled(rename = "Start Address")]
    start: String,
    #[tabled(rename = "End Address")]
    end: String,
    #[tabled(rename = "Size (bytes)")]
    size: String,
}

/// Print functions in a formatted table
fn print_function_table(analysis: &BinaryAnalysis) {
    if analysis.functions().is_empty() {
        println!("{}", "No functions analyzed yet. Run `aa` first.".yellow());
        return;
    }

    let rows: Vec<_> = analysis
        .functions()
        .iter()
        .map(|f| FunctionRow {
            name: f.function_identifier.clone(),
            start: format!("0x{:016x}", f.start),
            end: format!("0x{:016x}", f.end),
            size: format!("{}", f.size),
        })
        .collect();

    println!("\n{}", "📘 Discovered Functions".bright_green().bold());
    let mut table = Table::new(rows);

    let table = table.with(tabled::settings::Style::modern());
    println!("{table}");
    println!(
        "{} {}",
        "Total functions:".bright_yellow(),
        analysis.functions().len()
    );
}

/// Dump functions to JSON
fn dump_functions_json(analysis: &BinaryAnalysis, out: Option<String>) -> Result<()> {
    #[derive(serde::Serialize)]
    struct FuncView<'a> {
        name: &'a str,
        start: u64,
        end: u64,
        size: u64,
    }

    let view: Vec<_> = analysis
        .functions()
        .iter()
        .map(|f| FuncView {
            name: &f.function_identifier,
            start: f.start,
            end: f.end,
            size: f.size,
        })
        .collect();

    let json = serde_json::to_string_pretty(&view)?;

    if let Some(path) = out {
        File::create(&path)?.write_all(json.as_bytes())?;
        log::info!(
            "{} {}",
            "JSON dump written to:".bright_green(),
            path.bright_blue()
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

/// List ELF sections
fn list_sections(input: &str) -> Result<()> {
    let analysis = BinaryAnalysis::open(input)?;

    #[derive(Tabled)]
    struct SectionRow {
        #[tabled(rename = "Name")]
        name: String,
        #[tabled(rename = "VMA")]
        vma: String,
        #[tabled(rename = "Size (bytes)")]
        size: String,
    }

    println!(
        "\n{}",
        format!("📦 Sections in '{}':", input).bright_green().bold()
    );
    let rows: Vec<_> = analysis
        .section_headers
        .iter()
        .map(|sh| SectionRow {
            name: sh.name.clone(),
            vma: format!("0x{:016x}", sh.vma),
            size: format!("{}", sh.size),
        })
        .collect();

    let mut table = Table::new(rows);
    let table = table.with(tabled::settings::Style::modern());
    println!("{table}");
    Ok(())
}
