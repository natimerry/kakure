use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use kakure_core::BinaryAnalysis;
use log::{Level, LevelFilter, Record};
use std::fs::File;
use std::io::Write;
use tabled::{Table, Tabled};

/// Available analysis targets
#[derive(ValueEnum, Clone, Debug)]
enum AnalysisTarget {
    /// Analyze functions from .eh_frame (unwind info)
    EhFrame,
    /// Analyze symbols from .symtab (symbol table)
    Symtab,
    /// Analyze symbols from .dynsym (dynamic symbol table)
    DynSym,
}

/// Actions to run after analysis completes
#[derive(ValueEnum, Clone, Debug)]
enum Action {
    /// Print discovered functions in a table
    ListFunctions,
    /// Dump discovered functions to JSON (--out required)
    DumpJson,
    /// No extra action
    None,
}

/// CLI subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Perform analysis on a binary and optionally run an action
    Analyze {
        /// Path to the input binary
        #[arg(short, long)]
        input: String,

        /// Analysis targets to perform
        #[arg(
            short,
            long,
            value_enum,
            num_args = 1..,
            default_values_t = vec![AnalysisTarget::EhFrame, AnalysisTarget::Symtab],
            help = "Select one or more analyses to perform"
        )]
        targets: Vec<AnalysisTarget>,

        /// Action to run after analyses complete
        #[arg(long, value_enum, default_value_t = Action::None)]
        action: Action,

        /// Output path used by some actions (e.g. --action dump-json)
        #[arg(long)]
        out: Option<String>,
    },

    /// List sections in the binary (like `readelf -S`)
    ListSections {
        /// Path to the input binary
        #[arg(short, long)]
        input: String,
    },

    /// (Optional) — List symbols (can be implemented later)
    #[command(hide = true)]
    ListSymbols {
        /// Path to the input binary
        #[arg(short, long)]
        input: String,
    },
}

/// Root CLI
#[derive(Parser, Debug)]
#[command(author, version, about = "🧠 Kakure Binary Analysis CLI", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<()> {
    setup_logger();

    let args = Args::parse();

    match args.command {
        Command::Analyze {
            input,
            targets,
            action,
            out,
        } => run_analysis_and_action(&input, targets, action, out)?,
        Command::ListSections { input } => list_sections(&input)?,
        Command::ListSymbols { input } => list_symbols(&input)?,
    }

    Ok(())
}

/// Setup colorful logging
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

/// Run analyses and then perform the chosen action
fn run_analysis_and_action(
    input: &str,
    targets: Vec<AnalysisTarget>,
    action: Action,
    out: Option<String>,
) -> Result<()> {
    log::info!("Opening binary: {}", input.bright_blue());
    let mut analysis = BinaryAnalysis::open(input)?;

    for target in &targets {
        match target {
            AnalysisTarget::EhFrame => {
                log::info!("{}", "Analyzing .eh_frame...".cyan());
                if let Err(e) = analysis.analyze_eh_frame() {
                    log::error!("Failed to analyze .eh_frame: {e}");
                }
            }
            AnalysisTarget::Symtab => {
                log::info!("{}", "Analyzing .symtab...".cyan());
                if let Err(e) = analysis.analyze_symtab() {
                    log::error!("Failed to analyze .symtab: {e}");
                }
            }
            AnalysisTarget::DynSym => {
                log::info!("{}", "Analyzing .dynsym...".cyan());
                if let Err(e) = analysis.analyze_dynsym() {
                    log::warn!("DynSym analysis failed or unimplemented: {e}");
                }
            }
        }
    }

    log::info!("{}", "Finalizing analysis...".green());
    analysis.identify_entry_point();
    analysis.sort_functions();
    analysis.deduplicate_functions();

    match action {
        Action::None => log::info!("{}", "No post-analysis action requested.".yellow()),
        Action::ListFunctions => print_function_table(&analysis),
        Action::DumpJson => dump_functions_json(&analysis, out)?,
    }

    Ok(())
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

    if let Some(out) = out {
        File::create(&out)?.write_all(json.as_bytes())?;
        log::info!(
            "{} {}",
            "JSON dump written to:".bright_green(),
            out.bright_blue()
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

/// Table for ELF sections
#[derive(Tabled)]
struct SectionRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "VMA")]
    vma: String,
    #[tabled(rename = "Size (bytes)")]
    size: String,
}

/// List all ELF sections (pretty table)
fn list_sections(input: &str) -> Result<()> {
    let analysis = BinaryAnalysis::open(input)?;

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

/// Placeholder for listing symbols
fn list_symbols(input: &str) -> Result<()> {
    let analysis = BinaryAnalysis::open(input)?;
    println!(
        "{} '{}':",
        "🔣 Symbols in".bright_cyan().bold(),
        input.bright_blue()
    );

    let strtab = analysis.get_section(".strtab");
    if let Some(str_data) = strtab {
        for sym in analysis.symbols()? {
            let st_type = (sym.st_info) & 0xF;
            let symbol_name = sym.name_from_symtab(&str_data.raw_data())?;
            println!(
                "  {:<30} value={} size={} type={}",
                symbol_name.bright_white(),
                format!("0x{:016x}", sym.st_value).bright_yellow(),
                sym.st_size,
                st_type
            );
        }
    } else {
        bail!("Strtab not in binary");
    }
    Ok(())
}
