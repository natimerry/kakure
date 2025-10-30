use anyhow::Result;
use clap::{Parser, Subcommand};
use kakure_core::Binary;

/// Simple ELF introspection CLI
#[derive(Parser)]
#[command(
    name = "bininfo",
    about = "Inspect ELF binaries (entry point, functions, and sections)",
    version,
    author
)]
struct Cli {
    /// Path to binary file
    #[arg(required = true)]
    path: std::path::PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show entry point of binary
    Entry,
    /// Show all discovered functions
    Functions,
    /// List all sections
    Sections,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let bin = Binary::open(&cli.path)?;

    match cli.command {
        Command::Entry => {
            let entry = bin.get_entry_offset()?;
            println!("Entry point: 0x{entry:x}");
        }

        Command::Functions => {
            if bin.functions.is_empty() {
                println!("No functions found (.eh_frame missing or stripped binary).");
            } else {
                println!(
                    "{:<20} {:<18} {:<18} {:<10}",
                    "Function", "Start", "End", "Size"
                );
                println!("{}", "-".repeat(70));
                for func in &bin.functions {
                    println!(
                        "{:<20} 0x{:<16x} 0x{:<16x} {:<10}",
                        func.function_identifier, func.start, func.end, func.size
                    );
                }
            }
        }

        Command::Sections => {
            if bin.section_headers.is_empty() {
                println!("No sections found (possibly stripped binary).");
            } else {
                println!(
                    "{:<20} {:<18} {:<10} {:<10} {:<10}",
                    "Section", "VMA", "Size", "Offset", "Flags"
                );
                println!("{}", "-".repeat(80));
                for s in &bin.section_headers {
                    println!(
                        "{:<20} 0x{:<16x} {:<10x} {:<10x} {:<10x}",
                        s.name, s.vma, s.size, s.file_offset, s.flags
                    );
                }
            }
        }
    }

    Ok(())
}
