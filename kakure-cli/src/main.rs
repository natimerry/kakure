use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use env_logger::Env;
use kakure_core::{
    Binary,
    eh_frame::FdeParser,
    frame_analyzers::{FrameAnalyzer, PossibleFrames},
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List sections from the binary
    ListSections {
        /// Path to the binary to analyze
        path: PathBuf,
    },

    AnalyseFrame {
        path: PathBuf,
        frame_type: PossibleFrames,
    },

    GetEntry {
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    let args = Args::parse();

    match args.command {
        Commands::GetEntry { path } => {
            log::info!("Opening binary: {}", path.display());
            let binary = Binary::open(&path)?;

            let entry = binary.get_entry_offset()?;

            log::info!("{:#X}", entry);
        }
        Commands::ListSections { path } => {
            log::info!("Opening binary: {}", path.display());
            let binary = Binary::open(&path);

            match binary {
                Ok(binary) => {
                    log::info!("Sections in {}:", path.display());
                    for sec in &binary.section_headers {
                        println!(
                            "- {} | vma: 0x{:x} | size: {} bytes | offset: 0x{:x}",
                            sec.name,
                            sec.vma,
                            sec.raw_len(),
                            sec.file_offset
                        );
                    }
                }
                Err(e) => {
                    log::error!("Could not open binary: {}", e);
                }
            }
        }
        Commands::AnalyseFrame { frame_type, path } => {
            log::info!("Opening binary: {}", path.display());
            let binary = Binary::open(&path);

            if let Ok(binary) = binary {
                // build a map of sections and their offsets first

                let x: std::collections::HashMap<String, &Vec<u8>> = binary
                    .section_headers
                    .iter()
                    .map(|x| {
                        let data = x.raw_data();
                        (x.name.clone(), (data))
                    })
                    .collect();

                let base_address = binary
                    .section_headers
                    .iter()
                    .find(|sh| sh.name == frame_type.to_string())
                    .map(|sh| sh.vma)
                    .unwrap_or(0);
                let section_data = x.get(&frame_type.to_string());

                if let None = section_data {
                    log::error!("Section does not exist");
                    return Err(anyhow!("Invalid section asked to parse"));
                }
                let section_data = section_data.unwrap();

                match frame_type {
                    PossibleFrames::EhFrame => {
                        let fa = FrameAnalyzer::new(&section_data, base_address);
                        let functions: Vec<kakure_core::FunctionSignature> = fa.parse_eh_frame()?;

                        for func in &functions {
                            log::info!(
                                "{}: start=0x{:x}, end=0x{:x}, size={}",
                                func.function_identifier,
                                func.start,
                                func.end,
                                func.size
                            );
                        }
                    }
                    PossibleFrames::EhFrameHdr => {
                        let fa = FrameAnalyzer::new(&section_data, base_address);
                        let functions: Vec<kakure_core::FunctionSignature> =
                            fa.parse_eh_frame_headers()?;

                        for func in &functions {
                            log::info!(
                                "{}: start=0x{:x}, end=0x{:x}, size={}",
                                func.function_identifier,
                                func.start,
                                func.end,
                                func.size
                            );
                        }
                    }
                    PossibleFrames::InitArray => todo!(),
                    PossibleFrames::FiniArray => todo!(),
                    PossibleFrames::Ctors => todo!(),
                    PossibleFrames::Dtors => todo!(),
                    PossibleFrames::Text => todo!(),
                    PossibleFrames::Symtab => todo!(),
                    PossibleFrames::DynSym => todo!(),
                    PossibleFrames::Plt => todo!(),
                    PossibleFrames::Got => todo!(),
                    PossibleFrames::GccExceptTable => todo!(),
                    PossibleFrames::Pdata => todo!(),
                    PossibleFrames::DebugFrame => todo!(),
                }
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}
