use crate::eh_frame::parse_eh_frame;
use crate::header::elf::Elf64Ehdr;
use crate::header::Header;
use crate::symtab::{parse_symtab_64, Elf64Sym};
use crate::{FunctionSignature, KSection, PlatformType};
use anyhow::Result;
use anyhow::{anyhow, bail};
use gimli::{NativeEndian, UnwindSection};
use goblin::Object;
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};

pub struct BinaryAnalysis {
    pub functions: Vec<FunctionSignature>,
    pub path: String,
    pub section_headers: Vec<KSection>,
    pub is_stripped: bool,
    pub header: Box<Elf64Ehdr>,
    raw_buffer: Vec<u8>,
    section_map: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FunctionSource {
    EhFrame = 0, // Lowest priority
    CallGraph = 1,
    DynSym = 2,
    SymTab = 3, // Highest priority
    Manual = 4, // For entry point and user-defined
}

#[derive(Debug, Clone)]
struct FunctionEntry {
    signature: FunctionSignature,
    source: FunctionSource,
}
impl BinaryAnalysis {
    /// Load a binary file
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let mut file = std::fs::File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let obj = Object::parse(&buf)?;
        let buf_len = buf.len();
        let mut cursor = std::io::Cursor::new(&buf);

        let (header, sections, stripped) = match obj {
            Object::Elf(elf) => Self::parse_elf(&mut cursor, elf, buf_len)?,
            Object::PE(pe) => Self::parse_pe(&mut cursor, pe)?,
            _ => return Err(anyhow!("Malformed binary")),
        };

        let section_map: HashMap<String, Vec<u8>> = sections
            .iter()
            .map(|x| (x.name.clone(), x.raw_data().clone()))
            .collect();

        Ok(Self {
            functions: Vec::new(),
            path: path.as_ref().display().to_string(),
            section_headers: sections,
            is_stripped: stripped,
            header,
            raw_buffer: buf,
            section_map,
        })
    }

    fn get_function_map(&mut self) -> HashMap<u64, FunctionEntry> {
        let function_map: HashMap<u64, FunctionEntry> = self
            .functions
            .drain(..)
            .map(|sig| {
                // Infer source for compatibility
                let inferred_source = if sig.function_identifier.starts_with("FUNC_") {
                    FunctionSource::EhFrame
                } else if sig.function_identifier == "entry" {
                    FunctionSource::Manual
                } else {
                    FunctionSource::SymTab
                };
                (
                    sig.start,
                    FunctionEntry {
                        signature: sig,
                        source: inferred_source,
                    },
                )
            })
            .collect();

        function_map
    }
    /// Add functions with priority-based deduplication
    fn add_functions(&mut self, new_functions: Vec<FunctionSignature>, source: FunctionSource) {
        let mut function_map = self.get_function_map();

        for new_sig in new_functions {
            let start = new_sig.start;
            function_map
                .entry(start)
                .and_modify(|existing| {
                    if source > existing.source {
                        log::debug!(
                            "Replacing function at {:#x}: {} ({:?}) -> {} ({:?})",
                            start,
                            existing.signature.function_identifier,
                            existing.source,
                            new_sig.function_identifier,
                            source
                        );
                        existing.signature = new_sig.clone();
                        existing.source = source;
                    }
                })
                .or_insert(FunctionEntry {
                    signature: new_sig,
                    source,
                });
        }

        self.functions = function_map.into_values().map(|e| e.signature).collect();
        self.functions.sort_by_key(|f| f.start);
    }

    /// Parse ELF format
    fn parse_elf(
        cursor: &mut std::io::Cursor<&Vec<u8>>,
        elf: goblin::elf::Elf,
        buf_len: usize,
    ) -> Result<(Box<Elf64Ehdr>, Vec<KSection>, bool)> {
        let elf_hdr = Elf64Ehdr::from_reader(cursor)?;
        let mut header = Box::new(elf_hdr);

        let has_sections = elf.header.e_shnum > 0 && elf.header.e_shoff != 0;
        let has_programs = elf.header.e_phnum > 0 && elf.header.e_phoff != 0;

        let (sections, stripped) = if has_sections {
            log::info!("Has section headers (not stripped)");
            let sections = elf
                .section_headers
                .iter()
                .map(|sh| KSection::from_goblin_sh(cursor, sh, &elf).expect("Failed"))
                .collect::<Vec<_>>();
            (sections, false)
        } else if has_programs {
            log::warn!("Stripped binary; using program headers");
            let sections = KSection::from_goblin_ph(cursor, &elf, buf_len)?;
            (sections, true)
        } else {
            return Err(anyhow!("Invalid ELF"));
        };

        Ok((header, sections, stripped))
    }

    /// Parse PE format
    fn parse_pe(
        _cursor: &mut std::io::Cursor<&Vec<u8>>,
        _pe: goblin::pe::PE,
    ) -> Result<(Box<Elf64Ehdr>, Vec<KSection>, bool)> {
        todo!()
    }

    /// Analyze functions from .eh_frame
    pub fn analyze_eh_frame(&mut self) -> Result<&mut Self> {
        let base_address = self
            .section_headers
            .iter()
            .find(|sh| sh.name == ".eh_frame")
            .map(|sh| sh.vma)
            .unwrap_or(0);

        if let Some(data) = self.section_map.get(".eh_frame") {
            let functions = parse_eh_frame(data, base_address)?;
            log::info!("Found {} functions in .eh_frame", functions.len());
            self.add_functions(functions, FunctionSource::EhFrame);
        } else {
            log::warn!(".eh_frame not found");
        }

        Ok(self)
    }

    /// Analyze functions from .symtab
    pub fn analyze_symtab(&mut self) -> Result<&mut Self> {
        let section_map: HashMap<String, &Vec<u8>> = self
            .section_headers
            .iter()
            .map(|x| (x.name.clone(), x.raw_data()))
            .collect();

        let symtab = section_map.get(".symtab");
        let strtab = section_map.get(".strtab");

        if let (Some(symtab_data), Some(strtab_data)) = (symtab, strtab) {
            let symtabs = Elf64Sym::from_section(&symtab_data)?;
            let functions = parse_symtab_64(symtabs, strtab_data)?;
            log::info!("Found {} functions in .symtab", functions.len());
            self.add_functions(functions, FunctionSource::SymTab);
        } else {
            log::warn!(".symtab or .strtab not found");
        }

        Ok(self)
    }

    /// Analyze functions from .dynsym
    pub fn analyze_dynsym(&mut self) -> Result<&mut Self> {
        log::warn!(".dynsym analysis not implemented");
        Ok(self)
    }

    /// Deduplicate functions (handled automatically)
    pub fn deduplicate_functions(&mut self) -> &mut Self {
        log::debug!("Deduplication handled via priority system");
        self
    }

    /// Add entry point function
    pub fn identify_entry_point(&mut self) -> &mut Self {
        let entry_addr = self.header.entry_point();

        if entry_addr == 0 {
            log::warn!("ELF header has no entry point");
            return self;
        }

        // Build a function map to manage priorities cleanly
        let mut function_map = self.get_function_map();

        // If it already exists, rename and promote it
        if let Some(entry) = function_map.get_mut(&entry_addr) {
            if entry.signature.function_identifier != "entry" {
                log::info!(
                    "Entry function found at {:#x}, renaming {} -> entry",
                    entry.signature.start,
                    entry.signature.function_identifier
                );
                entry.signature.function_identifier = "entry".to_string();
            }
            entry.source = FunctionSource::Manual;
        } else {
            // Add a new synthetic entry if it doesn’t exist
            log::info!(
                "Entry address {:#x} not found in existing functions — adding synthetic 'entry'",
                entry_addr
            );
            let entry_sig = FunctionSignature {
                function_identifier: "entry".to_string(),
                start: entry_addr,
                size: 0,
                end: entry_addr, // optional: same as start, since we don’t know size
            };
            function_map.insert(
                entry_addr,
                FunctionEntry {
                    signature: entry_sig,
                    source: FunctionSource::Manual,
                },
            );
        }

        // Replace functions list with updated map
        self.functions = function_map.into_values().map(|e| e.signature).collect();
        self.functions.sort_by_key(|f| f.start);

        self
    }

    /// Sort functions by address
    pub fn sort_functions(&mut self) -> &mut Self {
        self.functions.sort_by_key(|f| f.start);
        self
    }

    /// Get section by name
    pub fn get_section(&self, name: &str) -> Option<&KSection> {
        self.section_headers.iter().find(|s| s.name == name)
    }

    /// Get raw section data
    pub fn get_section_data(&self, name: &str) -> Option<&[u8]> {
        self.get_section(name).map(|x| x.raw_data().as_slice())
    }

    /// Access all functions
    pub fn functions(&self) -> &[FunctionSignature] {
        &self.functions
    }

    /// Return the symbol table
    pub fn symbols(&self) -> anyhow::Result<Vec<Elf64Sym>> {
        let section_data = self.get_section_data(".symtab");

        if let Some(data) = section_data {
            let symtab = Elf64Sym::from_section(&data)?;
            return Ok(symtab);
        } else {
            bail!("No.symtab in binary");
        }
    }
}

// Priority system (highest to lowest):
// 1. Manual (entry point, user-defined) - FunctionSource::Manual = 4
// 2. SymTab (.symtab) - FunctionSource::SymTab = 3
// 3. DynSym (.dynsym) - FunctionSource::DynSym = 2
// 4. CallGraph (future) - FunctionSource::CallGraph = 1
// 5. EhFrame (.eh_frame) - FunctionSource::EhFrame = 0
//
// Example usage:
// let analysis = BinaryAnalysis::open("path/to/binary")?
//     .analyze_eh_frame()?      // Adds FUNC_* entries (lowest priority)
//     .analyze_dynsym()?         // Overwrites with real names if available
//     .analyze_symtab()?         // Overwrites with even better names (highest priority)
//     .identify_entry_point()    // Marks entry point (won't be overwritten)
//     .build();
