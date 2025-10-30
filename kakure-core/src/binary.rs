use crate::eh_frame::parse_eh_frame;
use crate::header::elf::Elf64Ehdr;
use crate::header::Header;
use crate::{FunctionSignature, KSection, PlatformType};
use anyhow::anyhow;
use anyhow::Result;
use byteorder::LE;
use gimli::{NativeEndian, UnwindSection};
use goblin::Object;
use std::io::{self, Read, Seek, SeekFrom};

pub struct Binary {
    pub path: String,
    pub section_headers: Vec<KSection>,
    pub is_stripped: bool,
    pub header: Box<dyn Header>,
    pub functions: Vec<FunctionSignature>,
}

impl Binary {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let mut file = std::fs::File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let obj = Object::parse(&buf)?;

        let buf_len = buf.len();
        let mut cursor = std::io::Cursor::new(&buf);
        let mut stripped = false;
        let mut header = Box::new_uninit();
        let mut sections = Vec::new();

        match obj {
            Object::Elf(elf) => {
                let elf_hdr = Elf64Ehdr::from_reader(&mut cursor)?;
                header.write(elf_hdr);

                let has_sections = elf.header.e_shnum > 0 && elf.header.e_shoff != 0;
                let has_programs = elf.header.e_phnum > 0 && elf.header.e_phoff != 0;

                if has_sections {
                    log::info!("Has section headers (not stripped)");
                    sections = elf
                        .section_headers
                        .iter()
                        .map(|sh| KSection::from_goblin_sh(&mut cursor, sh, &elf).unwrap())
                        .collect();
                } else if has_programs {
                    stripped = true;
                    log::warn!("Stripped binary; using program headers");
                    sections = KSection::from_goblin_ph(&mut cursor, &elf, buf_len)?;
                } else {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid ELF").into());
                }
            }
            Object::PE(pe) => {
                for s in &pe.sections {
                    let name = s.name().unwrap_or("").to_string();
                    let mut raw = vec![0u8; s.virtual_size as usize];
                    cursor.seek(SeekFrom::Start(s.pointer_to_raw_data as u64))?;
                    cursor.read_exact(&mut raw)?;
                    sections.push(KSection {
                        name,
                        vma: s.virtual_address as u64,
                        size: s.virtual_size as u64,
                        file_offset: s.pointer_to_raw_data as u64,
                        flags: s.characteristics as u64,
                        raw_data: PlatformType::PE(raw),
                    });
                }
            }
            _ => return Err(anyhow!("Malformed binary")),
        }

        let section_map: std::collections::HashMap<String, &Vec<u8>> = sections
            .iter()
            .map(|x| (x.name.clone(), x.raw_data()))
            .collect();

        let base_address = sections
            .iter()
            .find(|sh| sh.name == ".eh_frame")
            .map(|sh| sh.vma)
            .unwrap_or(0);

        let mut functions = Vec::new();
        if let Some(data) = section_map.get(".eh_frame") {
            functions.extend(parse_eh_frame(data, base_address)?);
            log::info!("Found {} functions in .eh_frame", functions.len());
        } else {
            log::warn!(".eh_frame not found");
        }

        let header = unsafe { header.assume_init() };

        let entry_addr = header.entry_point();
        if let Some(entry_func) = functions.iter_mut().find(|f| f.start == entry_addr) {
            log::info!(
                "Entry function found at {:#x}, renaming {} -> entry",
                entry_func.start,
                entry_func.function_identifier
            );
            entry_func.function_identifier = "entry".to_string();
        } else {
            // If no function matches, add a stub entry function
            functions.push(FunctionSignature {
                function_identifier: "entry".to_string(),
                start: entry_addr,
                end: entry_addr,
                size: 0,
            });
            log::warn!(
                "Entry address {:#x} not found in .eh_frame; added synthetic entry function",
                entry_addr
            );
        }
        Ok(Self {
            functions,
            path: path.as_ref().display().to_string(),
            section_headers: sections,
            is_stripped: stripped,
            header,
        })
    }

    pub fn get_entry_offset(&self) -> Result<u64> {
        Ok(self.header.entry_point())
    }
}
