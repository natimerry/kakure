use anyhow::anyhow;
use goblin::{Object};
use std::io::{self, Read, Seek, SeekFrom};

use crate::{KSection, PlatformType};

pub struct Binary {
    pub path: String,
    pub section_headers: Vec<KSection>,
    pub is_stripped: bool,
}

impl Binary {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let mut file = std::fs::File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let obj = Object::parse(&buf)?;

        let buf_len = buf.len();
        let mut sections = Vec::new();
        let mut cursor = std::io::Cursor::new(&buf);
        let mut stripped = false;

        match obj {
            Object::Elf(elf) => {
                let has_section_headers = elf.header.e_shnum > 0 && elf.header.e_shoff != 0;
                let has_program_headers = elf.header.e_phnum > 0 && elf.header.e_phoff != 0;

                if has_section_headers {
                    log::info!("Has section headers (not stripped)");
                } else if has_program_headers {
                    stripped = true;
                    log::warn!(
                        "No section headers — stripped binary. Using program headers instead."
                    );
                } else {
                    return Err(
                        io::Error::new(io::ErrorKind::Other, "Invalid or malformed ELF").into(),
                    );
                }

                if has_section_headers {
                    sections = elf
                        .section_headers
                        .iter()
                        .map(|sh| {
                            KSection::from_goblin_sh(&mut cursor, sh, &elf)
                                .expect("Unreachable panic")
                        })
                        .collect();
                } else {
                    log::warn!("ELF binary appears stripped (no section headers). Falling back to Program Headers (Segments).");
                    sections = KSection::from_goblin_ph(&mut cursor, &elf,buf_len)?;
                    
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
            _ => {
                return Err(anyhow!("Malformed or invalid PE file"));
            }
        }

        Ok(Self {
            path: path.as_ref().display().to_string(),
            section_headers: sections,
            is_stripped: stripped,
        })
    }
}
