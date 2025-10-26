use std::io::{self, SeekFrom};

use goblin::elf::{Elf, SectionHeader};
use goblin::elf32::program_header::PT_LOAD;

#[derive(Debug)]
pub enum PlatformType<T> {
    ELF(T),
    PE(T),
    Unknown(T),
}

#[derive(Debug)]
pub struct KSection {
    pub name: String,
    pub vma: u64,
    pub size: u64,
    pub file_offset: u64,
    pub flags: u64,
    pub raw_data: PlatformType<Vec<u8>>,
}

impl KSection {
    pub fn raw_len(&self) -> usize {
        match &self.raw_data {
            PlatformType::ELF(b) | PlatformType::PE(b) | PlatformType::Unknown(b) => b.len(),
        }
    }

    pub fn raw_data(&self) -> &Vec<u8> {
        match &self.raw_data {
            PlatformType::ELF(b) | PlatformType::PE(b) | PlatformType::Unknown(b) => &b,
        }
    }

    pub fn from_goblin_sh<R: io::Seek + io::Read>(
        cursor: &mut R,
        sh: &SectionHeader,
        elf: &Elf,
    ) -> io::Result<Self> {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let mut raw = vec![0u8; sh.sh_size as usize];
        cursor.seek(SeekFrom::Start(sh.sh_offset))?;
        cursor.read_exact(&mut raw)?;

        Ok(KSection {
            name,
            vma: sh.sh_addr,
            size: sh.sh_size,
            file_offset: sh.sh_offset,
            flags: sh.sh_flags,
            raw_data: PlatformType::ELF(raw),
        })
    }

    pub fn from_goblin_ph<R: io::Seek + io::Read>(
        cursor: &mut R,
        elf: &Elf,
        buf_len: usize,
    ) -> io::Result<Vec<Self>> {
        let mut sections = vec![];
        for (i, ph) in elf.program_headers.iter().enumerate() {
            if ph.p_type != PT_LOAD {
                continue;
            }

            if ph.p_filesz == 0 || (ph.p_offset as usize + ph.p_filesz as usize) > buf_len {
                continue;
            }

            let name = format!(".segment_{}", i);
            let mut raw = vec![0u8; ph.p_filesz as usize];
            cursor.seek(SeekFrom::Start(ph.p_offset))?;
            cursor.read_exact(&mut raw)?;

            // Map Program Header (Segment) to a KSection
            let x = KSection {
                name,
                vma: ph.p_vaddr,
                size: ph.p_memsz, // Use p_memsz for virtual size
                file_offset: ph.p_offset,
                flags: ph.p_flags as u64,
                raw_data: PlatformType::ELF(raw),
            };
            sections.push(x);
        }
        Ok(sections)
    }
}
