use crate::elf::KSection;
use crate::PlatformType;
use goblin::pe::PE;
use std::io;
use std::io::Seek;
use anyhow::Result;
use crate::header::pe::Pe64Header;

impl KSection {
    pub fn from_goblin_pe_section<R: io::Seek + io::Read>(
        cursor: &mut R,
        pe: &goblin::pe::PE,
    ) -> Result<Vec<Self>> {
        let sections = pe
            .sections
            .iter()
            .map(|section| {
                // Extract section name from the name bytes array
                let name = section.real_name.clone().unwrap_or_else(|| {
                    // Fallback: convert name bytes to string, trimming null bytes
                    std::str::from_utf8(&section.name)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string()
                });

                // Read raw section data from the cursor
                let raw_data = if section.size_of_raw_data > 0 && section.pointer_to_raw_data > 0 {
                    // Seek to the section's file offset
                    cursor.seek(io::SeekFrom::Start(section.pointer_to_raw_data as u64))?;

                    // Allocate buffer and read exact amount of bytes
                    let mut buffer = vec![0u8; section.size_of_raw_data as usize];
                    cursor.read_exact(&mut buffer)?;

                    buffer
                } else {
                    vec![]
                };

                Ok(KSection {
                    name,
                    vma: section.virtual_address as u64,
                    size: section.virtual_size as u64,
                    file_offset: section.pointer_to_raw_data as u64,
                    flags: section.characteristics as u64,
                    raw_data: PlatformType::PE(raw_data),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(sections)
    }

}
