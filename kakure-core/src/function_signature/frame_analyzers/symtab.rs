use crate::FunctionSignature;
use anyhow::bail;
use byteorder::{ReadBytesExt, LE};
use goblin::elf::sym::STT_FUNC;
use goblin::elf32::section_header::SHN_UNDEF;
use std::io::Cursor;
use std::mem;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Sym {
    pub fn from_section(symtab_data: &[u8]) -> anyhow::Result<Vec<Elf64Sym>> {
        let num_symbols = symtab_data.len() / size_of::<Elf64Sym>();

        if symtab_data.len() % std::mem::size_of::<Elf64Sym>() != 0 {
            bail!("Invalid symtab size for 64-bit");
        }

        let mut signatures = Vec::with_capacity(num_symbols);

        let mut reader = Cursor::new(symtab_data);

        for i in 0..num_symbols {
            let offset = i * std::mem::size_of::<Elf64Sym>();
            let sym_bytes = &symtab_data[offset..offset + std::mem::size_of::<Elf64Sym>()];

            let st_name = reader.read_u32::<LE>()?;
            let st_info = reader.read_u8()?;
            let st_other = reader.read_u8()?;
            let st_shndx = reader.read_u16::<LE>()?;
            let st_value = reader.read_u64::<LE>()?;
            let st_size = reader.read_u64::<LE>()?;

            if st_shndx == SHN_UNDEF as u16 || st_value == 0 || st_size == 0 {
                continue;
            }

            let symbol = Self {
                st_name,
                st_info,
                st_other,
                st_shndx,
                st_value,
                st_size,
            };

            signatures.push(symbol);
        }
        Ok(signatures)
    }

    pub fn name_from_symtab(&self, strtab_data: &[u8]) -> anyhow::Result<String> {
        let name = if (self.st_name as usize) < strtab_data.len() {
            let name_start = self.st_name as usize;
            let name_end = strtab_data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| name_start + pos)
                .unwrap_or(strtab_data.len());

            std::str::from_utf8(&strtab_data[name_start..name_end]).unwrap_or("<invalid_utf8>")
        } else {
            "<invalid_name>"
        };

        let function_identifier = if name.is_empty() {
            format!("FUNC_{:#x}", self.st_value)
        } else {
            name.to_string()
        };

        Ok(function_identifier)
    }
}

pub fn parse_symtab_64(
    symbols: Vec<Elf64Sym>,
    strtab_data: &[u8],
) -> anyhow::Result<Vec<FunctionSignature>> {
    let mut signatures = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        let name = if (symbol.st_name as usize) < strtab_data.len() {
            let name_start = symbol.st_name as usize;
            let name_end = strtab_data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| name_start + pos)
                .unwrap_or(strtab_data.len());

            std::str::from_utf8(&strtab_data[name_start..name_end]).unwrap_or("<invalid_utf8>")
        } else {
            "<invalid_name>"
        };

        let function_identifier = if name.is_empty() {
            format!("FUNC_{:#x}", symbol.st_value)
        } else {
            name.to_string()
        };

        signatures.push(FunctionSignature {
            function_identifier,
            start: symbol.st_value as u64,
            end: (symbol.st_value + symbol.st_size) as u64,
            size: symbol.st_size as u64,
        });
    }
    Ok(signatures)
}
