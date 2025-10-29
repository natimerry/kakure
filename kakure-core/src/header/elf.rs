use crate::header::Header;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16], // Magic number and other info
    pub e_type: u16,       // Object file type
    pub e_machine: u16,    // Architecture
    pub e_version: u32,    // Object file version
    pub e_entry: u64,      // Entry point virtual address
    pub e_phoff: u64,      // Program header table file offset
    pub e_shoff: u64,      // Section header table file offset
    pub e_flags: u32,      // Processor-specific flags
    pub e_ehsize: u16,     // ELF header size in bytes
    pub e_phentsize: u16,  // Program header table entry size
    pub e_phnum: u16,      // Program header table entry count
    pub e_shentsize: u16,  // Section header table entry size
    pub e_shnum: u16,      // Section header table entry count
    pub e_shstrndx: u16,   // Section header string table index
}

impl Header for Elf64Ehdr {
    fn entry_point(&self) -> u64 {
        self.e_entry
    }

    fn machine(&self) -> u16 {
        self.e_machine
    }

    fn is_64(&self) -> bool {
        true
    }

    fn format_name(&self) -> &'static str {
        "ELF"
    }

    fn is_executable(&self) -> bool {
        self.e_type == 0x2
    }
}
