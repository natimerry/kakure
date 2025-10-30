use crate::header::Header;
use byteorder::{ReadBytesExt, LE};
use std::io;

/// Represents the ELF (Executable and Linkable Format) header for a 64-bit object file.
///
/// This structure corresponds to the standard `Elf64_Ehdr` defined in the ELF specification.
/// It appears at the very beginning of every ELF file and contains metadata describing
/// the file’s organization and layout.
///
/// Reference: [ELF Specification v1.2](https://refspecs.linuxfoundation.org/elf/elf.pdf)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    /// ELF identification bytes (magic number and other information).
    ///
    /// The first 4 bytes should be `0x7F`, `'E'`, `'L'`, `'F'`.
    /// Remaining bytes encode class (32/64-bit), endianness, and version.
    pub e_ident: [u8; 16],

    /// Object file type (e.g. relocatable, executable, shared, core).
    ///
    /// Common values:
    /// - `ET_NONE` (0): No file type
    /// - `ET_REL` (1): Relocatable file
    /// - `ET_EXEC` (2): Executable file
    /// - `ET_DYN` (3): Shared object
    /// - `ET_CORE` (4): Core dump
    pub e_type: u16,

    /// Target architecture (e.g., x86_64, ARM).
    ///
    /// Common values:
    /// - `EM_X86_64` (62)
    /// - `EM_AARCH64` (183)
    pub e_machine: u16,

    /// ELF version (usually set to `EV_CURRENT` = 1).
    pub e_version: u32,

    /// Virtual address of the program entry point.
    ///
    /// This is where execution starts when the ELF is loaded.
    pub e_entry: u64,

    /// File offset of the program header table.
    ///
    /// Points to an array of `Elf64Phdr` entries.
    pub e_phoff: u64,

    /// File offset of the section header table.
    ///
    /// Points to an array of `Elf64Shdr` entries.
    pub e_shoff: u64,

    /// Processor-specific flags.
    pub e_flags: u32,

    /// Size of this ELF header (usually `64` bytes for ELF64).
    pub e_ehsize: u16,

    /// Size of one entry in the program header table.
    pub e_phentsize: u16,

    /// Number of entries in the program header table.
    pub e_phnum: u16,

    /// Size of one entry in the section header table.
    pub e_shentsize: u16,

    /// Number of entries in the section header table.
    pub e_shnum: u16,

    /// Index of the section header string table.
    ///
    /// This section contains the names of all other sections.
    pub e_shstrndx: u16,
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

    fn from_reader<R: io::Read + io::Seek>(cur: &mut R) -> anyhow::Result<Elf64Ehdr> {
        let mut e_ident = [0u8; 16];
        cur.read_exact(&mut e_ident)?;

        Ok(Elf64Ehdr {
            e_ident,
            e_type: cur.read_u16::<LE>()?,
            e_machine: cur.read_u16::<LE>()?,
            e_version: cur.read_u32::<LE>()?,
            e_entry: cur.read_u64::<LE>()?,
            e_phoff: cur.read_u64::<LE>()?,
            e_shoff: cur.read_u64::<LE>()?,
            e_flags: cur.read_u32::<LE>()?,
            e_ehsize: cur.read_u16::<LE>()?,
            e_phentsize: cur.read_u16::<LE>()?,
            e_phnum: cur.read_u16::<LE>()?,
            e_shentsize: cur.read_u16::<LE>()?,
            e_shnum: cur.read_u16::<LE>()?,
            e_shstrndx: cur.read_u16::<LE>()?,
        })
    }
}
