pub mod eh_frame;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PossibleFrames {
    // DWARF / Exception-Handling
    EhFrame,    // .eh_frame
    DebugFrame, // .debug_frame
    EhFrameHdr, // .eh_frame_hdr

    // ELF Program Startup/Shutdown
    InitArray, // .init_array
    FiniArray, // .fini_array
    Ctors,     // .ctors (legacy)
    Dtors,     // .dtors (legacy)

    // ELF Code / Symbols
    Text,   // .text section
    Symtab, // .symtab symbol table
    DynSym, // .dynsym dynamic symbol table
    Plt,    // Procedure Linkage Table
    Got,    // Global Offset Table (indirect function pointers)

    // Compiler / Optional / Misc
    GccExceptTable, // .gcc_except_table
    Pdata,          // Windows-style / PE unwind info if cross-compiled
}

impl std::str::FromStr for PossibleFrames {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ehframe" | ".eh_frame" => Ok(PossibleFrames::EhFrame),
            "debugframe" | ".debug_frame" => Ok(PossibleFrames::DebugFrame),
            "ehframehdr" | ".eh_frame_hdr" => Ok(PossibleFrames::EhFrameHdr),
            "initarray" | ".init_array" => Ok(PossibleFrames::InitArray),
            "finiarray" | ".fini_array" => Ok(PossibleFrames::FiniArray),
            "ctors" | ".ctors" => Ok(PossibleFrames::Ctors),
            "dtors" | ".dtors" => Ok(PossibleFrames::Dtors),
            "text" | ".text" => Ok(PossibleFrames::Text),
            "symtab" | ".symtab" => Ok(PossibleFrames::Symtab),
            "dynsym" | ".dynsym" => Ok(PossibleFrames::DynSym),
            "plt" | ".plt" => Ok(PossibleFrames::Plt),
            "got" | ".got" => Ok(PossibleFrames::Got),
            "gccexcepttable" | ".gcc_except_table" => Ok(PossibleFrames::GccExceptTable),
            "pdata" | ".pdata" => Ok(PossibleFrames::Pdata),
            _ => Err(format!("Unknown frame type: {}", s)),
        }
    }
}

// Optional: implement Display for nicer clap output
impl fmt::Display for PossibleFrames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            PossibleFrames::EhFrame => ".eh_frame",
            PossibleFrames::DebugFrame => ".debug_frame",
            PossibleFrames::EhFrameHdr => ".eh_frame_hdr",
            PossibleFrames::InitArray => ".init_array",
            PossibleFrames::FiniArray => ".fini_array",
            PossibleFrames::Ctors => ".ctors",
            PossibleFrames::Dtors => ".dtors",
            PossibleFrames::Text => ".text",
            PossibleFrames::Symtab => ".symtab",
            PossibleFrames::DynSym => ".dynsym",
            PossibleFrames::Plt => ".plt",
            PossibleFrames::Got => ".got",
            PossibleFrames::GccExceptTable => ".gcc_except_table",
            PossibleFrames::Pdata => ".pdata",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug)]
pub struct FrameAnalyzer<'a> {
    pub data: &'a [u8],
    pub base_address: u64,
}

// ─────────────────────────────────────────────
// Common Information Entry (CIE) Layout (.eh_frame)
// ─────────────────────────────────────────────
// Each entry in .eh_frame starts with a length field.
// If CIE_id == 0, it's a CIE. Otherwise, it's an FDE (Frame Description Entry).
//
// Offsets are relative to the start of the entry (after length).
//
// [0x00 - 0x03]  4 bytes   Length (excluding this field itself)
// [0x04 - 0x07]  4 bytes   CIE ID (0 for .eh_frame, 0xFFFFFFFF for .debug_frame)
//
// ─────────────── CIE body starts ───────────────
//
// [0x08]         1 byte    Version (usually 1 or 3)
// [0x09 .. ?]    N bytes   Augmentation string (null-terminated ASCII)
//
// After augmentation string:
//
// [?]            ULEB128   Code alignment factor
// [?]            SLEB128   Data alignment factor
// [?]            1 byte    Return address register (encoded as DWARF reg num)
//
// If augmentation string starts with 'z':
// [?]            ULEB128   Augmentation data length
//
// Then optionally, depending on augmentation string letters:
//
// 'L' → 1 byte   LSDA encoding
// 'P' → variable  Personality routine pointer (encoded per augmentation encoding)
// 'R' → 1 byte   FDE encoding
//
// ─────────────── CIE Instructions ───────────────
//
// Remaining bytes until end of CIE length:
// [ ... ]        N bytes   Initial Instructions (DWARF Call Frame Instructions)
//
// ───────────────
// Total size = 4 (length) + 4 (CIE_id) + body_length
// ───────────────

impl<'a> FrameAnalyzer<'a> {
    pub fn new(data: &'a [u8], base_address: u64) -> Self {
        Self { data, base_address }
    }
}
