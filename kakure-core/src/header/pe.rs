use std::io::{Read, Seek, SeekFrom};
use std::mem;
use byteorder::{ReadBytesExt, LE};
use crate::header::Header;

/// Represents the 64-bit PE (Portable Executable) NT header.
///
/// Layout matches:
/// - IMAGE_NT_HEADERS64 (Signature + FileHeader + OptionalHeader64)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Pe64Header {
    pub signature: u32,           // "PE\0\0" signature (0x00004550)
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,                    // Target machine architecture
    pub number_of_sections: u16,         // Number of sections
    pub time_date_stamp: u32,            // Timestamp of creation
    pub pointer_to_symbol_table: u32,    // File offset to COFF symbol table
    pub number_of_symbols: u32,          // Number of symbols in table
    pub size_of_optional_header: u16,    // Size of optional header
    pub characteristics: u16,            // File characteristics flags
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,                          // 0x20b for PE32+
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,         // RVA of entry point
    pub base_of_code: u32,                   // RVA of code section
    pub image_base: u64,                     // Preferred load address (64-bit)
    pub section_alignment: u32,              // Alignment in memory
    pub file_alignment: u32,                 // Alignment in file
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,            // Reserved, must be 0
    pub size_of_image: u32,                  // Size of image in memory
    pub size_of_headers: u32,                // Size of all headers
    pub check_sum: u32,                      // Image checksum
    pub subsystem: u16,                      // Subsystem required
    pub dll_characteristics: u16,            // DLL characteristics flags
    pub size_of_stack_reserve: u64,          // Stack reserve size (64-bit)
    pub size_of_stack_commit: u64,           // Stack commit size (64-bit)
    pub size_of_heap_reserve: u64,           // Heap reserve size (64-bit)
    pub size_of_heap_commit: u64,            // Heap commit size (64-bit)
    pub loader_flags: u32,                   // Obsolete
    pub number_of_rva_and_sizes: u32,        // Number of data directories
    pub data_directory: [ImageDataDirectory; 16], // Data directory array
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,  // RVA of the data
    pub size: u32,             // Size of the data
}


#[repr(C)]
struct DosHeader {
    pub signature: u16,                           // Magic number: 0x5A4D ("MZ")
    pub bytes_on_last_page: u16,                  // e_cblp
    pub pages_in_file: u16,                       // e_cp
    pub relocations: u16,                         // e_crlc
    pub size_of_header_in_paragraphs: u16,        // e_cparhdr
    pub minimum_extra_paragraphs_needed: u16,     // e_minalloc
    pub maximum_extra_paragraphs_needed: u16,     // e_maxalloc
    pub initial_relative_ss: u16,                 // e_ss
    pub initial_sp: u16,                          // e_sp
    pub checksum: u16,                            // e_csum
    pub initial_ip: u16,                          // e_ip
    pub initial_relative_cs: u16,                 // e_cs
    pub file_address_of_relocation_table: u16,    // e_lfarlc
    pub overlay_number: u16,                      // e_ovno
    pub reserved: [u16; 4],                       // e_res[4]
    pub oem_id: u16,                              // e_oemid
    pub oem_info: u16,                            // e_oeminfo
    pub reserved2: [u16; 10],                     // e_res2[10]
    pub pe_pointer: u32,                          // e_lfanew - offset to PE header
}



fn read_dos_header<R: Read + Seek>(cur: &mut R) -> anyhow::Result<DosHeader> {
    // Seek to the beginning of the file
    cur.seek(std::io::SeekFrom::Start(0))?;

    // Create a buffer of the exact size of DosHeader (64 bytes)
    let mut buffer = [0u8; mem::size_of::<DosHeader>()];

    // Read exactly 64 bytes into the buffer
    cur.read_exact(&mut buffer)?;

    // Safely transmute the bytes into the DosHeader struct
    let dos_header: DosHeader = unsafe {
        std::ptr::read(buffer.as_ptr() as *const DosHeader)
    };

    // Verify the DOS signature (MZ magic bytes)
    if dos_header.signature != 0x5A4D {
        anyhow::bail!("Invalid DOS signature: expected 0x5A4D, got 0x{:04X}", dos_header.signature);
    }

    Ok(dos_header)
}
impl Header for Pe64Header{
    fn entry_point(&self) -> u64 {
        self.optional_header.address_of_entry_point as u64
    }

    fn machine(&self) -> u16 {
        self.file_header.machine
    }

    fn is_64(&self) -> bool {
        true
    }

    fn format_name(&self) -> &'static str {
        "PE64"
    }

    fn is_executable(&self) -> bool {
        let characteristics = self.file_header.characteristics;
        characteristics == 0x0002 || characteristics == 0x2000
    }

    fn from_reader<R: Read + Seek>(cur: &mut R) -> anyhow::Result<Self>
    where
        Self: Sized
    {
        let dos_header = read_dos_header(cur)?;
        cur.seek(SeekFrom::Start(dos_header.pe_pointer as u64))?;

        let signature = cur.read_u32::<LE>()?;
        if signature != 0x00004550 {
            anyhow::bail!("Invalid PE signature: expected 0x00004550, got 0x{:08X}", signature);
        }

        // Read IMAGE_FILE_HEADER
        let file_header = ImageFileHeader {
            machine: cur.read_u16::<LE>()?,
            number_of_sections: cur.read_u16::<LE>()?,
            time_date_stamp: cur.read_u32::<LE>()?,
            pointer_to_symbol_table: cur.read_u32::<LE>()?,
            number_of_symbols: cur.read_u32::<LE>()?,
            size_of_optional_header: cur.read_u16::<LE>()?,
            characteristics: cur.read_u16::<LE>()?,
        };

        // Read IMAGE_OPTIONAL_HEADER64
        let magic = cur.read_u16::<LE>()?;
        if magic != 0x20b {
            anyhow::bail!("Not a PE64 file: magic is 0x{:04X}, expected 0x20b", magic);
        }

        let optional_header = ImageOptionalHeader64 {
            magic,
            major_linker_version: cur.read_u8()?,
            minor_linker_version: cur.read_u8()?,
            size_of_code: cur.read_u32::<LE>()?,
            size_of_initialized_data: cur.read_u32::<LE>()?,
            size_of_uninitialized_data: cur.read_u32::<LE>()?,
            address_of_entry_point: cur.read_u32::<LE>()?,
            base_of_code: cur.read_u32::<LE>()?,
            image_base: cur.read_u64::<LE>()?,
            section_alignment: cur.read_u32::<LE>()?,
            file_alignment: cur.read_u32::<LE>()?,
            major_operating_system_version: cur.read_u16::<LE>()?,
            minor_operating_system_version: cur.read_u16::<LE>()?,
            major_image_version: cur.read_u16::<LE>()?,
            minor_image_version: cur.read_u16::<LE>()?,
            major_subsystem_version: cur.read_u16::<LE>()?,
            minor_subsystem_version: cur.read_u16::<LE>()?,
            win32_version_value: cur.read_u32::<LE>()?,
            size_of_image: cur.read_u32::<LE>()?,
            size_of_headers: cur.read_u32::<LE>()?,
            check_sum: cur.read_u32::<LE>()?,
            subsystem: cur.read_u16::<LE>()?,
            dll_characteristics: cur.read_u16::<LE>()?,
            size_of_stack_reserve: cur.read_u64::<LE>()?,
            size_of_stack_commit: cur.read_u64::<LE>()?,
            size_of_heap_reserve: cur.read_u64::<LE>()?,
            size_of_heap_commit: cur.read_u64::<LE>()?,
            loader_flags: cur.read_u32::<LE>()?,
            number_of_rva_and_sizes: cur.read_u32::<LE>()?,
            data_directory: {
                let mut dirs = [ImageDataDirectory { virtual_address: 0, size: 0 }; 16];
                for dir in &mut dirs {
                    dir.virtual_address = cur.read_u32::<LE>()?;
                    dir.size = cur.read_u32::<LE>()?;
                }
                dirs
            },
        };

        Ok(Pe64Header {
            signature,
            file_header,
            optional_header,
        })
    }
}