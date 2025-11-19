pub mod elf;
pub mod pe;

use std::io::{self, SeekFrom};

use goblin::elf::{Elf, SectionHeader};
use goblin::elf32::program_header::PT_LOAD;

#[derive(Debug)]
pub enum PlatformType<T> {
    ELF(T),
    PE(T),
    Unknown(T),
}
