pub mod elf;

pub trait Header: std::fmt::Debug + Send + Sync {
    /// Returns the virtual address of the entry point.
    fn entry_point(&self) -> u64;

    /// Returns the machine architecture identifier.
    fn machine(&self) -> u16;

    /// Returns true if this is a 64-bit binary.
    fn is_64(&self) -> bool;

    /// Returns a short human-readable name, e.g. "ELF" or "PE".
    fn format_name(&self) -> &'static str;

    /// Returns true if the binary represents an executable (vs object/lib).
    fn is_executable(&self) -> bool;
}
