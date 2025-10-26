pub mod frame_analyzers;
pub use frame_analyzers::*;

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub function_identifier: String,
    pub start: u64,
    pub end: u64,
    pub size: u64,
}
