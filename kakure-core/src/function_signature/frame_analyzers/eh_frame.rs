use crate::FunctionSignature;
use anyhow::Result;
use gimli::{BaseAddresses, EhFrame, NativeEndian, UnwindSection};
pub fn parse_eh_frame(data: &[u8], base_address: u64) -> Result<Vec<FunctionSignature>> {
    let mut signatures = Vec::new();
    let eh_frame = EhFrame::new(data, NativeEndian);
    let bases = BaseAddresses::default().set_eh_frame(base_address);

    let mut entries = eh_frame.entries(&bases);
    while let Some(entry) = entries.next()? {
        if let gimli::CieOrFde::Fde(partial_fde) = entry {
            if let Ok(fde) = partial_fde.parse(|_, bases, o| eh_frame.cie_from_offset(bases, o)) {
                let start = fde.initial_address();
                let size = fde.len();
                signatures.push(FunctionSignature {
                    function_identifier: format!("FUNC_{:#x}", start),
                    start,
                    end: start + size,
                    size,
                });
            }
        }
    }

    signatures.sort_by_key(|sig| sig.start);
    Ok(signatures)
}
