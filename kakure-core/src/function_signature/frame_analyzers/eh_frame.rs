use anyhow::{anyhow, Result};
use gimli::{BaseAddresses, EhFrame, EhFrameHdr, NativeEndian, UnwindSection};

use crate::{FrameAnalyzer, FunctionSignature};

pub trait FdeParser {
    fn parse_eh_frame(&self) -> Result<Vec<FunctionSignature>>;
    fn parse_eh_frame_headers(&self) -> Result<Vec<FunctionSignature>>;
}

/// Implement for FrameAnalyzer
impl<'a> FdeParser for FrameAnalyzer<'a> {
    fn parse_eh_frame(&self) -> Result<Vec<FunctionSignature>> {
        let mut signatures = Vec::new();

        let eh_frame = EhFrame::new(self.data, NativeEndian);
        let bases = BaseAddresses::default().set_eh_frame(self.base_address);

        // Iterate over all FDEs (Frame Description Entries)
        let mut entries = eh_frame.entries(&bases);

        while let Some(entry) = entries.next()? {
            match entry {
                gimli::CieOrFde::Fde(partial_fde) => {
                    // Parse the FDE to get function information
                    if let Ok(fde) =
                        partial_fde.parse(|_, bases, o| eh_frame.cie_from_offset(bases, o))
                    {
                        let start = fde.initial_address();
                        let size = fde.len();
                        let end = start + size;
                        let function_name = format!("FUNC_{:#x}", start);
                        signatures.push(FunctionSignature {
                            function_identifier: function_name,
                            start,
                            end,
                            size,
                        });
                    }
                }
                gimli::CieOrFde::Cie(_) => {
                    // Skip CIE entries, we only care about FDEs
                    continue;
                }
            }
        }

        // Sort by start address for consistency
        signatures.sort_by_key(|sig| sig.start);
        Ok(signatures)
    }

    fn parse_eh_frame_headers(&self) -> Result<Vec<FunctionSignature>> {
        let mut signatures = Vec::new();
        let eh_frame = EhFrameHdr::new(self.data, NativeEndian);
        let bases = BaseAddresses::default().set_eh_frame_hdr(self.base_address);

        let eh_frame_parsed = eh_frame.parse(&bases, self.data.len().try_into().unwrap())?;

        let table = eh_frame_parsed.table();
        if let None = table {
            return Err(anyhow!("No table data in .eh_frame_hdr to parse"));
        }
        let table = table.unwrap();
        let mut table_iter = table.iter(&bases);

        while let Some(pointer_tuple) = table_iter.next()? {
            let (pointer1, pointer2) = pointer_tuple;

            let sign = FunctionSignature {
                function_identifier: format!("FUN_{:#X}", pointer1.pointer()),
                start: pointer1.pointer(),
                end: pointer2.pointer(),
                size: (pointer2.pointer() - pointer1.pointer()),
            };
            signatures.push(sign);
        }

        Ok(signatures)
    }
}
