enum CallFormat {
    FastCall,
    StdCall,
}
struct FunctionCallGraph {
    source_call: u64, // Address where the call originates from
    jump_to: u64,
}
