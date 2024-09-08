module ShuffleProofs

using CryptoGroups: CryptoGroups

function __init__()
    CryptoGroups.set_strict_mode(true)
end

include("../SigmaProofs/src/SigmaProofs.jl")

include("utils.jl") # Common functions
include("prover.jl") 
include("parser.jl") 
include("io.jl") # Some convinience methods
include("verifier.jl") 
include("decryption.jl") 
include("braid.jl")
include("store.jl")

end # module
