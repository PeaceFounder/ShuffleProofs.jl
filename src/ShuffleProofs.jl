module ShuffleProofs

using CryptoGroups: CryptoGroups
CryptoGroups.set_strict_mode(true)

include("utils.jl") # Common functions

include("prover.jl") 

include("parser.jl") 
include("io.jl") # Some convinience methods

include("verifier.jl") 

include("decryption.jl") 

include("braid.jl")

include("store.jl")

end # module
