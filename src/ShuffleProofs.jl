module ShuffleProofs

using CryptoGroups: CryptoGroups

function __init__()
    CryptoGroups.set_strict_mode(true)
end

import SigmaProofs: prove, verify, proof_type

include("utils.jl")
include("prover.jl") 
include("verifier.jl") 

SigmaProofs.proof_type(::Type{Shuffle{G, N}}) where {G <: Group, N} = PoSProof{G, N} 
SigmaProofs.proof_type(::Type{Shuffle}) = PoSProof #

Base.isvalid(::Type{VShuffleProof{G, N}}, proposition::Shuffle{G, N}) where {G <: Group, N} = true

include("braid.jl")
include("serializer.jl")

end # module
