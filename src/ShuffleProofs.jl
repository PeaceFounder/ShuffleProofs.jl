module ShuffleProofs

#using Infiltrator

include("utils.jl") # Common functions

include("prover.jl") 

include("parser.jl") 
include("io.jl") # Some convinience methods

include("verifier.jl") 

end # module
