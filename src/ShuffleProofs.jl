module ShuffleProofs

using Infiltrator

include("utils.jl") # Common functions

include("generators.jl") 
include("primitives.jl") 

include("verifier.jl") 



include("parser.jl") 
include("io.jl") # Some convinience methods
include("vverifier.jl") 


#greet() = print("Hello World!")

end # module
