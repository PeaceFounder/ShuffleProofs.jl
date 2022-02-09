module Verificatum

using Infiltrator

include("utils.jl") # Common functions

include("generators.jl") 
include("primitives.jl") 


include("parser.jl") 


export Node, Leaf, Tree

end # module
