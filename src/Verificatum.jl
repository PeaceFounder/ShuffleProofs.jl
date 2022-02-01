module Verificatum

using Infiltrator

include("utils.jl") # Common functions

include("parser.jl")
include("primitives.jl")

include("generators.jl")


export Node, Leaf, Tree

end # module
