module Verificatum

using Infiltrator

include("utils.jl") # Common functions

include("generators.jl") 
include("primitives.jl") 


include("parser.jl") 
include("io.jl") # Some convinience methods





# I could add a similar mwthod to string. 

export Node, Leaf, Tree

end # module
