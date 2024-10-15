using SigmaProofs.Parser: Tree

import Base: &

mutable struct Report
    data::Vector{Tuple{String, Union{Bool, BitVector}}} # It could actually be made optional
    state::Bool # Whether all previous expressions have been 
end

Report() = Report(Tuple{String, Union{Bool, BitVector}}[], true)

function (&)(report::Report, x::Tuple{String, Bool})
    push!(report.data, x)
    (name, value) = x
    report.state &= value
    return report
end

function (&)(report::Report, x::Tuple{String, BitVector}) 
    push!(report.data, x)
    (name, values) = x
    report.state &= prod(values)
    return report
end

(&)(report::Report, x::Tuple{String, Vector{Bool}}) = report & (x[1], BitVector(x[2]))


_entry(io::IO, key::String, value::Bool) = println(io, "$key: $value")

function _entry(io::IO, key::String, values::BitVector)

    t = prod(values)
    _entry(io, key, t)
    
    if t == false
        for (i, value) in enumerate(values)
            println(io, "    $i: $value")
        end
    end
end


function Base.println(io::IO, report::Report)
    
    println(io, "Report: $(isvalid(report))")
    
    (; data) = report

    for (key, value) in data
        print(io, "  ")
        _entry(io, key, value)
    end
end

Base.isvalid(report::Report) = report.state


# Returns the depth of the tree
function depth(tree::Tree)

    if tree isa Leaf
        return 0
    else
        return 1 + depth(tree[1])
    end

end
