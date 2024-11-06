using CryptoGroups.Specs: GroupSpec, ECP, EC2N
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

function modprod(elements::Vector{T}, q::T) where T <: Integer
    return reduce((x, y) -> (x * y) % q, elements; init=T(1))
end

# function modsum(elements::Vector{T}, q::T) where T <: Integer
#     return reduce((x, y) -> (x + y) % q, elements; init=T(0))
# end

# Different implementations of modular sum
function modsum(elements::Vector{T}, q::T; batch_size::Int=1000) where T <: Integer
    n = length(elements)
    result = T(0)
    
    # Process in batches to reduce number of modulo operations
    for i in 1:batch_size:n
        batch_end = min(i + batch_size - 1, n)
        # Sum within batch without modulo
        batch_sum = sum(@view(elements[i:batch_end]))
        # Apply modulo only once per batch
        result = (result + batch_sum) % q
    end
    
    return result
end
