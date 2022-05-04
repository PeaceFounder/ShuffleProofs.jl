tobig(x) = parse(BigInt, bytes2hex(reverse(x)), base=16)

function int2bytes(x::Integer)
    hex = string(x, base=16)
    if mod(length(hex), 2) != 0
        hex = string("0", hex)
    end
    
    return reverse(hex2bytes(hex))
end

style(x, n) = "\33[1;$(n)m$x\33[0m"

bitlength(::Type{T}) where T <: Integer = T.size * 8


function bitlength(p::Integer)

    bits = bitstring(p)
    start = findfirst(x -> x == '1', bits)
    N = length(bits) - start + 1

    return N
end


function bitlength(p::BigInt)

    bytes = int2bytes(p)
    bits = bitstring(bytes[end])
    start = findfirst(x -> x == '1', bits)
    N = length(bytes) * 8  - (start - 1)

    return N
end

bytelength(x::Integer) = div(bitlength(x) + 1, 8, RoundUp)


interpret(::Type{BigInt}, x::Vector{UInt8}) = tobig(reverse(x))

function interpret(::Type{T}, x::Vector{UInt8}) where T <: Integer 

    L = bitlength(T) ÷ 8
    y = UInt8[zeros(UInt8, L - length(x))..., x...]

    r = reinterpret(T, reverse(y))[1]
    return r
end


interpret(::Type{Vector{UInt8}}, x::BigInt) = reverse(int2bytes(x))

interpret(::Type{Vector{UInt8}}, x::Integer) = reverse(reinterpret(UInt8, [x])) # Number of bytes are useful for construction for bytes. 

function interpret(::Type{Vector{T}}, 𝐫::Vector{UInt8}, N::Int) where T <: Integer
    M = length(𝐫) ÷ N
    𝐮 = reshape(𝐫, (M, N))
    𝐭 = [interpret(T, 𝐮[:, i]) for i in 1:N]
    return 𝐭
end


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
