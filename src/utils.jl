tobig(x) = parse(BigInt, bytes2hex(reverse(x)), base=16)

function int2bytes(x::Integer)
    hex = string(x, base=16)
    if mod(length(hex), 2) != 0
        hex = string("0", hex)
    end
    
    return reverse(hex2bytes(hex))
end

bitsize(::Type{T}) where T <: Integer = T.size * 8
#bitsize(::Type{UInt8}) = 8


### This piece will be different for BigInt
function frombytes(::Type{T}, x::Vector{UInt8}) where T <: Integer 

    L = bitsize(T) ÷ 8
    y = UInt8[x..., zeros(UInt8, L - length(x))...]
    r = reinterpret(T, y)[1]

    return r
end

frombytes(::Type{BigInt}, x::Vector{UInt8}) = tobig(x) # I do also need to know number of bits here 


function frombytes(::Type{T}, x::Vector{UInt8}, N::Int) where T <: Integer
    
    M = length(x) ÷ N
    x = reshape(x, (M, N))

    numbers = T[frombytes(T, x[:, i]) for i in 1:N]

    return numbers
end


function bitsize(p::Integer)
    # ceil(log2( c + 1)) is another option
    @assert p > 0 "Not implemented"

    bits = bitstring(p)
    start = findfirst(x -> x == '1', bits)
    N = length(bits[start:end])
    return N
end


function bitsize(p::BigInt)
    @assert p > 0 "Not implemented"

    bytes = int2bytes(p)
    #bits = bitstring(bytes[1])
    bits = bitstring(bytes[end])
    start = findfirst(x -> x == '1', bits)
    N = length(bytes) * 8  - (start - 1)

    return N
end

