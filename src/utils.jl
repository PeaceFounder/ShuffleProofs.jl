tobig(x) = parse(BigInt, bytes2hex(reverse(x)), base=16)

function int2bytes(x::Integer)
    hex = string(x, base=16)
    if mod(length(hex), 2) != 0
        hex = string("0", hex)
    end
    
    return reverse(hex2bytes(hex))
end

bitlength(::Type{T}) where T <: Integer = T.size * 8


#bitlength(p) = Int(ceil(log2(p + 1)))

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
