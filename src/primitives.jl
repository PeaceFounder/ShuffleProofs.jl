using Nettle


struct Hash
    spec::String
end

(h::Hash)(x::Vector{UInt8}) = hex2bytes(hexdigest(h.spec, x))

# Dispatching on value types seems as plausable solution
outlen(::Hash) = 256 # Number of bits in the output of the hash function

struct PRG
    h::Hash
    s::Vector{UInt8}
end

(prg::PRG)(i::UInt32) = prg.h([prg.s..., reverse(reinterpret(UInt8, UInt32[i]))...])


function Base.getindex(prg::PRG, range)
    (; start, stop) = range
    
    # I will be rather primitive on the matter here. 
    
    a = outlen(prg.h) ÷ 8 # which just gives 32

    K = div(stop, a, RoundUp) - 1

    r = UInt8[]
    
    for i in UInt32(0):UInt32(K)
        ri = prg(i)
        append!(r, ri)
    end
    
    return r[range]
end


struct RO
    h::Hash
    n_out::Int
end

zerofirst(x, n) = (x << n) >> n # Puts first n bits of a number x to zero. 

function (ro::RO)(d::Vector{UInt8})
    (; h, n_out) = ro

    nb = reinterpret(UInt8, UInt32[n_out])
    s = h([reverse(nb)...,d...]) # Numbers on Java are represented in reverse
    prg = PRG(h, s)

    a = prg[1:div(n_out, 8, RoundUp)]
    
    if mod(n_out, 8) != 0 
        a[1] = zerofirst(a[1], 8 - mod(n_out, 8))
    end

    return a
end


function Base.rand(prg::PRG, ::Type{T}, N::Int; n = bitlength(T)) where T

    M = div(n, 8, RoundUp) # bytes for each number

    total = M * N

    𝐫 = prg[1:total]
    𝐭 = interpret(Vector{BigInt}, 𝐫, N)
    
    return 𝐭
end



function crs(G::PrimeGroup, N::Int, prg::PRG, nr::Int)
    
    p = modulus(G)
    q = order(G)

    np = bitlength(p)

    𝐭 = rand(prg, BigInt, N; n = np + nr)

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐡 = powermod.(𝐭′, (p - 1) ÷ q, p)
    
    𝐡_typed = convert(Vector{PrimeGenerator{G}}, 𝐡)

    return 𝐡_typed
end
