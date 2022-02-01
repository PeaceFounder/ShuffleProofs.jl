using Nettle


struct Hash
    spec::String
end

(h::Hash)(x::Vector{UInt8}) = hex2bytes(hexdigest(h.spec, x))
(h::Hash)(t::Tree) = h(convert(Vector{UInt8}, t))

# Dispatching on value types seems as plausable solution
outlen(::Hash) = 256 # Number of bits in the output of the hash function


struct PRG
    h::Hash
    s::Vector{UInt8}
end

(prg::PRG)(i::UInt32) = prg.h([prg.s..., reverse(reinterpret(UInt8, UInt32[i]))...])

import Base.rand


### The same function shall also work for UInt8!

# In principle I need to ensure uniqueness for the numbers 
# To ensure new set of numbers seed can be chnaged in deterministic way accordingly.
function rand(prg::PRG, ::Type{T}, N::Int; l = div(bitsize(T), 8, RoundUp)) where T <: Integer
    
    #P = bitsize(T)
    #l = P ÷ 8 

    #l = div(P, 8, RoundUp)
    
    M = l * N # Number of bytes needed
    
    K = UInt32(M ÷ (outlen(prg.h) ÷ 8))

    r = UInt8[]

    for i in UInt32(0):K
        ri = prg(i)
        append!(r, ri)
    end

    resize!(r, M)

    t = frombytes(T, r, N) ## Need to prepend

    return t
end


function rand(prg::PRG, range::UnitRange{T}, N::Int) where T <: Integer

    Δ = range.stop - range.start # Meaningful bit range
    @assert Δ > 0 "Defined only for a positive range"

    #P = length(int2bytes(Δ)) * 8
    
    l = div(bitsize(Δ), 8, RoundUp)
    
    
    #t = rand(prg, T, N; P = P)
    t = rand(prg, T, N; l = l)
    #rand(prg, T, N; P)
    
    t1 = mod.(t, range.stop + 1) # This does make the distribution a little bit nonunnnniform. It can introduce a nonuniquness even if t is unique. 
    t2 = t .+ range.start 

    return t2
end




# function zerofirst(x,n)
#    if n==1
#        x & 0b01111111
#    elseif n==2
#        x & 0b00111111
#    elseif n==3
#        x & 0b00011111
#    elseif n==4
#        x & 0b00001111
#    elseif n==5
#        x & 0b00000111
#    elseif n==6
#        x & 0b00000011  
#    elseif n==7
#        x & 0b00000001  
#    elseif n > 7 
#        x & 0b00000000
#    else
#        x
#    end
# end

zerofirst(x, n) = (x << n) >> n


struct RO
    h::Hash
    n_out::Int
end

function (ro::RO)(d::Vector{UInt8})
    (; h, n_out) = ro

    nb = reinterpret(UInt8, UInt32[n_out])
    s = h([reverse(nb)...,d...]) # Numbers on Java are represented in reverse
    prg = PRG(h, s)

    a = rand(prg, UInt8, div(n_out, 8, RoundUp))
    
    if mod(n_out, 8) != 0 
        a[1] = zerofirst(a[1], 8 - mod(n_out, 8))
    end

    return a
end


