abstract type Generator end


untype(G::Type{<:Generator}) = G.parameters[1] # A dirty hack 

group(G::Type{<:Generator}) = G.parameters[1]#.parameters[1]
group(::G) where G <: Generator = G.parameters[1]


Base.show(io::IO, 𝓖::Type{Generator}) = print(io, "Generator")
Base.show(io::IO, 𝓖::Type{<:Generator}) = print(io, "Generator[$(group(𝓖))]")

order(G::Type{<:Generator}) = order(G.parameters[1])
order(::G) where G <: Generator = order(G.parameters[1])


Base.convert(::Type{G}, x) where G <: Generator = G(x)
Base.convert(::Type{G}, g::G) where G <: Generator = g # Identity


"""
Returns a value of the function
"""
function value end
Base.isless(x::G, y::G) where G <: Generator = value(x) < value(y)

import Base.==
==(x::Generator, y::Generator) = false
==(x::G, y::G) where G <: Generator = value(x) == value(y)

==(x::Generator, y) = error("Uncomparable: $(typeof(x)) with $(typeof(y))")
==(x, y::Generator) = error("Uncomparable: $(typeof(x)) with $(typeof(y))")


postfix(G::Generator) = postfix(group(G))

import Base.show
Base.show(io::IO, g::Generator) = print(io, "$(value(g)) " * style(postfix(g), 90))


function Base.show(io::IO, g::Vector{G}) where G <: Generator
    show(io, value.(g))
    Group = untype(G)
    str = " " * postfix(Group)
    print(io, style(str, 90))
end

Base.display(x::Vector{G}) where G <: Generator = show(x)


Base.show(io::IO, g::NTuple{N, <:Generator}) where N = print(io, "$(value.(g)) " * style(postfix(g[1]), 90))


# A more generic function can be constructed if necessary
Base.broadcasted(f::Function, x::Generator, y::AbstractVector{<:Integer}) = f.((x for i in 1:length(y)), y)

Base.broadcasted(::typeof(*), x::G, y::Vector{G}) where G <: Generator = (x for i in 1:length(y)) .* y 
Base.broadcasted(::typeof(*), x::Vector{G}, y::G) where G <: Generator =  x .* (y for i in 1:length(x))

############################# PRIME GROUP #################################


struct PrimeGroup{N} ### Type parameter is essential to ensure it to be bitstype
    x::StaticBigInt{N}
end


PrimeGroup(x::Integer) = PrimeGroup(StaticBigInt(x))
PrimeGroup(; q) = PrimeGroup(2*q + 1)


Base.getindex(::Type{Generator}, 𝓖::PrimeGroup) = PrimeGenerator{𝓖} # This is somewhat like a trait


const 𝐙 = PrimeGroup
import Base./
/(::Type{𝐙}, p::Integer) = PrimeGroup(p)


modulus(G::PrimeGroup) = BigInt(G.x)
order(G::PrimeGroup) = (modulus(G) - 1) ÷ 2

# Z/(p) notation seems more reasonable for printing this. Seems more appropriate to be left for PrimeGroup
postfix(G::PrimeGroup) = "mod $(modulus(G)) (q = $(order(G)))"


# An alternative for presenting the group

# function subscript(x::Integer)
#     str = string(x)
#     chararr = Char[]

#     for c in str
#         if c == '1'
#             push!(chararr, '₁')
#         elseif c == '2'
#             push!(chararr, '₂')
#         elseif c == '3'
#             push!(chararr, '₃')
#         elseif c == '4'
#             push!(chararr, '₄')
#         elseif c == '5'
#             push!(chararr, '₅')
#         elseif c == '6'
#             push!(chararr, '₆')
#         elseif c == '7'
#             push!(chararr, '₇')
#         elseif c == '8'
#             push!(chararr, '₈')
#         elseif c == '9'
#             push!(chararr, '₉')
#         elseif c == '0'
#             push!(chararr, '₀')
#         end
#     end
    
#     subscript = String(chararr)
    
#     return subscript
# end

# groupstr(m) = "𝓩$(subscript(m))"


function trimnumber(x::String)
    if length(x) < 30
        return x
    else
        return x[1:10] * "..." * x[end-10:end]
    end
end

trimnumber(x::Integer)= trimnumber(string(x))



groupstr(m) = "𝐙/($(trimnumber(m)))"

Base.show(io::IO, x::PrimeGroup) = print(io, groupstr(modulus(x)))

############################ PRIME GENERATOR ##################################


struct PrimeGenerator{G} <: Generator #{G} 
    g::BigInt
end


PrimeGenerator(x::Integer, p::Integer) = PrimeGenerator{PrimeGroup(p)}(x)


modulus(g::PrimeGenerator) = modulus(group(g)) # A method which one could add. 
value(g::PrimeGenerator) = g.g 

validate(g::PrimeGenerator) = value(g) != 1 && value(g^order(g)) == 1


Base.convert(::Type{BigInt}, x::PrimeGenerator) = value(x)

import Base.*
*(x::PrimeGenerator{G}, y::PrimeGenerator{G}) where G = PrimeGenerator{G}(mod(value(x) * value(y), modulus(G)))


import Base.^
^(x::PrimeGenerator{G}, n::Integer) where G = PrimeGenerator{G}(powermod(x.g, n, modulus(G)))

modinv(s, q) = gcdx(s, q)[2]

import Base.inv
inv(x::PrimeGenerator{G}) where G = PrimeGenerator{G}(modinv(value(x), modulus(G)))

import Base./
/(x::PrimeGenerator, y::PrimeGenerator) = x * inv(y)


### Need to add also elgamal encrytption primitives as follows:

struct Enc{T<:Generator} 
    pk::T
    g::T
end

### Encrytion as we see does eactually 
#(enc::Enc{T})(m::T, r::Integer) where T <: Generator = (m*enc.pk^r, enc.g^r) ### Message first?
#(enc::Enc)(r::Integer) = (enc.pk^r, enc.g^r)  

(enc::Enc{T})(m::T, r::Integer) where T <: Generator = (enc.g^r, m*enc.pk^r) ### Message first?
(enc::Enc)(r::Integer) = (enc.g^r, enc.pk^r)  



a(x::Tuple{T, T}) where T <: Generator = x[1]
b(x::Tuple{T, T}) where T <: Generator = x[2]


*(x::Tuple{G, G}, y::Tuple{G, G}) where G <: Generator = (a(x)*a(y), b(x)*b(y))

(enc::Enc)(e::Tuple{G, G}, r::Integer) where G <: Generator = e * enc(r)

struct ElGamal{G <: Generator} <: AbstractVector{G}
    a::Vector{G}
    b::Vector{G}

    function ElGamal{G}(a::Vector{G}, b::Vector{G}) where {G <: Generator} 
        @assert length(a) == length(b)
        return new(a, b)
    end
end

ElGamal(a::Vector{G}, b::Vector{G}) where G <: Generator = ElGamal{G}(a, b)

ElGamal(e::Vector{Tuple{G, G}}) where G <: Generator = ElGamal([a(i) for i in e], [b(i) for i in e])

function ElGamal{G}(a::Vector{T}, b::Vector{T}) where {T, G<:Generator}
    a′ = convert(Vector{G}, a)
    b′ = convert(Vector{G}, b)

    return ElGamal{G}(a′, b′)
end


a(e::ElGamal) = e.a
b(e::ElGamal) = e.b

Base.getindex(e::ElGamal, i::Int) = (a(e)[i], b(e)[i])
Base.length(e::ElGamal) = length(a(e))
Base.size(e::ElGamal) = size(a(e))

function *(x::ElGamal{G}, y::ElGamal{G}) where G

    @assert length(x) == length(y)

    a′ = a(x) .* a(y)
    b′ = b(x) .* b(y)

    return ElGamal(a′, b′)
end

function *(x::ElGamal{G}, y::Tuple{G, G}) where G 
    
    a′ = a(x) .* a(y)
    b′ = b(x) .* b(y)

    return ElGamal(a′, b′)
end

*(x::Tuple{G, G}, y::ElGamal{G}) where G = y * x

(enc::Enc)(e::ElGamal, r::Integer) = enc(r) * e 


function (enc::Enc{G})(m::Vector{G}, r::AbstractVector{<:Integer}) where G <: Generator

    a′ = enc.g .^ r
    b′ = m .* (enc.pk .^ r)

    return ElGamal(a′, b′)
end


struct Dec
    sk::Integer
end


#(dec::Dec)(e::Tuple{G, G}) where G = a(e) * b(e)^(-dec.sk) # Only operation for which it is desirable to store encryptions as a tuple. 

(dec::Dec)(e::Tuple{G, G}) where G = b(e) * a(e)^(-dec.sk) # Only operation for which it is desirable to store encryptions as a tuple. 

(dec::Dec)(e::ElGamal) = [dec(ei) for ei in e]

Base.isless(x::Tuple{G, G}, y::Tuple{G, G}) where G <: Generator = x[1] == y[1] ? x[2] < y[2] : x[1] < y[1]
