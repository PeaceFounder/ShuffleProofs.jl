using Mods: Mod

struct PrimeGenerator
    x::Mod
end


modulus(a::Mod) = a.mod
value(a::Mod) = a.val


"""
We assume a prime order. That means (p - 1)/2 is a prime.
"""
PrimeGenerator(x::Integer, p::Integer) = PrimeGenerator(Mod(x, p))


import Base.*
*(x::PrimeGenerator, y::PrimeGenerator) = PrimeGenerator(x.x*y.x)

import Base./
/(x::PrimeGenerator, y::PrimeGenerator) = PrimeGenerator(x.x / y.x)

import Base.==
==(x::PrimeGenerator, y::PrimeGenerator) = x.x == y.x

import Base.inv
inv(x::PrimeGenerator) = PrimeGenerator(inv(x.x))


import Mods.modulus
modulus(g::PrimeGenerator) = modulus(g.x)

import Mods.value
value(g::PrimeGenerator) = value(g.x)


order(g::PrimeGenerator) = (modulus(g) - 1) ÷ 2
validate(g::PrimeGenerator) = g.x != 1 && g.x^order(g) == 1


import Base.^
"""
Beacuse a prime order group is cyclic, in order to put it in power larger than that of it's order we can take it's mod.
"""
^(g::PrimeGenerator, n::Integer) = PrimeGenerator(g.x^n) # Redefining in this way because prone to make an invalid test

style(x, n) = "\33[1;$(n)m$x\33[0m"

import Base.show
Base.show(io::IO, g::PrimeGenerator) = print(io, "$(value(g.x))" * style(" mod $(modulus(g.x)) (q = $(order(g)))", 90))

"""
A group is cyclic only if it's order is a prime. This function evaluates a prime modulo for a given prime order.
"""
safeprime(q::Integer) = 2*q + 1


Base.isless(x::PrimeGenerator, y::PrimeGenerator) = value(x) < value(y)



############################################ TODO ##################################################

struct GVector{G}
    x::Vector{T} where T
    g::G
end

####################################################################################################



### Representation of field elements

# Need something smarter in the end
bitlength(x::PrimeGenerator) = bitlength(modulus(x)) 

Leaf(x::PrimeGenerator; L = bitlength(x)) = Leaf(value(x), div(L + 1, 8, RoundUp))


function Tree(x::Vector{PrimeGenerator})
    L = bitlength(x[1])
    s = Leaf[Leaf(i, L = L) for i in x]
    return Node(s)
end


function marshal(x::PrimeGenerator)

    java_name = "com.verificatum.arithm.ModPGroup"
    p = modulus(x)
    q = order(x)
    g = Leaf(x)
    e = UInt32(1)

    msg = (java_name, (p, q, g, e))

    tree = Tree(msg)

    return tree
end

function unmarshal(::Type{T}, x::Node) where T

    (java_name, (p, q, g, e)) = convert(Tuple{String, Tuple{T, T, T, UInt32}}, x)
    
    @assert java_name == "com.verificatum.arithm.ModPGroup" # Alternativelly I could have an if statement
    
    # May as well do assertion here, but that is not necessary as forward and backwards conversion would be rather enough.

    x = PrimeGenerator(g, p)

    @assert order(x) == q "The modular group does not use safe primes"
    
    return x
end


### Now I need to make the generator group elements as desired


function crs(g::PrimeGenerator, N::Int, prg::PRG, nr::Int)
    
    p = modulus(g)
    q = order(g)

    np = bitlength(p)

    𝐭 = rand(prg, BigInt, N; n = np + nr)

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐡 = powermod.(𝐭′, (p - 1) ÷ q, p)

    return 𝐡
end


