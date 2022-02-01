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


#Base.broadcast(::typeof(^), g::PrimeGenerator, v::Vector) = [g^i for i in v]


import Base.^
"""
Beacuse a prime order group is cyclic, in order to put it in power larger than that of it's order we can take it's mod.
"""
function ^(g::PrimeGenerator, n::Integer)
    n_mod = mod(n, order(g))
    #@assert n_mod != 0 "Power matches prime group order pointing to element {1}."
    n_mod==0 && (@warn "Power matches prime group order pointing to element {1}.")
    PrimeGenerator(g.x^n_mod)
end

style(x, n) = "\33[1;$(n)m$x\33[0m"

import Base.show
Base.show(io::IO, g::PrimeGenerator) = print(io, "$(value(g.x))" * style(" mod $(modulus(g.x)) (q = $(order(g)))", 90))

"""
A group is cyclic only if it's order is a prime. This function evaluates a prime modulo for a given prime order.
"""
safeprime(q::Integer) = 2*q + 1


Base.isless(x::PrimeGenerator, y::PrimeGenerator) = value(x) < value(y)

### Representation of field elements

# Need something smarter in the end
bitsize(x::PrimeGenerator) = bitsize(modulus(x)) #length(int2bytes(modulus(x))) * 8

Leaf(x::PrimeGenerator; L = bitsize(x)) = Leaf(value(x), div(L + 1, 8, RoundUp))


function Tree(x::Vector{PrimeGenerator})
    L = bitsize(x[1])
    s = Leaf[Leaf(i, L = L) for i in x]
    return Node(s)
end


# Conversion one needs to do manually as it is necessary to know additional paramters for the group. 

# struct PrimeGroup # May as well make it to be CyclicGroup whoose dispatch just depends on the generator.
#     g::PrimeGenerator
# end

# convert(::Type{Tree}, x::PrimeGroup) = convert(::Type{Tree}, ())

# Instead I could define methods marshal and unmarshal for groups generators. 

# I need to have four bytes for the last

function marshal(x::PrimeGenerator)

    java_name = "com.verificatum.arithm.ModPGroup"
    p = modulus(x)
    q = order(x)
    g = Leaf(x)
    e = Leaf(UInt32(1), trim = false)


    msg = (java_name, (p, q, g, e))

    tree = Tree(msg)

    return tree
end

function unmarshal(::Type{T}, x::Node) where T

    # Perhaps g and p need to be enforced to have the same bitlength
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

    np = bitsize(p)

    #P = div(np + nr, 8, RoundUp) # number of bytes

    l = div(np + nr, 8, RoundUp)

    𝐭 = rand(prg, BigInt, N; l = l)

    r = big(2)^(np + nr)
    𝐭′ = (t-> PrimeGenerator(mod(t, r), p)).(𝐭)

    𝐡 = 𝐭′ .^ ((p - 1) ÷ q)

    #@infiltrate
    
    return 𝐡
end

# np is bitlengt of p
# 
#bitsize = np + nr


#N = div(np + nr, 8, RoundUp)

