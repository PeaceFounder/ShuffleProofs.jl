import Base.convert
import Base.==

const NODE = UInt8(0)
const LEAF = UInt8(1)

abstract type Tree end

struct Leaf <: Tree
    x::Vector{UInt8} # Bytes
end

==(a::Leaf, b::Leaf) = a.x == b.x

struct Node <: Tree
    x::Vector{Tree} # Leaf or Node
end

==(a::Node, b::Node) = a.x == b.x

Node() = Node([])

Base.push!(n::Node, y) = push!(n.x, y)

toint(x) = reinterpret(UInt32, x[4:-1:1])[1] ### TOREMOVE

function parseb(x)
    
    if x[1] == LEAF

        L = interpret(UInt32, x[2:5])

        bytes = x[6:5+L]
        leaf = Leaf(bytes)

        if length(x) == L + 5
            rest = []
        else
            rest = x[L+6:end]
        end

        return leaf, rest

    elseif x[2] == NODE

        N = interpret(UInt32, x[2:5])

        rest = x[6:end]

        node = Node()

        for i in 1:N
            head, tail = parseb(rest)
            push!(node, head)
            rest = tail
        end
        
        return node, rest
    end
end


decode(x::Vector{UInt8}) = parseb(x)[1]
decode(x::AbstractString) = decode(hex2bytes(replace(x, " "=>""))) # I could have optional arguments here as well


function tobin(leaf::Leaf)

    N = UInt32(length(leaf.x))

    Nbin = interpret(Vector{UInt8}, N)
    bin = UInt8[LEAF, Nbin..., leaf.x...]

    return bin
end

function tobin(node::Node)
    
    N = UInt32(length(node.x))
    Nbin = interpret(Vector{UInt8}, N)
    
    data = UInt8[]

    for n in node.x
        b = tobin(n)
        append!(data, b)
    end

    bin = UInt8[NODE, Nbin..., data...]

    return bin
end

encode(x::Tree) = tobin(x)

convert(::Type{T}, x::Leaf) where T <: Integer = interpret(T, x.x)

function convert(::Type{String}, x::Leaf)
    return String(copy(x.x))
end

function convert(::Type{Vector{T}}, x::Node) where T #<: Integer 
    return T[convert(T, i) for i in x.x] 
end

function convert(cfact::Type{T}, x::Node) where T <: Tuple 
     return Tuple((convert(ci, xi) for (xi, ci) in zip(x.x, cfact.types)))
end

function Leaf(x::Signed)

    bytes = interpret(Vector{UInt8}, x) 

    # Adding a redundant byte to ensure that the number is positive. 
    if bytes[1] > 127
        return Leaf(UInt8[0, bytes...]) 
    else
        return Leaf(bytes)
    end
end

Leaf(x::Unsigned) = Leaf(interpret(Vector{UInt8}, x))
    

function Leaf(x::Integer, k::Integer) 
    
    if x == 0

        return Leaf(zeros(UInt8, k))

    else
        leaf = Leaf(x)

        N = findfirst(x -> x != UInt8(0), leaf.x)
        bytes = leaf.x[N:end]
        pad = k - length(bytes)

        return newleaf = Leaf(UInt8[zeros(UInt8, pad)...,bytes...])
    end
end


function Leaf(x::AbstractString)
    bytes = Vector{UInt8}(x)
    return Leaf(bytes)
end

Tree(x::Any) = Leaf(x) 
Tree(x::BigInt; L=bitlength(x)) = Leaf(x, div(L + 1, 8, RoundUp)) 
Tree(x::Node) = x
Tree(x::Leaf) = x
Tree(x::Tuple; L=nothing) = Node(x; L)


function Node(x::Tuple; L=nothing)
    node = Node()
    for i in x
        if isnothing(L)
            r = Tree(i)
        else
            r = Tree(i; L) # This would make issues when i would be a string or a group element
        end
        push!(node, r)
    end
    return node
end


############################ COMPOSITE TYPE PARSING ############################

#using CryptoGroups: HashSpec, PGroup, ECGroup, Group, ElGamal, value, concretize_type, a, b, spec, generator, <|, name, ECPoint, field, gx, gy

using CryptoGroups.Curves: a, b, field, gx, gy
using CryptoGroups: PGroup, ECGroup, Group, value, concretize_type, spec, generator, name, ECPoint
using CryptoPRG.Verificatum: HashSpec


function convert(::Type{Vector{G}}, x::Node; allow_one=false) where G <: Group 
    return G[convert(G, i; allow_one) for i in x.x] 
end


(h::HashSpec)(t::Tree) = h(convert(Vector{UInt8}, t))  ### need to relocate

# Need something smarter in the end
bitlength(::Type{G}) where G <: PGroup = bitlength(modulus(G)) 
bitlength(x::PGroup) = bitlength(modulus(x)) 


bitlength(::Type{ECGroup{P}}) where P <: ECPoint = bitlength(modulus(field(P)))
bitlength(g::G) where G <: ECGroup = bitlength(G)

Tree(x::PGroup; L = bitlength(x)) = Leaf(value(x), div(L + 1, 8, RoundUp))

# Probably I will need to replace 
convert(::Type{G}, x::Leaf; allow_one=false) where G <: PGroup = convert(G, convert(BigInt, x); allow_one)

### Note that only PrimeCurves are supported. 
convert(::Type{G}, x::Node; allow_one=false) where G <: ECGroup = convert(G, convert(Tuple{BigInt, BigInt}, x); allow_one)
convert(::Type{ECGroup{P}}, x::Node; allow_one=false) where P <: ECPoint = convert(ECGroup{P}, convert(Tuple{BigInt, BigInt}, x); allow_one)


function Tree(g::G; L = bitlength(G)) where G <: ECGroup
    
    gxleaf = Leaf(value(gx(g)), div(L + 1, 8, RoundUp))
    gyleaf = Leaf(value(gy(g)), div(L + 1, 8, RoundUp))

    gtree = Tree((gxleaf, gyleaf))

    return gtree
end

function Tree(x::Vector{<:Group})
    L = bitlength(x[1])
    s = Tree[Tree(i, L = L) for i in x]
    return Node(s)
end

function marshal(x::PGroup)

    java_name = "com.verificatum.arithm.ModPGroup"
    p = modulus(x)
    q = order(x)
    g = Tree(x)
    e = UInt32(1)

    msg = (java_name, (p, q, g, e))

    tree = Tree(msg)

    return tree
end


normalize_ecgroup_name(x::String) = replace(x, "_"=>"-")
normalize_ecgroup_name(x::Symbol) = normalize_ecgroup_name(String(x))


function marshal(g::ECGroup)

    java_name = "com.verificatum.arithm.ECqPGroup"

    # generator is not a group
    # @check spec(g) == spec(name(g)) "wrong group name"

    v_name = normalize_ecgroup_name(name(g))

    msg = (java_name, v_name)

    tree = Tree(msg)

    return tree
end


function unmarshal(tree::Tree)
    
    group_type = convert(String, tree.x[1])

    if group_type == "com.verificatum.arithm.ModPGroup"
        _unmarshal_pgroup(tree.x[2])
    elseif group_type == "com.verificatum.arithm.ECqPGroup"
        _unmarshal_ecgroup(tree.x[2])
    else
        error("Unrecognized group type: $group_type")
    end
end


function _unmarshal_pgroup(x::Node) 

    (p, q, g, e) = convert(Tuple{BigInt, BigInt, BigInt, UInt32}, x)
    
    G = concretize_type(PGroup, p, q)
    x = G(g)
    
    return x
end

spec_name(x::String) = Symbol(replace(x, "-"=>"_"))

function _unmarshal_ecgroup(x::Leaf)
    
    group_spec_str = convert(String, x)
    name = spec_name(group_spec_str)

    group_spec = spec(name)
    G = concretize_type(ECGroup, group_spec; name)
    g = G(generator(group_spec))

    return g
end


function convert(::Type{Vector{ElGamalRow{G, 1}}}, tree::Node; allow_one=false) where G <: Group

    a_tree, b_tree = tree.x
    𝐚 = convert(Vector{G}, a_tree; allow_one)
    𝐛 = convert(Vector{G}, b_tree; allow_one)
    𝐞 = [ElGamalRow(ai, bi) for (ai, bi) in zip(𝐚, 𝐛)]

    return 𝐞
end

function convert(::Type{ElGamalRow{G, 1}}, tree::Node; allow_one=false) where G <: Group

    a_tree, b_tree = tree.x

    a = convert(G, a_tree; allow_one)
    b = convert(G, b_tree; allow_one)
    
    return ElGamalRow(a, b)
end

function Tree(row::ElGamalRow{<:Group, 1})

    (; a, b) = row[1]

    return Tree((a, b))
end

function Tree(𝐞::Vector{<:ElGamalRow{<:Group, 1}})

    𝐚 = [i[1].a for i in 𝐞]
    𝐛 = [i[1].b for i in 𝐞]

    tree = Tree((𝐚, 𝐛))
    
    return tree
end


Tree(x::Vector{BigInt}; L = bitlength(maximum(x))) = Node([Leaf(i, L) for i in x])

