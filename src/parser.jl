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

### Reverse


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
#encode(::Type{String}, x::Tree) = bytes2hex(encode(Vector{UInt8}, x))


convert(::Type{T}, x::Leaf) where T <: Integer = interpret(T, x.x)

function convert(::Type{String}, x::Leaf)
    return String(copy(x.x))
end

function convert(::Type{Vector{T}}, x::Node) where T <: Integer 
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
    

# Encoding with fixed size bytes
function Leaf(x::Integer, k::Integer) ### The logic here also seems better could belong to an interpret method.
    leaf = Leaf(x)
    N = findfirst(x -> x != UInt8(0), leaf.x)
    bytes = leaf.x[N:end]
    pad = k - length(bytes)

    newleaf = Leaf(UInt8[zeros(UInt8, pad)...,bytes...])
    return newleaf
end


function Leaf(x::String)
    bytes = Vector{UInt8}(x)
    return Leaf(bytes)
end

Tree(x::Any) = Leaf(x)
Tree(x::Node) = x
Tree(x::Leaf) = x
Tree(x::Tuple) = Node(x)

function Node(x::Tuple)
    node = Node()
    for i in x
        r = Tree(i)
        push!(node, r)
    end
    return node
end


############################ COMPOSITE TYPE PARSING ############################

(h::Hash)(t::Tree) = h(convert(Vector{UInt8}, t))

# Need something smarter in the end
bitlength(x::PrimeGenerator) = bitlength(modulus(x)) 


Leaf(x::PrimeGenerator; L = bitlength(x)) = Leaf(value(x), div(L + 1, 8, RoundUp))

function Tree(x::Vector{<:Generator})
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


function convert(::Type{ElGamal{G}}, tree::Tree) where G <: Generator
    𝐚, 𝐛 = convert(Tuple{Vector{BigInt}, Vector{BigInt}}, tree)
    𝐞 = ElGamal{G}(𝐚, 𝐛)
    return 𝐞
end

function Tree(𝐞::ElGamal{<:Generator})
    𝐚 = a(𝐞)  # 𝐚 = value.(a(𝐞))
    𝐛 = b(𝐞)
    tree = Tree((𝐚, 𝐛))
end
