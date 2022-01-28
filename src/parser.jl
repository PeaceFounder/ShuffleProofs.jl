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


toint(x) = reinterpret(UInt32, x[4:-1:1])[1]


function parseb(x)
    
    if x[1] == LEAF

        L = toint(x[2:5])

        bytes = x[6:5+L]
        leaf = Leaf(bytes)

        if length(x) == L + 5
            rest = []
        else
            rest = x[L+6:end]
        end

        return leaf, rest

    elseif x[2] == NODE

        N = toint(x[2:5])
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


convert(::Type{Tree}, x::Vector{UInt8}) = parseb(x)[1]
convert(::Type{Tree}, x::AbstractString) = convert(Tree, hex2bytes(replace(x, " "=>"")))


### Reverse


function tobin(leaf::Leaf)

    N = UInt32[length(leaf.x)]

    Nbin = reinterpret(UInt8, N)[end:-1:1]
    bin = UInt8[LEAF, Nbin..., leaf.x...]

    return bin
end

function tobin(node::Node)
    
    N = UInt32[length(node.x)]
    Nbin = reinterpret(UInt8, N)[end:-1:1]

    data = UInt8[]

    for n in node.x
        b = tobin(n)
        append!(data, b)
    end

    bin = UInt8[NODE, Nbin..., data...]

    return bin
end

convert(::Type{Vector{UInt8}}, x::T) where T <: Tree = tobin(x)

tobig(x) = parse(BigInt, bytes2hex(x), base=16)


function convert(::Type{BigInt}, x::Leaf)
    return tobig(x.x)
end

function convert(::Type{String}, x::Leaf)
    return String(copy(x.x))
end

function convert(::Type{Vector{BigInt}}, x::Node)
    return BigInt[tobig(i.x) for i in x.x]
end

function convert(cfact::Type{T}, x::Node) where T <: Tuple 
     return Tuple((convert(ci, xi) for (xi, ci) in zip(x.x, cfact.types)))
end


### The last part then remains to convert tuple to tree! This is of practical importance to specify 

function int2bytes(x::Integer)
    hex = string(x, base=16)
    if mod(length(hex), 2) != 0
        hex = string("0", hex)
    end
    return hex2bytes(hex)
end

#function convert(::Type{Tree}, x::BigInt)
function Leaf(x::BigInt)
    bytes = reverse(int2bytes(x)) ### Do I need to reverse order here?
    return Leaf(bytes)
end


function Leaf(x::Integer)
    bytes = reverse(reinterpret(UInt8, [x]))
    N = findfirst(x -> x != 0, bytes)
    return Leaf(bytes[N:end])
end


function Leaf(x::String)
    bytes = Vector{UInt8}(x)
    return Leaf(bytes)
end

Tree(x::Union{String, Integer}) = Leaf(x)
Tree(x::Tuple) = Node(x)

function Node(x::Tuple)
    node = Node()
    for i in x
        r = Tree(i)
        push!(node, r)
    end
    return node
end
