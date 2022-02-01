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


# decode(x::Vector{UInt8})
# parse(::Type{Tree}, x::Vector{UInt8})

decode(x::Vector{UInt8}) = parseb(x)[1]
decode(x::AbstractString) = decode(hex2bytes(replace(x, " "=>""))) # I could have optional arguments here as well
#convert(::Type{Tree}, x::Vector{UInt8}) = parseb(x)[1]
#convert(::Type{Tree}, x::AbstractString) = convert(Tree, hex2bytes(replace(x, " "=>"")))


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

encode(::Type{Vector{UInt8}}, x::Tree) = tobin(x)
encode(::Type{String}, x::Tree) = bytes2hex(encode(Vector{UInt8}, x))
#convert(::Type{Vector{UInt8}}, x::T) where T <: Tree = tobin(x) ### Ambigious
# convert(::Type{String}, x::T) where T <: Tree

# function convert(::Type{BigInt}, x::Leaf)
#     return tobig(reverse(x.x))
# end

function convert(::Type{T}, x::Leaf) where T <: Integer
    return frombytes(T, reverse(x.x))
end


function convert(::Type{String}, x::Leaf)
    return String(copy(x.x))
end

function convert(::Type{Vector{T}}, x::Node) where T <: Integer 
    #return BigInt[tobig(reverse(i.x)) for i in x.x] # Why not convert?
    return T[convert(T, i) for i in x.x] # Why not convert?
end

function convert(cfact::Type{T}, x::Node) where T <: Tuple 
     return Tuple((convert(ci, xi) for (xi, ci) in zip(x.x, cfact.types)))
end


### The last part then remains to convert tuple to tree! This is of practical importance to specify 

#function convert(::Type{Tree}, x::BigInt)
function Leaf(x::BigInt)
    bytes = reverse(int2bytes(x)) ### Do I need to reverse order here?
    
    #return Leaf(bytes)
    # Need to decode this from Java documentaion
    # May experiment with it on https://compiler.javatpoint.com/opr/test.jsp?filename=BigIntegerBitLengthExample
    # the most significant byte is in the zeroth element. The array will contain the minimum number of bytes required to represent this BigInteger, including at least one sign bit, which is (ceil((this.bitLength() + 1)/8)). 

    # https://en.wikipedia.org/wiki/Signed_number_representations#Signed_magnitude_representation

    if bytes[1] > 127
        return Leaf(UInt8[0, bytes...]) # Adding a redundant byte to ensure that the number is positive. 
    else
        return Leaf(bytes)
    end
end


function Leaf(x::Integer; trim = true)
    bytes = reverse(reinterpret(UInt8, [x]))
    
    if trim
        N = findfirst(x -> x != 0, bytes)
        leaf = Leaf(bytes[N:end])
    else
        leaf = Leaf(bytes)
    end

    return leaf
end

function Leaf(x::Integer, k::Integer)
    leaf = Leaf(x)
    pad = k - length(leaf.x)
    newleaf = Leaf(UInt8[zeros(UInt8, pad)...,leaf.x...])
    return newleaf
end



function Leaf(x::String)
    bytes = Vector{UInt8}(x)
    return Leaf(bytes)
end

Tree(x::Any) = Leaf(x)
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

