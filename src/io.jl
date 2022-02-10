Base.write(io::IO, tree::Tree) = write(io, encode(tree))
Base.write(f::AbstractString, tree::Tree) = write(f, encode(tree))

Base.string(tree::Tree) = bytes2hex(encode(tree))



function unmarshal_publickey(tree::Tree)
    
    g = unmarshal(BigInt, tree.x[1])
    # It is possilbe to have a some logic here
    c1, c2 = convert(Tuple{BigInt, BigInt}, tree.x[2])

    @assert value(g) == c1

    𝓖 = group(g)
    y = convert(Generator{𝓖}, c2)

    return y, g
end


function marshal_publickey(g::G, y::G) where G <: PrimeGenerator
    
    group_spec = marshal(g)
    
    p = modulus(g)
    
    ### It may be actaully be forcing to use the same bytelength as prime order
    gleaf = Leaf(g, L = bitlength(p))
    yleaf = Leaf(y, L = bitlength(p))

    public_key = Tree((gleaf, yleaf))
    tree = Tree((group_spec, public_key))

    return tree
end


function marshal_privatekey(g::G, s::BigInt) where G <: PrimeGenerator
    group_spec = marshal(g)

    q = order(g)

    @assert s < q "Secret key must be with in the order of the group"

    sleaf = Leaf(s, bytelength(q))

    tree = Tree((group_spec, sleaf))

    return tree
end


function unmarshal_privatekey(tree::Tree)

    g = unmarshal(BigInt, tree.x[1])
    s = convert(BigInt, tree.x[2])    

    return (s, g) ### The group can often be omited when not needed.
end

