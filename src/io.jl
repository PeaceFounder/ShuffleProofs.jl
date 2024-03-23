using CryptoGroups: Group, PGroup

Base.write(io::IO, tree::Tree) = write(io, encode(tree))
Base.write(f::AbstractString, tree::Tree) = write(f, encode(tree))

Base.string(tree::Tree) = bytes2hex(encode(tree))


function unmarshal_full_public_key(g::Group, tree::Tree)
    
    G = typeof(g)

    g′, y = convert(Tuple{G, G}, tree)    

    @assert g′ == g

    return y
end

marshal_full_public_key(g::G, y::G) where G <: Group = Tree((g, y))


function unmarshal_publickey(tree::Tree; relative::Bool = false)
    
    g = unmarshal(tree.x[1])
    G = typeof(g)

    g′, y = convert(Tuple{G, G}, tree.x[2]) 

    if !relative
        @assert g′ == g "Generator does not match specification of the group. Perhaps intentioanl, if so pass `relative=true` as keyword argument."
    end

    return y, g′
end


function marshal_publickey(y::G, g::G) where G <: Group
    
    group_spec = marshal(g)
    
    L = bitlength(G) # 
    
    g_tree = Tree(g; L)
    y_tree = Tree(y; L)

    public_key = Tree((g_tree, y_tree))
    tree = Tree((group_spec, public_key))

    return tree
end


function marshal_privatekey(g::Group, s::BigInt) 
    group_spec = marshal(g)

    q = order(g)

    @assert s < q "Secret key must be with in the order of the group"

    sleaf = Leaf(s, bytelength(q))

    tree = Tree((group_spec, sleaf))

    return tree
end


function unmarshal_privatekey(tree::Tree)

    g = unmarshal(tree.x[1])
    s = convert(BigInt, tree.x[2])    

    return (s, g) ### The group can often be omited when not needed.
end


function map_hash_name(x::AbstractString)
    if x == "SHA-256"
        return "sha256"
    elseif x == "SHA-384"
        return "sha384"
    elseif x == "SHA-512"
        return "sha512"
    else
        error("No corepsonding mapping for $x implemented")
    end
end


function map_hash_name_back(x::AbstractString)
    if x == "sha256"
        return "SHA-256"
    elseif x == "sha384"
        return "SHA-384"
    elseif x == "sha512"
        return "SHA-512"
    else
        error("No corepsonding mapping for $x implemented")
    end
end 


map_hash_name_back(x::HashSpec) = map_hash_name_back(x.spec)


function ro_prefix(protinfo::AbstractDict; auxsid="default")

    version = protinfo["version"]
    sid = protinfo["sid"]


    s_H = protinfo["rohash"]  
    s_PRG = protinfo["prg"]
    s_Gq = protinfo["pgroup"]

    nr = parse(Int32, protinfo["statdist"])
    nv = parse(Int32, protinfo["vbitlenro"])
    ne = parse(Int32, protinfo["ebitlenro"])


    data = (version, sid * "." * auxsid, nr, nv, ne, s_PRG, s_Gq, s_H)

    tree = Tree(data)
    binary = encode(tree)

    rohash = HashSpec(map_hash_name(protinfo["rohash"]))

    ρ = rohash(binary) ### Which hash function shall be used here?

    return ρ
end


