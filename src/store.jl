
function fill_xml_template(template_path::String, replacements)
    # Read the template content
    template_content = read(template_path, String)

    # Replace placeholders with actual values
    for (placeholder, value) in replacements
        # An alternative would be replacing the XML tags themselves, however, that in general does not work
        # when XML is hierarchical and can have repeated tags.
        template_content = replace(template_content, "{{$placeholder}}" => value)
    end

    return template_content
end

function fill_protinfo_template(spec::ProtocolSpec; name="ShuffleProofs", descr="")

    (; g, nr, nv, ne, prghash, rohash, version, sid) = spec

    pgroup = String(marshal_s_Gq(g).x) # could be improved

    prg_hash = map_hash_name_back(prghash)
    ro_hash = map_hash_name_back(rohash)

    return fill_xml_template(joinpath(@__DIR__, "assets", "protInfo.xml"), [
        "VERSION" => version,
        "SID" => sid,
        "NAME" => name,
        "DESCR" => descr,
        "STATDIST" => nr,
        "PGROUP" => pgroup,
        "VBITLENRO" => nv,
        "EBITLENRO" => ne,
        "PRG" => prg_hash,
        "ROHASH" => ro_hash
    ])
end

function save(spec::ProtocolSpec, path::AbstractString; name="undefined")

    info = fill_protinfo_template(spec; name)
    write(path, info)

    return
end


function load(::Type{ProtocolSpec}, path::AbstractString; auxsid = "default")

    xml = read(path) |> String

    rohash = HashSpec(match(r"<rohash>(.*?)</rohash>", xml)[1] |> map_hash_name)
    prghash = HashSpec(match(r"<prg>(.*?)</prg>", xml)[1] |> map_hash_name)
    s_Gq = match(r"<pgroup>(.*?)</pgroup>", xml)[1]

    nr = parse(Int32, match(r"<statdist>(.*?)</statdist>", xml)[1])
    nv = parse(Int32, match(r"<vbitlenro>(.*?)</vbitlenro>", xml)[1])
    ne = parse(Int32, match(r"<ebitlenro>(.*?)</ebitlenro>", xml)[1])

    g = unmarshal(decode(split(s_Gq, "::")[2]))

    version = match(r"<version>(.*?)</version>", xml)[1] |> String
    sid = match(r"<sid>(.*?)</sid>", xml)[1] |> String


    return ProtocolSpec(; g, nr, nv, ne, prghash, rohash, version, sid, auxsid)
end


function save(proposition::Shuffle, dir::AbstractString) 

    (; g, pk, 𝐞, 𝐞′) = proposition

    pbkey_tree = marshal_publickey(pk, g)
    write(joinpath(dir, "publicKey.bt"), pbkey_tree)

    write(joinpath(dir, "Ciphertexts.bt"), Tree(𝐞))

    write(joinpath(dir, "ShuffledCiphertexts.bt"), Tree(𝐞′))

    return
end


function load(::Type{Shuffle}, basedir::AbstractString)

    publickey_tree = decode(read(joinpath(basedir, "publicKey.bt")))
    pk, g = unmarshal_publickey(publickey_tree; relative=true)

    G = typeof(g)

    L_tree = decode(read(joinpath(basedir, "Ciphertexts.bt")))
    L′_tree = decode(read(joinpath(basedir, "ShuffledCiphertexts.bt")))

    𝔀 = convert(ElGamal{G}, L_tree; allow_one=true)
    𝔀′ = convert(ElGamal{G}, L′_tree; allow_one=true)

    return Shuffle(g, pk, 𝔀, 𝔀′)
end


function save(proof::VShuffleProof, dir::AbstractString) 

    (; μ, τ, σ) = proof

    write(joinpath(dir, "PermutationCommitment.bt"), Tree(μ))
    write(joinpath(dir, "PoSCommitment.bt"), Tree(τ))

    L = bitlength(μ[1])

    write(joinpath(dir, "PoSReply.bt"), Tree(σ; L))
    
    return 
end 

save(proof::PoSProof, dir::AbstractString) = save(VShuffleProof(proof), dir)

function load(::Type{PoSProof}, basedir::AbstractString, g::Group)

    G = typeof(g)

    μ_tree = decode(read(joinpath(basedir, "PermutationCommitment.bt")))
    μ = convert(Vector{G}, μ_tree)

    τ_tree = decode(read(joinpath(basedir, "PoSCommitment.bt")))
    τ = convert(Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}, τ_tree)

    σ_tree = decode(read(joinpath(basedir, "PoSReply.bt")))
    σ = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, BigInt}, σ_tree)

    return VShuffleProof(μ, τ, σ) |> PoSProof
end 


function save(proposition::Decryption, dir::AbstractString) 
    
    (; g, pk, 𝔀, 𝔀′) = proposition

    pbkey_tree = marshal_publickey(pk, g)
    write(joinpath(dir, "publicKey.bt"), pbkey_tree)

    write(joinpath(dir, "Ciphertexts.bt"), Tree(𝔀))
    write(joinpath(dir, "Decryption.bt"), Tree(𝔀′))

    return
end

function load(::Type{Decryption}, basedir::AbstractString)
    
    publickey_tree = decode(read(joinpath(basedir, "publicKey.bt")))
    pk, g = unmarshal_publickey(publickey_tree; relative=true)

    G = typeof(g)

    𝔀_tree = decode(read(joinpath(basedir, "Ciphertexts.bt")))
    𝔀′_tree = decode(read(joinpath(basedir, "Decryption.bt")))
    
    𝔀 = convert(Vector{G}, 𝔀_tree)
    𝔀′ = convert(Vector{G}, 𝔀′_tree)

    return Decryption(g, pk, 𝔀, 𝔀′)
end


function save(proof::DecryptionProof, dir::AbstractString) 

    (; τ, r) = proof

    L = bitlength(τ[1])

    write(joinpath(dir, "DecryptionCommitment.bt"), Tree(τ))
    write(joinpath(dir, "DecryptionReply.bt"), Tree(r; L))

    return
end


function load(::Type{DecryptionProof}, dir::AbstractString, g::Group)

    G = typeof(g)

    τ_tree = decode(read(joinpath(dir, "DecryptionCommitment.bt")))
    τ = convert(Vector{G}, τ_tree)

    r_tree = decode(read(joinpath(dir, "DecryptionReply.bt")))
    r = convert(BigInt, r_tree)

    return DecryptionProof(τ, r)
end


function save(braid::Braid, dir::AbstractString) 

    mkdir(joinpath(dir, "shuffle"))
    save(braid.shuffle, joinpath(dir, "shuffle"))
    
    mkdir(joinpath(dir, "decryption"))
    save(braid.decryption, joinpath(dir, "decryption"))

    write(joinpath(dir, "BraidedMembers.bt"), Tree(braid.members))

    return
end

function load(::Type{Braid}, dir::AbstractString)

    shuffle = load(Shuffle, joinpath(dir, "shuffle"))
    decryption = load(Decryption, joinpath(dir, "decryption"))

    G = typeof(shuffle.g)

    members_tree = decode(read(joinpath(dir, "BraidedMembers.bt")))
    members = convert(Vector{G}, members_tree)

    return Braid(shuffle, decryption, members)
end


function save(braid::BraidProof, dir::AbstractString) 

    mkpath(joinpath(dir, "shuffle", "nizkp"))
    save(braid.shuffle, joinpath(dir, "shuffle", "nizkp"))

    mkpath(joinpath(dir, "decryption", "nizkp"))
    save(braid.decryption, joinpath(dir, "decryption", "nizkp"))

    return
end # 

function load(::Type{BraidProof}, dir::AbstractString, g::Group)
    
    shuffle = load(PoSProof, joinpath(dir, "shuffle", "nizkp"), g)
    decryption = load(DecryptionProof, joinpath(dir, "decryption", "nizkp"), g)

    return BraidProof(shuffle, decryption)
end


save(simulator::Simulator, dir::AbstractString) = _save(typeof(simulator.proposition), simulator, dir)


function _save(::Type{<:Shuffle}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)

    mkdir(joinpath(dir, "nizkp"))
    save(simulator.proof, joinpath(dir, "nizkp"))

    save(simulator.verifier, joinpath(dir, "protInfo.xml"); name="Shuffle") 

    return
end


function _save(::Type{<:Decryption}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)

    mkdir(joinpath(dir, "nizkp"))
    save(simulator.proof, joinpath(dir, "nizkp"))

    save(simulator.verifier, joinpath(dir, "protInfo.xml"); name="Decryption") 

    return
end


function _save(::Type{<:Braid}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)
    save(simulator.proof, dir)
    save(simulator.verifier, joinpath(dir, "protInfo.xml"); name="Braid")     
    
    return
end

function load_shuffle_simulator(dir::AbstractString)

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Shuffle, dir)
    proof = load(PoSProof, joinpath(dir, "nizkp"), proposition.g)

    return Simulator(proposition, proof, verifier)
end

function load_decryption_simulator(dir::AbstractString)

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Decryption, dir)
    proof = load(DecryptionProof, joinpath(dir, "nizkp"), proposition.g)
    
    return Simulator(proposition, proof, verifier)
end

function load_braid_simulator(dir::AbstractString) 

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Braid, dir)
    proof = load(BraidProof, dir, proposition.shuffle.g)

    return Simulator(proposition, proof, verifier)
end


function load(dir::AbstractString; name=nothing)

    if isnothing(name)
        xmlpath = joinpath(dir, "protInfo.xml")

        if !isfile(xmlpath)
            error("protInfo.xml not found in $dir")
        end

        xml = read(xmlpath) |> String
        name = match(r"<name>(.*?)</name>", xml)[1] |> String
    end

    if name == "Shuffle"
        return load_shuffle_simulator(dir)
    elseif name == "Decryption"
        return load_decryption_simulator(dir)
    elseif name == "Braid"
        return load_braid_simulator(dir)
    else
        error("Unable to deduce simulator type from name $name.")
    end

end


### Some verificatum proof of shuffle loading methods

function load_verificatum_proposition(basedir::AbstractString, auxsid::AbstractString)

    PUBLIC_KEY = "$basedir/publicKey"

    tree = decode(read(PUBLIC_KEY))
    pk, g = unmarshal_publickey(tree)

    NIZKP = basedir * "/dir/nizkp/$auxsid/"

    CIPHERTEXTS = "$NIZKP/Ciphertexts.bt"
    SHUFFLED_CIPHERTEXTS = "$NIZKP/ShuffledCiphertexts.bt"

    G = typeof(g)

    L_tree = decode(read(CIPHERTEXTS))
    L′_tree = decode(read(SHUFFLED_CIPHERTEXTS))

    𝔀 = convert(ElGamal{G}, L_tree) ## Is there anything I can do so that I would get a concrete type here?
    𝔀′ = convert(ElGamal{G}, L′_tree)

    return Shuffle(g, pk, 𝔀, 𝔀′)
end

function load_verificatum_proof(proofs::AbstractString, g::Group)

    PERMUTATION_COMMITMENT = "$proofs/PermutationCommitment01.bt"
    PoS_COMMITMENT = "$proofs/PoSCommitment01.bt"
    PoS_REPLY = "$proofs/PoSReply01.bt"

    G = typeof(g)

    μ_tree = decode(read(PERMUTATION_COMMITMENT))
    μ = convert(Vector{G}, μ_tree)

    τ_tree = decode(read(PoS_COMMITMENT))
    τ = convert(Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}, τ_tree)

    σ_tree = decode(read(PoS_REPLY))
    σ = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, BigInt}, σ_tree)

    return VShuffleProof(μ, τ, σ)    
end


function load_verificatum_simulator(basedir::AbstractString; auxsid = "default")

    spec = load(ProtocolSpec, joinpath(basedir, "protInfo.xml"); auxsid)

    proposition = load_verificatum_proposition(basedir, auxsid)
    
    NIZKP = basedir * "/dir/nizkp/$auxsid/"
    proof = load_verificatum_proof("$NIZKP/proofs/", proposition.g)
    
    simulator = Simulator(proposition, proof, spec)

    return simulator
end

