
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

function save(spec::ProtocolSpec, path::AbstractString)

    info = fill_protinfo_template(spec)
    write(path, info)

    return
end


function save(proposition::Shuffle, dir::AbstractString) 

    (; g, pk, 𝐞, 𝐞′) = proposition

    pbkey_tree = marshal_publickey(pk, g)
    write(joinpath(dir, "publicKey.bt"), pbkey_tree)

    write(joinpath(dir, "Ciphertexts.bt"), Tree(𝐞))

    write(joinpath(dir, "ShuffledCiphertexts.bt"), Tree(𝐞′))

    return
end


function load_shuffle_proposition(basedir::AbstractString)

    publickey_tree = decode(read(joinpath(basedir, "publicKey.bt")))
    pk, g = unmarshal_publickey(publickey_tree; relative=true)

    G = typeof(g)

    L_tree = decode(read(joinpath(basedir, "Ciphertexts.bt")))
    L′_tree = decode(read(joinpath(basedir, "ShuffledCiphertexts.bt")))

    𝔀 = convert(ElGamal{G}, L_tree)
    𝔀′ = convert(ElGamal{G}, L′_tree)

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

function load_shuffle_proof(basedir::AbstractString, g::Group)

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

function load_decrytion_proposition(basedir::AbstractString)
    
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


function load_decrytion_proof(dir::AbstractString, g::Group)

    G = typeof(g)

    τ_tree = decode(read(joinpath(basedir, "DecryptionCommitment.bt")))
    τ = convert(Vector{G}, τ_tree)

    r_tree = decode(read(joinpath(basedir, "DecryptionReply.bt")))
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

function load_braid_proposition(dir::AbstractString)

    shuffle = load_shuffle_proposition(joinpath(dir, "shuffle"))
    decryption = load_decryption_proposition(joinpath(dir, "decryption"))

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

function load_braid_proof(dir::AbstractString, g::Group)
    
    shuffle = load_shuffle_proof(joinpath(dir, "shuffle", "nizkp"), g)
    decryption = load_decryption_proof(joinpath(dir, "decryption", "nizkp"), g)

    return BraidProof(shuffle, decryption)
end


save(simulator::Simulator, dir::AbstractString) = _save(typeof(simulator.proposition), simulator, dir)


function _save(::Type{<:Union{Shuffle, Decryption}}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)

    mkdir(joinpath(dir, "nizkp"))
    save(simulator.proof, joinpath(dir, "nizkp"))

    save(simulator.verifier, joinpath(dir, "protInfo.xml")) 

    return
end

function _save(::Type{<:Braid}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)
    save(simulator.proof, dir)
    save(simulator.verifier, joinpath(dir, "protInfo.xml"))     
    
    return
end

function load_shuffle_simulator(dir::AbstractString)

    verifier = ProtocolSpec(joinpath(dir, "protInfo.xml"))
    proposition = load_shuffle_proposition(dir)
    proof = load_shuffle_proof(joinpath(dir, "nizkp"), proposition.g)

    return Simulator(proposition, proof, verifier)
end

function load_decryption_simulator(dir::AbstractString)

    verifier = ProtocolSpec(joinpath(dir, "protInfo.xml"))
    proposition = load_decryption_proposition(dir)
    proof = load_decryption_proof(joinpath(dir, "nizkp"), proposition.g)
    
    return Simulator(proposition, proof, verifier)
end

function load_braid_simulator(dir::AbstractString) 

    verifier = ProtocolSpec(joinpath(dir, "protInfo.xml"))
    proposition = load_braid_proposition(dir)
    proof = load_braid_proof(dir, proposition.g)

    return Simulator(proposition, proof, verifier)
end
