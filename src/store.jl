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
    pk, g = unmarshal_publickey(publickey_tree)

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



#save(simulator::Simulator, dir::AbstractString) = save(simulator.proposition, simulator.proof, simulator.verifier, dir::AbstractString)


function _save(::Type{<:Union{Shuffle, Decryption}}, simulator::Simulator, dir::AbstractString)

    save(simulator.proposition, dir)

    mkdir(joinpath(dir, "nizkp"))
    save(simulator.proof, joinpath(dir, "nizkp"))

    save(simulator.verifier, joinpath(dir, "protInfo.xml")) 

    return
end


function load_shuffle_simulator(dir::AbstractString)

    verifier = ProtocolSpec(joinpath(dir, "protInfo.xml"))
    proposition = load_shuffle_proposition(dir)
    proof = load_shuffle_proof(joinpath(dir, "nizkp"), proposition.g)

    return Simulator(proposition, proof, verifier)
end





function _save(::Type{Braid}, simulator::Simulator, dir::AbstractString)
    
    # TODO

end

save(simulator::Simulator, dir::AbstractString) = _save(typeof(simulator.proposition), simulator, dir)







function load_decrytion_proposition end

function load_decrytion_proof end

function load_braid_proposition end

function load_braid_proof end




function save(decryption::Decryption, dir::AbstractString) end
function save(decryption::DecryptionProof, dir::AbstractString) end

function save(braid::Braid, dir::AbstractString) end
function save(braid::BraidProof, dir::AbstractString) end # 



function save(spec::ProtocolSpec, path::AbstractString)

    info = fill_protinfo_template(spec)
    write(path, info)

    return
end




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

    # com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536

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

