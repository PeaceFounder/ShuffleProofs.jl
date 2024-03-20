
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

# proof folder
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

function load_decrytion_proposition end

function load_decrytion_proof end

function load_braid_proposition end

function load_braid_proof end



function save(proposition::Shuffle) end
function save(proof::VShuffleProof) end 
function save(proof::PoSProof) end # converts to VShuffleProof

function save(decryption::Decryption) end
function save(decryption::DecryptionProof) end

function save(braid::Braid) end
function save(braid::BraidProof) end # 


