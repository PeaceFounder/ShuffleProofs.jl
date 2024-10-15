using SigmaProofs.Serializer: Path, LocalPath, DEFAULT_VERIFIER
using SigmaProofs.Parser: decode, unmarshal_publickey, marshal_publickey
import SigmaProofs.Serializer: load, save, treespec
using CryptoGroups.Fields: bitlength # 

using CryptoGroups.Utils: @check

treespec(::Type{<:Shuffle}) = (
    "publicKey.bt",
    "Ciphertexts.bt",
    "ShuffledCiphertexts.bt"
)

treespec(::Type{<:VShuffleProof}) = (
    "PermutationCommitment.bt",
    "PoSCommitment.bt",
    "PoSReply.bt",
)

treespec(::Type{<:PoSProof}) = treespec(VShuffleProof)

treespec(::Type{<:Braid}) = (
    joinpath.("shuffle", treespec(Shuffle))...,
    joinpath.("decryption", treespec(DecryptionInv))...
)

treespec(::Type{<:BraidProof}) = (
    joinpath.("shuffle/nizkp", treespec(VShuffleProof))...,
    joinpath.("decryption/nizkp", treespec(ChaumPedersenProof; prefix="DecryptionInv"))...
)

treespec(::Type{Simulator{B}}) where B <: Braid = (treespec(DEFAULT_VERIFIER), treespec(Braid)..., treespec(BraidProof)...)


function save(obj::Simulator{<:Braid}, path::Path) 

    save(obj.proposition, path)
    save(obj.proof, path)

    verifier_path = joinpath(path, treespec(obj.verifier))
    save(obj.verifier, verifier_path; name = "Braid")

    return
end

function load(::Type{Simulator{Braid}}, path::Path; verifier_type = DEFAULT_VERIFIER) 

    proposition = load(Braid, path)
    proof = load(proof_type(proposition), path)
    verifier = load(verifier_type, joinpath(path, treespec(verifier_type)))

    return Simulator(proposition, proof, verifier)
end

function save(proposition::Shuffle, dir::Path) 

    (; g, pk, 𝐞, 𝐞′) = proposition

    pbkey_tree = marshal_publickey(pk, g)
    write(joinpath(dir, "publicKey.bt"), pbkey_tree)

    write(joinpath(dir, "Ciphertexts.bt"), Tree(𝐞))

    write(joinpath(dir, "ShuffledCiphertexts.bt"), Tree(𝐞′))

    return
end

function load(::Type{Shuffle}, basedir::Path)

    publickey_tree = decode(read(joinpath(basedir, "publicKey.bt")))
    pk, g = unmarshal_publickey(publickey_tree; relative=true)

    G = typeof(g)

    L_tree = decode(read(joinpath(basedir, "Ciphertexts.bt")))
    L′_tree = decode(read(joinpath(basedir, "ShuffledCiphertexts.bt")))

    𝔀 = convert(Vector{ElGamalRow{G, 1}}, L_tree; allow_one=true)
    𝔀′ = convert(Vector{ElGamalRow{G, 1}}, L′_tree; allow_one=true)

    return Shuffle(g, pk, 𝔀, 𝔀′)
end

function save(proof::VShuffleProof, dir::Path) 

    (; μ, τ, σ) = proof

    write(joinpath(dir, "PermutationCommitment.bt"), Tree(μ))
    write(joinpath(dir, "PoSCommitment.bt"), Tree(τ))

    L = bitlength(μ[1])

    write(joinpath(dir, "PoSReply.bt"), Tree(σ; L))
    
    return 
end 

save(proof::PoSProof, dir::Path) = save(VShuffleProof(proof), dir)

function load(::Type{VShuffleProof{G}}, basedir::Path) where G <: Group

    μ_tree = decode(read(joinpath(basedir, "PermutationCommitment.bt")))
    μ = convert(Vector{G}, μ_tree)

    τ_tree = decode(read(joinpath(basedir, "PoSCommitment.bt")))
    N = width_elgamal_row(G, τ_tree[6])
    τ = convert(Tuple{Vector{G}, G, Vector{G}, G, G, ElGamalRow{G, N}}, τ_tree)

    σ_tree = decode(read(joinpath(basedir, "PoSReply.bt")))
    σ = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, NTuple{N, BigInt}}, σ_tree)

    return VShuffleProof(μ, τ, σ)
end 

load(::Type{<:PoSProof{G}}, basedir::Path) where G <: Group = load(VShuffleProof{G}, basedir) |> PoSProof

function save(braid::Braid, dir::Path) 

    mkdir(joinpath(dir, "shuffle"))
    save(braid.shuffle, joinpath(dir, "shuffle"))
    
    mkdir(joinpath(dir, "decryption"))
    save(braid.decryption, joinpath(dir, "decryption"))

    return
end

function load(::Type{Braid}, dir::Path)

    shuffle = load(Shuffle, joinpath(dir, "shuffle"))
    decryption = load(DecryptionInv, joinpath(dir, "decryption"))

    G = typeof(shuffle.g)

    return Braid(shuffle, decryption) #, members)
end


function save(braid::BraidProof, dir::Path) 

    mkpath(joinpath(dir, "shuffle", "nizkp"))
    save(braid.shuffle, joinpath(dir, "shuffle", "nizkp"))

    mkpath(joinpath(dir, "decryption", "nizkp"))

    save(braid.decryption, joinpath(dir, "decryption", "nizkp"); prefix="DecryptionInv")

end

function load(::Type{BraidProof{G}}, dir::Path) where G <: Group
    
    shuffle = load(PoSProof{G}, joinpath(dir, "shuffle", "nizkp"))
    decryption = load(ChaumPedersenProof{G}, joinpath(dir, "decryption", "nizkp"); prefix="DecryptionInv")

    return BraidProof(shuffle, decryption)
end

function _save(::Type{<:Shuffle}, simulator::Simulator, dir::Path)

    save(simulator.verifier, joinpath(dir, "protInfo.xml"); name="Shuffle") 
    save(simulator.proposition, dir)
    mkdir(joinpath(dir, "nizkp"))
    save(simulator.proof, joinpath(dir, "nizkp"))

    return
end

function _save(::Type{<:Braid}, simulator::Simulator, dir::Path)

    save(simulator.verifier, joinpath(dir, "protInfo.xml"); name="Braid")     
    save(simulator.proposition, dir)
    save(simulator.proof, dir)
    
    return
end

function load_shuffle_simulator(dir::Path)

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Shuffle, dir)
    G = typeof(proposition.g)
    proof = load(PoSProof{G}, joinpath(dir, "nizkp"))

    return Simulator(proposition, proof, verifier)
end

function load_decryption_simulator(dir::Path)

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Decryption, dir)
    proof = load(DecryptionProof, joinpath(dir, "nizkp"), proposition.g)
    
    return Simulator(proposition, proof, verifier)
end

function load_braid_simulator(dir::Path) 

    verifier = load(ProtocolSpec, joinpath(dir, "protInfo.xml"))
    proposition = load(Braid, dir)
    proof = load(BraidProof, dir, proposition.shuffle.g)

    return Simulator(proposition, proof, verifier)
end

width_elgamal_vec(::Type{<:PGroup}, tree::Tree) = depth(tree) == 2 ? 1 : length(tree[1])
width_elgamal_vec(::Type{<:ECGroup}, tree::Tree) = depth(tree) == 3 ? 1 : length(tree[1])

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

    N = width_elgamal_vec(G, L_tree)

    𝔀 = convert(Vector{ElGamalRow{G, N}}, L_tree) ## Is there anything I can do so that I would get a concrete type here?
    𝔀′ = convert(Vector{ElGamalRow{G, N}}, L′_tree)

    return Shuffle(g, pk, 𝔀, 𝔀′)
end

width_elgamal_row(::Type{<:PGroup}, tree::Tree) = depth(tree) == 1 ? 1 : length(tree[1])
width_elgamal_row(::Type{<:ECGroup}, tree::Tree) = depth(tree) == 2 ? 1 : length(tree[1])

function load_verificatum_proof(proofs::AbstractString, g::Group)

    PERMUTATION_COMMITMENT = "$proofs/PermutationCommitment01.bt"
    PoS_COMMITMENT = "$proofs/PoSCommitment01.bt"
    PoS_REPLY = "$proofs/PoSReply01.bt"

    G = typeof(g)

    μ_tree = decode(read(PERMUTATION_COMMITMENT))
    μ = convert(Vector{G}, μ_tree)

    τ_tree = decode(read(PoS_COMMITMENT))
    N = width_elgamal_row(G, τ_tree[6])
    τ = convert(Tuple{Vector{G}, G, Vector{G}, G, G, ElGamalRow{G, N}}, τ_tree)

    σ_tree = decode(read(PoS_REPLY))
    σ = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, NTuple{N, BigInt}}, σ_tree)

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

