using XMLDict: parse_xml

using Base: @kwdef

@kwdef struct ProtocolSpec{𝓰<:Generator} <: Verifier
    g::𝓰
    pk::𝓰 
    nr::Int32
    nv::Int32
    ne::Int32
    prghash::Hash
    rohash::Hash
    version::String
    sid::String
    auxsid::String = "default"
end

function ProtocolSpec(protinfo::AbstractDict, pk_tree::Tree; auxsid = "default")

    s_H = protinfo["rohash"]  
    s_PRG = protinfo["prg"]
    s_Gq = protinfo["pgroup"]


    prghash = Hash(map_hash_name(protinfo["prg"]))
    rohash = Hash(map_hash_name(protinfo["rohash"]))
    

    nr = parse(Int32, protinfo["statdist"])
    nv = parse(Int32, protinfo["vbitlenro"])
    ne = parse(Int32, protinfo["ebitlenro"])
    
    g = unmarshal(BigInt, decode(split(s_Gq, "::")[2]))

    𝓖 = group(g)
    𝓰 = Generator[𝓖]

    pk = unmarshal_full_public_key(g, pk_tree)

    version = String(protinfo["version"])
    sid = String(protinfo["sid"])

    return ProtocolSpec(; g, pk, nr, nv, ne, prghash, rohash, version, sid, auxsid)
end


# The public key is from the main direcotry as it can mach best the meaning
function ProtocolSpec(PROT_INFO::AbstractString, PUBLIC_KEY::AbstractString; auxsid = "default")

    xml = String(read(PROT_INFO))
    protinfo = parse_xml(xml)

    # There are two publickey files with different formating, thus both can be accepted
    tree = decode(read(PUBLIC_KEY))
    if tree.x[1] isa Leaf
        pk_tree = tree
    else
        pk_tree = tree.x[2]
    end

    return ProtocolSpec(protinfo, pk_tree; auxsid)
end


function ProtocolSpec(basedir::AbstractString; auxsid = "default")
    
    PROT_INFO = "$basedir/protInfo.xml"
    PUBLIC_KEY = "$basedir/publicKey"

    return ProtocolSpec(PROT_INFO, PUBLIC_KEY; auxsid)
end



function marshal_s_Gq(g::PrimeGenerator)

    M = bitlength(order(g))

    tree = marshal(g)
    str = "ModPGroup(safe-prime modulus=2*order+1. order bit-length = $M)::" * string(tree)
    
    return Leaf(str)
end


function ro_prefix(spec::ProtocolSpec)

    (; version, sid, auxsid, rohash, prghash, g, nr, nv, ne) = spec

    s_PRG = map_hash_name_back(prghash)
    s_H = map_hash_name_back(rohash)
    
    s_Gq = marshal_s_Gq(g)

    data = (version, sid * "." * auxsid, nr, nv, ne, s_PRG, s_Gq, s_H)

    tree = Tree(data)
    binary = encode(tree)

    ρ = rohash(binary)

    return ρ
end


struct VShuffleProof{𝓰<:Generator} <: Proof
    μ::Vector{𝓰}
    τ::Tuple{Vector{𝓰}, 𝓰, Vector{𝓰}, 𝓰, 𝓰, Tuple{𝓰, 𝓰}}
    σ::Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, BigInt}
end

==(x::VShuffleProof{𝓰}, y::VShuffleProof{𝓰}) where 𝓰 <: Generator = x.μ == y.μ && x.τ == y.τ && x.σ == y.σ


function VShuffleProof(proof::PoSProof)

    (; 𝐜, 𝐜̂, t, s) = proof

    # Now we can look into translation

    𝓰 = typeof(𝐜[1])

    𝐮 = 𝐜
    μ = 𝐮

    (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) = t # 𝐭̂ = 𝐁′, t₃ = A′, t₄ = F
    𝐁 = 𝐜̂
    𝐁′= Vector{𝓰}(𝐭̂)
    D′ = t₂
    A′ = t₃
    C′ = t₁
    F′ = (t₄₂, t₄₁)

    τ = (𝐁, A′, 𝐁′, C′, D′, F′)

    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s # 𝐬̂ = 𝐤_B, 𝐬′ = 𝐤_E, s₃ = k_A
    𝐤_B = 𝐬̂
    𝐤_E = 𝐬′
    k_D = s₂
    k_A = s₃
    k_C = s₁ # 
    k_F = s₄ # Yet to be tested

    σ = (k_A, 𝐤_B, k_C, k_D, 𝐤_E, k_F)

    vproof = VShuffleProof(μ, τ, σ)

    return vproof
end

function PoSProof(vproof::VShuffleProof)

    (; μ, τ, σ) = vproof
    
    𝐮 = μ
    𝐜 = 𝐮

    (𝐁, A′, 𝐁′, C′, D′, F′) = τ 

    𝐜̂ = 𝐁
    𝐭̂ = 𝐁′
    t₂ = D′
    t₃ = A′
    t₁ = C′ 
    (t₄₂, t₄₁) = F′

    t = (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) 

    (k_A, 𝐤_B, k_C, k_D, 𝐤_E, k_F) = σ 


    𝐬̂ = 𝐤_B 
    𝐬′ = 𝐤_E 
    s₂ = k_D 
    s₃ = k_A 
    s₁ = k_C 
    s₄ = k_F 

    s = (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) 
    
    proof = PoSProof(𝐜, 𝐜̂, t, s)

    return proof
end


function load_verificatum_simulator(basedir::AbstractString; auxsid = "default")

    spec = ProtocolSpec(basedir; auxsid)

    NIZKP = basedir * "/dir/nizkp/$auxsid/"

    CIPHERTEXTS = "$NIZKP/Ciphertexts.bt"
    SHUFFLED_CIPHERTEXTS = "$NIZKP/ShuffledCiphertexts.bt"

    PERMUTATION_COMMITMENT = "$NIZKP/proofs/PermutationCommitment01.bt"
    PoS_COMMITMENT = "$NIZKP/proofs/PoSCommitment01.bt"
    PoS_REPLY = "$NIZKP/proofs/PoSReply01.bt"

    (; g, pk) = spec

    𝓖 = group(g)
    𝓰 = Generator[𝓖]

    L_tree = decode(read(CIPHERTEXTS))
    L′_tree = decode(read(SHUFFLED_CIPHERTEXTS))

    𝔀 = convert(ElGamal{𝓰}, L_tree) ## Is there anything I can do so that I would get a concrete type here?
    𝔀′ = convert(ElGamal{𝓰}, L′_tree)

    μ_tree = decode(read(PERMUTATION_COMMITMENT))
    μ = convert(Vector{𝓰}, μ_tree)

    τ_tree = decode(read(PoS_COMMITMENT))
    τ = convert(Tuple{Vector{𝓰}, 𝓰, Vector{𝓰}, 𝓰, 𝓰, Tuple{𝓰, 𝓰}}, τ_tree)

    σ_tree = decode(read(PoS_REPLY))
    σ = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, BigInt}, σ_tree)

    
    proof = VShuffleProof(μ, τ, σ)
    proposition = Shuffle(g, pk, 𝔀, 𝔀′)
    
    simulator = Simulator(proposition, proof, spec)

    return simulator
end


### The simulator type will deal with loading the data. 

struct VInit{𝓰<:Generator} #<: Verifier
    spec::ProtocolSpec{𝓰}
    proposition::Shuffle
    ρ::Vector{UInt8} 
    𝐡::Vector{𝓰}
end

function VInit(spec::ProtocolSpec, proposition::Shuffle) where 𝓰 <: Generator

    ρ = ro_prefix(spec) ### I can add another method there

    𝔀 = proposition.𝐞
    N = length(𝔀)

    (; g, nr, rohash, prghash)  = spec

    𝓖 = group(g)

    𝐡 = crs(𝓖, N, prghash, rohash; nr, ρ)

    return VInit(spec, proposition, ρ, 𝐡)
end


#VInit(spec::ProtocolSpec, proposition::Shuffle) = VInit(spec, proposition.𝐞, proposition.𝐞′)


struct VPermCommit{𝓰<:Generator} #<: Verifier
    spec::ProtocolSpec{𝓰}
    proposition::Shuffle
    ρ::Vector{UInt8} 
    𝐡::Vector{𝓰} 
    s::Vector{UInt8}  
    𝐞::Vector{BigInt} 
end


function VPermCommit(v::VInit{𝓰}, 𝐮::Vector{𝓰}) where 𝓰 <: Generator
    (; 𝐡, ρ, spec, proposition) = v
    (; ne, prghash, rohash, g, pk) = spec
    𝔀, 𝔀′ = proposition.𝐞, proposition.𝐞′

    N = length(𝔀)

    ns = outlen(prghash)
    ro = RO(rohash, ns)

    pk_tree = (g, pk)

    tree = Tree((g, 𝐡, 𝐮, pk_tree, 𝔀, 𝔀′))
    s = ro([ρ..., encode(tree)...])

    prg = PRG(prghash, s)
    𝐭 = rand(prg, BigInt, N; n = ne)
    𝐞 = mod.(𝐭, BigInt(2)^ne)

    return VPermCommit(spec, proposition, ρ, 𝐡, s, 𝐞)
end


struct VPoSCommit{𝓰<:Generator} #<: Verifier
    spec::ProtocolSpec{𝓰}
    proposition::Shuffle
    ρ::Vector{UInt8} 
    𝐡::Vector{𝓰}
    𝐞::Vector{BigInt}
    𝓿::BigInt
end


function VPoSCommit(v::VPermCommit{𝓰}, τ::Tuple{Vector{𝓰}, 𝓰, Vector{𝓰}, 𝓰, 𝓰, Tuple{𝓰, 𝓰}}) where 𝓰 <: Generator
    (; 𝐡, ρ, 𝐞, spec, proposition, s) = v
    (; nv, rohash) = spec

    ro_challenge = RO(rohash, nv)
    tree_challenge = Tree((Leaf(s), τ))
    𝓿 = interpret(BigInt, ro_challenge([ρ..., encode(tree_challenge)...]))

    return VPoSCommit(spec, proposition, ρ, 𝐡, 𝐞, 𝓿)
end

function VPoSCommit(v::VPermCommit, 𝐜̂, t)
    (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) = t # 𝐭̂ = 𝐁′, t₃ = A′, t₄ = F
    𝐁 = 𝐜̂

    𝓰 = typeof(𝐜̂[1])

    𝐁′= Vector{𝓰}(𝐭̂)
    D′ = t₂
    A′ = t₃
    C′ = t₁
    F′ = (t₄₂, t₄₁)

    τ = (𝐁, A′, 𝐁′, C′, D′, F′)

    return VPoSCommit(v, τ)
end


PoSChallenge(verifier::VPoSCommit) = PoSChallenge(verifier.𝐡, verifier.𝐞, verifier.𝓿)


function verify(proposition::Shuffle, proof::VShuffleProof, challenge::PoSChallenge)
    
    𝐡, 𝐞, 𝓿 = challenge.𝐡, challenge.𝐮, challenge.c
    𝔀, 𝔀′ = proposition.𝐞, proposition.𝐞′
    (; g, pk) = proposition

    (; μ, τ, σ) = proof
    
    𝐮 = μ
    𝐁, A′, 𝐁′, C′, D′, F′ = τ
    k_A, 𝐤_B, k_C, k_D, 𝐤_E, k_F = σ

    N = length(𝔀)

    A = prod(𝐮 .^ 𝐞)

    C = prod(𝐮) / prod(𝐡)
    D = 𝐁[N] * inv(𝐡[1])^prod(𝐞)

    @show A^𝓿 * A′ == g^k_A * prod(𝐡 .^ 𝐤_E)
    @show C^𝓿 * C′ == g^k_C
    @show D^𝓿 * D′ == g^k_D

    @show 𝐁[1]^𝓿 * 𝐁′[1] == g^𝐤_B[1] * 𝐡[1]^𝐤_E[1]

    for i in 2:N
        @show 𝐁[i]^𝓿 * 𝐁′[i] == g^𝐤_B[i] * 𝐁[i - 1]^𝐤_E[i]
    end
    
    return true
end


function verify(proposition::Shuffle, proof::VShuffleProof, verifier::ProtocolSpec)

    v1 = VInit(verifier, proposition)
    
    (; μ) = proof
    v2 = VPermCommit(v1, μ)

    (; τ) = proof
    v3 = VPoSCommit(v2, τ)

    v4 = PoSChallenge(v3)

    return verify(proposition, proof, v4) 
end



step(spec::ProtocolSpec, proposition::Proposition) = VInit(spec, proposition)
step(v::VInit{𝓰}, 𝐜::Vector{𝓰}) where 𝓰 <: Generator = VPermCommit(v, 𝐜)
step(v::VPermCommit, 𝐜̂, t) = VPoSCommit(v, 𝐜̂, t)

challenge(v::VInit) = (v.𝐡, v.𝐡[1])
challenge(v::VPermCommit) = v.𝐞
challenge(v::VPoSCommit) = v.𝓿
