using CryptoGroups: Group, Hash, PRG, RO, PGroup, ROPRG

using Base: @kwdef

@kwdef struct ProtocolSpec{G<:Group} <: Verifier
    g::G
    nr::Int32 = Int32(100)
    nv::Int32 = Int32(256)
    ne::Int32 = Int32(256)
    prghash::HashSpec = Hash("sha256")
    rohash::HashSpec = Hash("sha256")
    version::String = "3.0.4"
    sid::String = "SessionID"
    auxsid::String = "default"
end

function ProtocolSpec(path::AbstractString; auxsid = "default")

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


function marshal_s_Gq(g::PGroup)

    M = bitlength(order(g))

    tree = marshal(g)
    str = "ModPGroup(safe-prime modulus=2*order+1. order bit-length = $M)::" * string(tree)
    
    return Leaf(str)
end


function marshal_s_Gq(g::ECGroup)
    
    curve_name = normalize_ecgroup_name(name(g))
    tree = marshal(g)

    str = "com.verificatum.arithm.ECqPGroup($curve_name)::" * string(tree)

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


struct VShuffleProof{G<:Group} <: Proof
    μ::Vector{G}
    τ::Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}
    σ::Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, BigInt}
end

==(x::VShuffleProof{G}, y::VShuffleProof{G}) where G <: Group = x.μ == y.μ && x.τ == y.τ && x.σ == y.σ


function VShuffleProof(proof::PoSProof)

    (; 𝐜, 𝐜̂, t, s) = proof

    G = typeof(𝐜[1])

    𝐮 = 𝐜
    μ = 𝐮

    (t₁, t₂, t₃, t₄, 𝐭̂) = t 
    𝐁 = 𝐜̂
    𝐁′= 𝐭̂
    D′ = t₂
    A′ = t₃
    C′ = t₁
    F′ = t₄ 

    τ = (𝐁, A′, 𝐁′, C′, D′, F′)

    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s 
    𝐤_B = 𝐬̂
    𝐤_E = 𝐬′
    k_D = s₂
    k_A = s₃
    k_C = s₁ 
    k_F = s₄ 

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
    t₄ = F′

    t = (t₁, t₂, t₃, t₄, 𝐭̂) 

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

    spec = ProtocolSpec(basedir * "/protInfo.xml"; auxsid)

    proposition = load_verificatum_proposition(basedir, auxsid)
    
    NIZKP = basedir * "/dir/nizkp/$auxsid/"
    proof = load_verificatum_proof("$NIZKP/proofs/", proposition.g)
    
    simulator = Simulator(proposition, proof, spec)

    return simulator
end

### The simulator type will deal with loading the data. 

struct VInit{G<:Group} #<: Verifier
    spec::ProtocolSpec{G}
    proposition::Shuffle{G} # ADD G!
    ρ::Vector{UInt8} 
    𝐡::Vector{G}
end

leaf(x::String) = encode(Leaf(x))

function gen_verificatum_basis(::Type{G}, prghash::HashSpec, rohash::HashSpec, N::Integer; nr::Integer = 0, ρ = UInt8[], d = [ρ..., leaf("generators")...]) where G <: Group

    roprg = ROPRG(d, rohash, prghash)
    prg = roprg(UInt8[]) # d is a better argument than x

    return rand(prg, G, N; nr)
end



function VInit(spec::ProtocolSpec{G}, proposition::Shuffle) where G <: Group

    ρ = ro_prefix(spec) ### I can add another method there

    𝔀 = proposition.𝐞
    N = length(𝔀)

    (; g, nr, rohash, prghash)  = spec

    𝐡 = gen_verificatum_basis(G, prghash, rohash, N; nr, ρ)

    return VInit(spec, proposition, ρ, 𝐡)
end


struct VPermCommit{G<:Group} #<: Verifier
    spec::ProtocolSpec{G}
    proposition::Shuffle{G} 
    ρ::Vector{UInt8} 
    𝐡::Vector{G} 
    s::Vector{UInt8}  
    𝐞::Vector{BigInt} 
end


function VPermCommit(v::VInit{G}, 𝐮::Vector{G}) where G <: Group
    (; 𝐡, ρ, spec, proposition) = v
    (; ne, prghash, rohash) = spec
    𝔀, 𝔀′ = proposition.𝐞, proposition.𝐞′
    (; g, pk) = proposition

    N = length(𝔀)

    roprg = ROPRG(ρ, rohash, prghash)

    pk_tree = (g, pk)

    tree = Tree((g, 𝐡, 𝐮, pk_tree, 𝔀, 𝔀′))
    prg = roprg(encode(tree))
    
    (; s) = prg

    𝐭 = rand(prg, BigInt, N; n = ne)
    𝐞 = mod.(𝐭, BigInt(2)^ne)

    return VPermCommit(spec, proposition, ρ, 𝐡, s, 𝐞)
end


struct VPoSCommit{G<:Group} #<: Verifier
    spec::ProtocolSpec{G}
    proposition::Shuffle{G} # ADD G!
    ρ::Vector{UInt8} 
    𝐡::Vector{G}
    𝐞::Vector{BigInt}
    𝓿::BigInt
end


function VPoSCommit(v::VPermCommit{G}, τ::Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}) where G <: Group
    (; 𝐡, ρ, 𝐞, spec, proposition, s) = v
    (; nv, rohash) = spec

    ro_challenge = RO(rohash, nv)
    tree_challenge = Tree((Leaf(s), τ))
    𝓿 = interpret(BigInt, ro_challenge([ρ..., encode(tree_challenge)...]))

    return VPoSCommit(spec, proposition, ρ, 𝐡, 𝐞, 𝓿)
end

function VPoSCommit(v::VPermCommit{G}, 𝐜̂::Vector{G}, t::Tuple{G, G, G, Tuple{G, G}, Vector{G}}) where G <: Group
    (t₁, t₂, t₃, t₄, 𝐭̂) = t 
    𝐁 = 𝐜̂

    𝐁′= 𝐭̂
    D′ = t₂
    A′ = t₃
    C′ = t₁
    F′ = t₄

    τ = (𝐁, A′, 𝐁′, C′, D′, F′)

    return VPoSCommit(v, τ)
end


PoSChallenge(verifier::VPoSCommit) = PoSChallenge(verifier.𝐡, verifier.𝐞, verifier.𝓿)


function verify(proposition::Shuffle, proof::VShuffleProof, challenge::PoSChallenge; verbose=false)
    
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
    
    F = ∏(𝔀 .^ 𝐞)

    report = Report()

    report &= "A", A^𝓿 * A′ == g^k_A * prod(𝐡 .^ 𝐤_E)
    report &= "C", C^𝓿 * C′ == g^k_C
    report &= "D", D^𝓿 * D′ == g^k_D
    
    report &= "B", Bool[
        𝐁[1]^𝓿 * 𝐁′[1] == g^𝐤_B[1] * 𝐡[1]^𝐤_E[1],
        (𝐁[i]^𝓿 * 𝐁′[i] == g^𝐤_B[i] * 𝐁[i - 1]^𝐤_E[i] for i in 2:N)...
    ]

    enc = Enc(pk, g)
    report &= "F", F^𝓿 * F′ == enc(-k_F) * ∏(𝔀′ .^ 𝐤_E) 

    if verbose || isvalid(report) == false
        println(report)
    end

    return isvalid(report)
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
step(v::VInit{G}, 𝐜::Vector{G}) where G <: Group = VPermCommit(v, 𝐜)
step(v::VPermCommit, 𝐜̂, t) = VPoSCommit(v, 𝐜̂, t)

challenge(v::VInit) = (v.𝐡, v.𝐡[1])
challenge(v::VPermCommit) = v.𝐞
challenge(v::VPoSCommit) = v.𝓿
