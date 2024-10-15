using SigmaProofs.Verificatum: generator_basis, ProtocolSpec, ro_prefix
using CryptoPRG.Verificatum: HashSpec, PRG, RO, ROPRG
using CryptoGroups: Group, PGroup, ECGroup
using SigmaProofs.ElGamal: width
using SigmaProofs.Parser: Tree, Leaf, interpret, encode


struct VShuffleProof{G<:Group, N} <: Proof
    μ::Vector{G}
    τ::Tuple{Vector{G}, G, Vector{G}, G, G, ElGamalRow{G, N}}
    σ::Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, NTuple{N, BigInt}}
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


leaf(x::String) = encode(Leaf(x))


function seed(spec, proposition, 𝐮;
              ρ = ro_prefix(spec),
              𝐡 = generator_basis(spec, typeof(proposition.g), length(proposition.𝐞); ρ)
              )

    𝔀, 𝔀′ = proposition.𝐞, proposition.𝐞′
    (; g, pk) = proposition

    (; ne, prghash, rohash) = spec

    roprg = ROPRG(ρ, rohash, prghash)

    N = width(proposition)
    g_ = N == 1 ? g : ntuple(n -> g, N)
    pk_ = N == 1 ? pk : ntuple(n -> pk, N)
    pk_tree = (g_, pk_) 

    tree = Tree((g, 𝐡, 𝐮, pk_tree, 𝔀, 𝔀′)) 

    prg = roprg(encode(tree))

    (; s) = prg

    return s
end

function challenge_perm(spec::ProtocolSpec, proposition, 𝐮;
                        s = seed(spec, proposition, 𝐮)
                        )

    prg = PRG(spec.prghash, s)

    (; ne) = spec
    N = length(proposition.𝐞)

    𝐭 = rand(prg, BigInt, N; n = ne)
    𝐞 = mod.(𝐭, BigInt(2)^ne)

    return 𝐞
end

function verify(proposition::Shuffle{G}, proof::PoSProof{G}, verifier::ProtocolSpec{G}) where G <: Group


    ρ = ro_prefix(verifier)
    𝐡 = generator_basis(verifier, G, length(proposition.𝐞); ρ)
    s = seed(verifier, proposition, proof.𝐜; ρ, 𝐡)

    𝐮 = challenge_perm(verifier, proposition, proof.𝐜; s)

    c = challenge_reenc(verifier, proposition, proof.𝐜, proof.𝐜̂, proof.t; ρ, s)

    chg = PoSChallenge(𝐡, 𝐮, c)
    
    return verify(proposition, proof, chg)
end


function challenge_reenc(spec::ProtocolSpec{G}, proposition::Shuffle{G}, 𝐮, τ::Tuple{Vector{G}, G, Vector{G}, G, G, ElGamalRow{G, N}};     
                         ρ = ro_prefix(spec),
                         s = seed(spec, proposition, 𝐮; ρ)
                         ) where {G <: Group, N}

    (; nv, rohash) = spec

    ro_challenge = RO(rohash, nv)
    tree_challenge = Tree((Leaf(s), τ))
    𝓿 = interpret(BigInt, ro_challenge([ρ..., encode(tree_challenge)...]))

    return 𝓿
end


function challenge_reenc(spec::ProtocolSpec{G}, proposition::Shuffle{G}, 𝐜, 𝐜̂::Vector{G}, t::Tuple{G, G, G, ElGamalRow{G, N}, Vector{G}};
                         ρ = ro_prefix(spec),
                         s = seed(spec, proposition, 𝐜; ρ)
                         ) where {G <: Group, N}

    (t₁, t₂, t₃, t₄, 𝐭̂) = t 
    𝐁 = 𝐜̂

    𝐁′= 𝐭̂
    D′ = t₂
    A′ = t₃
    C′ = t₁
    F′ = t₄

    τ = (𝐁, A′, 𝐁′, C′, D′, F′)

    return challenge_reenc(spec, proposition, 𝐜, τ; ρ, s)
end


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
    report &= "F", F^𝓿 * F′ == enc(.-k_F) * ∏(𝔀′ .^ 𝐤_E) 

    if verbose || isvalid(report) == false
        println(report)
    end

    return isvalid(report)
end


function verify(proposition::Shuffle{G}, vproof::VShuffleProof{G}, verifier::Verifier) where G <: Group

    𝐡 = generator_basis(verifier, G, length(proposition))
    
    𝐮 = challenge_perm(verifier, proposition, vproof.μ)

    c = challenge_reenc(verifier, proposition, vproof.μ, vproof.τ)

    chg = PoSChallenge(𝐡, 𝐮, c)

    return verify(proposition, vproof, chg)
end
