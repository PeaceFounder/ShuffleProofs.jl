using CryptoGroups.Utils: @check
using CryptoGroups: Group, order
using SigmaProofs.ElGamal: Enc, Dec, ElGamalRow
using SigmaProofs: SigmaProofs, Proposition, Proof, Verifier, Simulator
import SigmaProofs.ElGamal: width

struct Shuffle{G <: Group, N} <: Proposition
    g::G
    pk::G
    𝐞::Vector{ElGamalRow{G, N}} 
    𝐞′::Vector{ElGamalRow{G, N}} 

    function Shuffle{G}(g::G, pk::G, 𝐞::Vector{ElGamalRow{G, N}}, 𝐞′::Vector{ElGamalRow{G, N}}) where {G <: Group, N}
        @check length(𝐞) == length(𝐞′)
        new{G, N}(g, pk, 𝐞, 𝐞′)
    end

    Shuffle(g::G, pk::G, 𝐞::Vector{<:ElGamalRow{G}}, 𝐞′::Vector{<:ElGamalRow{G}}) where G <: Group = Shuffle{G}(g, pk, 𝐞, 𝐞′)
end

Base.:(==)(x::Shuffle{G}, y::Shuffle{G}) where G <: Group = x.g == y.g && x.pk == y.pk && x.𝐞 == y.𝐞 && x.𝐞′ == y.𝐞′


Base.permute!(shuffle::Shuffle, perm::AbstractVector{<:Integer}) = permute!(shuffle.𝐞′, perm)
Base.sortperm(shuffle::Shuffle) = sortperm(shuffle.𝐞′)

width(::Type{<:Shuffle{<:Group, N}}) where N = N

Base.length(proposition::Shuffle) = length(proposition.𝐞)

seed(verifier::Verifier, proposition::Shuffle, 𝐜; 𝐡) = nothing # optional method 

struct PoSProof{G <: Group, N} <: Proof
    𝐜::Vector{G}
    𝐜̂::Vector{G}
    t::Tuple{G, G, G, ElGamalRow{G, N}, Vector{G}}
    s::Tuple{BigInt, BigInt, BigInt, NTuple{N, BigInt}, Vector{BigInt}, Vector{BigInt}}
end

import Base: ==

==(x::PoSProof, y::PoSProof) = x.𝐜 == y.𝐜 && x.𝐜̂ == y.𝐜̂ && x.t == y.t && x.s == y.s

width(::Type{PoSProof{<:Group, N}}) where N = N

struct PoSChallenge{G<:Group}
    𝐡::Vector{G} # Independent set of generators
    𝐮::Vector{BigInt} # PoS commitment challenge
    c::BigInt # reencryption challenge

    PoSChallenge(𝐡::Vector{G}, 𝐮::Vector{<:Integer}, c::Integer) where G <: Group = new{G}(𝐡, convert(Vector{BigInt}, 𝐮), convert(BigInt, c))
end

function verify(proposition::Shuffle, 𝐫′::Matrix{<:Integer}, 𝛙::Vector{<:Integer})
    
    (; 𝐞, 𝐞′, g, pk) = proposition

    enc = Enc(pk, g)

    r = [tuple(ri...) for ri in eachcol(𝐫′)]

    return enc(𝐞, r)[𝛙] == 𝐞′
end

verify(proposition::Shuffle, 𝐫′::Vector{<:Integer}, 𝛙::Vector{<:Integer}) = verify(proposition, reshape(𝐫′, (1, length(𝐫′))), 𝛙)

function verify(proposition::Shuffle, sk::Integer)
    
    (; 𝐞, 𝐞′, g, pk) = proposition

    @check g^sk == pk
    
    dec = Dec(sk)
    
    return sort(dec(𝐞)) == sort(dec(𝐞′))
end

function gen_commitment(g::G, 𝐡::Vector{G}, b::Vector, r::Integer) where G <: Group

    com = g^r * prod(𝐡 .^ b)

    return com
end

function gen_perm_commitment(g::G, 𝐡::Vector{G}, 𝛙::Vector, 𝐫::Vector) where G <: Group

    N = length(𝛙)

    𝐜 = Vector{G}(undef, N)

    for i in 1:N
        j = 𝛙[i]
        𝐜[j] = g^𝐫[j] * 𝐡[i]
    end

    return 𝐜
end

function gen_commitment_chain(g::Group, c0::T, 𝐮::Vector, 𝐫::Vector) where T
    
    N = length(𝐮)

    𝐜 = Vector{T}(undef, N)

    𝐜[1] = g^𝐫[1] * c0^𝐮[1]

    for i in 2:N
        𝐜[i] = g^𝐫[i] * 𝐜[i-1]^𝐮[i]
    end
    
    return 𝐜
end

∑(𝐱::Vector{T}, q::T) where T <: Integer = modsum(𝐱, q) #mod(sum(𝐱), q) ### Need to improve
∏(𝐞::Vector{T}, q::T) where T <: Integer = modprod(𝐞, q)
∏(𝐱) = prod(𝐱)

using Random: RandomDevice

function gen_roprg(ρ::AbstractVector{UInt8})

    rohash = HashSpec("sha256")
    prghash = HashSpec("sha256")
    roprg = ROPRG(ρ, rohash, prghash)

    return roprg
end

gen_roprg() = gen_roprg(rand(RandomDevice(), UInt8, 32))

prove(proposition::Shuffle{G}, verifier::Verifier, 𝐫′::Vector{<:Integer}, 𝛙::Vector{<:Integer}; roprg = gen_roprg()) where G <: Group = prove(proposition, verifier, reshape(𝐫′, (length(𝐫′), 1)), 𝛙; roprg)

function prove(proposition::Shuffle{G}, verifier::Verifier, 𝐫′::Matrix{<:Integer}, 𝛙::Vector{<:Integer}; roprg = gen_roprg()) where G <: Group

    @check length(𝛙) == length(proposition)
    @check size(𝐫′) == (length(proposition), width(proposition)) "Dimensions for randomization factors does not match"

    (; g, pk, 𝐞, 𝐞′) = proposition
    
    𝐡 = generator_basis(verifier, G, length(proposition))
    h = first(𝐡)

    N = length(𝛙)
    q = order(g)

    𝐫 = rand(roprg(:𝐫), 2:q - 1, N) # n is part of the sampler here
    𝐫̂ = rand(roprg(:𝐫̂), 2:q - 1, N)

    ω₁ = rand(roprg(:ω₁), 2:q - 1) 
    ω₂ = rand(roprg(:ω₂), 2:q - 1) 
    ω₃ = rand(roprg(:ω₃), 2:q - 1) 
    𝛚₄ = rand(roprg(:𝛚₄), 2:q - 1, width(proposition)) 

    𝛚̂ = rand(roprg(:𝛚̂), 2:q - 1, N)
    𝛚̂′ = rand(roprg(:𝛚̂′), 2:q - 1, N)

    𝐜 = gen_perm_commitment(g, 𝐡, 𝛙, 𝐫)

    _seed = seed(verifier, proposition, 𝐜; 𝐡)
    𝐮 = challenge_perm(verifier, proposition, 𝐜; s = _seed)

    𝐮′ = 𝐮[𝛙]

    𝐜̂ = gen_commitment_chain(g, h, 𝐮′, 𝐫̂)

    𝐯 = Vector{BigInt}(undef, N) 
    𝐯[N] = 1
    for i in N-1:-1:1
        𝐯[i] = 𝐮′[i+1] * 𝐯[i+1] % q
    end

    r̄ = ∑(𝐫, q) 
    r̂ = ∑(𝐫̂ .* 𝐯, q)
    r̃ = ∑(𝐫 .* 𝐮, q)

    r′ = [∑(𝐫′_col .* 𝐮, q) for 𝐫′_col in eachcol(𝐫′)] # a vector of width 𝔀

    t₁ = g^ω₁
    t₂ = g^ω₂
    t₃ = g^ω₃ * ∏(𝐡 .^ 𝛚̂′) 

    enc = Enc(pk, g)
    t₄ = enc(.-𝛚₄) * ∏(𝐞′ .^ 𝛚̂′) 

    𝐭̂ = Vector{G}(undef, N)
    𝐭̂[1] = g^𝛚̂[1] * h^𝛚̂′[1]
    for i in 2:N
        𝐭̂[i] = g^𝛚̂[i] * 𝐜̂[i-1]^𝛚̂′[i]
    end

    t = (t₁, t₂, t₃, t₄, 𝐭̂) 

    c = challenge_reenc(verifier, proposition, 𝐜, 𝐜̂, t; s = _seed)

    s₁ = mod(ω₁ + c * r̄, q)
    s₂ = mod(ω₂ + c * r̂, q)
    s₃ = mod(ω₃ + c * r̃, q)
    𝐬₄ = mod.(𝛚₄ + c * r′, q) 
    
    𝐬̂ = mod.(𝛚̂ .+ c .* 𝐫̂, q) 
    𝐬′ = mod.(𝛚̂′ .+ c .* 𝐮′, q) 

    # It would be bad if any s point to 0
    @check s₁ != 0 
    @check s₂ != 0
    @check s₃ != 0
    @check !(0 in 𝐬₄) 
    @check !(0 in 𝐬̂)
    @check !(0 in 𝐬′)
    
    s = (s₁, s₂, s₃, tuple(𝐬₄...), 𝐬̂, 𝐬′) 

    proof = PoSProof(𝐜, 𝐜̂, t, s)

    return proof
end


function verify(proposition::Shuffle{G, N}, proof::PoSProof{G, N}, verifier::Verifier) where {G <: Group, N}

    #ρ = ro_prefix(verifier) # can be efficiently recomputed
    𝐡 = generator_basis(verifier, G, length(proposition))
    s = seed(verifier, proposition, proof.𝐜; 𝐡)
    
    𝐮 = challenge_perm(verifier, proposition, proof.𝐜; s)

    c = challenge_reenc(verifier, proposition, proof.𝐜, proof.𝐜̂, proof.t; s)

    chg = PoSChallenge(𝐡, 𝐮, c)

    return verify(proposition, proof, chg)
end


function verify(proposition::Shuffle{G, W}, proof::PoSProof{G, W}, challenge::PoSChallenge{G}; verbose=false) where {G <: Group, W}

    (; g, pk, 𝐞, 𝐞′) = proposition
    (; 𝐜, 𝐜̂, t, s) = proof
    (; 𝐡, 𝐮, c) = challenge
    h = 𝐡[1]

    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s 
    (t₁, t₂, t₃, t₄, 𝐭̂) = t 

    q = order(g)
    N = length(𝐞)

    
    c̄ = ∏(𝐜) / ∏(𝐡)
    u = ∏(𝐮, q) 
    
    ĉ = 𝐜̂[N] / h^u
    c̃ = ∏(𝐜 .^ 𝐮)

    e′ =  ∏(𝐞 .^ 𝐮)

    t₁′ = c̄^(-c) * g^s₁
    t₂′ = ĉ^(-c) * g^s₂
    t₃′ = c̃^(-c) * g^s₃ * ∏(𝐡 .^ 𝐬′) # 𝐬′ is 0!

    enc = Enc(pk, g)
    t₄′ = e′^(-c) * enc(.-s₄) * ∏(𝐞′ .^ 𝐬′)

    𝐭̂′ = Vector(undef, N)

    𝐭̂′[1] = 𝐜̂[1]^(-c) * g^𝐬̂[1] * h^𝐬′[1]

    for i in 2:N
        𝐭̂′[i] = 𝐜̂[i]^(-c) * g^𝐬̂[i] * 𝐜̂[i-1]^𝐬′[i]
    end

    report = Report()
    
    report &= "t₁", t₁ == t₁′
    report &= "t₂", t₂ == t₂′ 
    report &= "t₃", t₃ == t₃′
    report &= "t₄", t₄ == t₄′ 

    report &= "𝐭̂", 𝐭̂ .== 𝐭̂′

    if verbose || isvalid(report) == false
        println(report)
    end

    return isvalid(report)
end

function shuffle(𝐞::AbstractVector{<:ElGamalRow{G, N}}, g::G, pk::G; 𝐫′ = gen_r(𝐞)) where {N, G <: Group}

    enc = Enc(pk, g)

    e_enc = enc(𝐞, 𝐫′)

    return Shuffle(g, pk, 𝐞, e_enc)
end


gen_r(𝐞::Vector{G}; roprg = gen_roprg()) where G <: Group = rand(roprg(:𝐫′), 2:order(G)-1, length(𝐞))
gen_r(𝐞::Vector{<:ElGamalRow{G, N}}; roprg = gen_roprg()) where {G <: Group, N} = rand(roprg(:𝐫′), 2:order(G)-1, (length(𝐞), N))

# A convert method could be cleaner
shuffle(𝐦::Vector{G}, g::G, pk::G; 𝐫′ = gen_r(𝐞)) where G <: Group = shuffle([ElGamalRow(one(mi), mi) for mi in 𝐦], g, pk; 𝐫′)

shuffle(𝐞::Union{Vector{<:ElGamalRow{G}}, Vector{G}}, enc::Enc; 𝐫′ = gen_r(𝐞)) where G <: Group = shuffle(𝐞, enc.g, enc.pk; 𝐫′)


function shuffle(𝐞::Vector{<:ElGamalRow{G}}, g::G, pk::G, verifier::Verifier; roprg = gen_roprg(), ψ = nothing) where G <: Group

    𝐫′ = gen_r(𝐞; roprg)

    proposition = shuffle(𝐞, g, pk; 𝐫′)

    if isnothing(ψ)
        ψ = sortperm(proposition)
    end
    permute!(proposition, ψ)

    proof = prove(proposition, verifier, 𝐫′, ψ; roprg)

    return Simulator(proposition, proof, verifier)
end

shuffle(𝐦::Vector{G}, g::G, pk::G, verifier::Verifier; roprg = gen_roprg(), ψ = nothing) where G <: Group = shuffle([ElGamalRow(one(mi), mi) for mi in 𝐦], g, pk, verifier; roprg, ψ)

shuffle(𝐞::Union{Vector{<:ElGamalRow{G}}, Vector{G}}, enc::Enc, verifier::Verifier; roprg = gen_roprg(), ψ = nothing) where G <: Group = shuffle(𝐞, enc.g, enc.pk, verifier; roprg, ψ)
