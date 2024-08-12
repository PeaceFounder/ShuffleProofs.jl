using CryptoGroups: Group, order, modulus
using SigmaProofs.ElGamal: Enc, Dec, ElGamalRow

abstract type Proposition end
abstract type Proof end
abstract type Verifier end

function step end
function challenge end

struct Simulator #{T<:Proposition} 
    proposition::Proposition # Proposition type is the one which selects a type of prover being used
    proof::Proof
    verifier::Verifier
end

Base.:(==)(x::Simulator, y::Simulator) = x.proposition == y.proposition && x.proof == y.proof && x.verifier == y.verifier

struct Shuffle{G <: Group} <: Proposition
    g::G
    pk::G
    𝐞::Vector{<:ElGamalRow{G}} # ElGamalRow?
    𝐞′::Vector{<:ElGamalRow{G}} # ElGamalRow?

    function Shuffle{G}(g::G, pk::G, 𝐞::Vector{<:ElGamalRow{G, N}}, 𝐞′::Vector{<:ElGamalRow{G, N}}) where {G <: Group, N}
        @assert length(𝐞) == length(𝐞′)
        new(g, pk, 𝐞, 𝐞′)
    end

    Shuffle(g::G, pk::G, 𝐞::Vector{<:ElGamalRow{G}}, 𝐞′::Vector{<:ElGamalRow{G}}) where G <: Group = Shuffle{G}(g, pk, 𝐞, 𝐞′)
end

Base.:(==)(x::Shuffle{G}, y::Shuffle{G}) where G <: Group = x.g == y.g && x.pk == y.pk && x.𝐞 == y.𝐞 && x.𝐞′ == y.𝐞′

struct ShuffleSecret
    𝛙::Vector{<:Integer}
    𝐫′::Matrix{<:Integer}
end

# When having a ElGamalRow what structure would this proof have?
struct PoSProof{G <: Group} <: Proof
    𝐜::Vector{G}
    𝐜̂::Vector{G}
    #t::Tuple{G, G, G, Tuple{G, G}, Vector{G}}
    t::Tuple{G, G, G, ElGamalRow{G}, Vector{G}}
    s::Tuple{BigInt, BigInt, BigInt, BigInt, Vector{BigInt}, Vector{BigInt}}
end

import Base: ==

==(x::PoSProof, y::PoSProof) = x.𝐜 == y.𝐜 && x.𝐜̂ == y.𝐜̂ && x.t == y.t && x.s == y.s

struct PoSChallenge
    𝐡::Vector{<:Group} # Independent set of generators
    𝐮::Vector{BigInt} # PoS commitment challenge
    c::BigInt # Last bit of a challenge
end

### 
function verify(proposition::Shuffle, secret::ShuffleSecret)
    
    (; 𝐞, 𝐞′, g, pk) = proposition
    (; 𝛙, 𝐫′) = secret

    enc = Enc(pk, g)

    r = [tuple(ri...) for ri in eachcol(𝐫′)]

    return enc(𝐞, r)[𝛙] == 𝐞′
end


function verify(proposition::Shuffle, sk::Integer)
    
    (; 𝐞, 𝐞′, g, pk) = proposition

    @assert g^sk == pk
    
    dec = Dec(sk)
    
    return sort(dec(𝐞)) == sort(dec(𝐞′))
end


function gen_shuffle(enc::Enc, e::AbstractVector{<:ElGamalRow{<:Group}}, r::Matrix{<:Integer}) 

    e_enc = enc(e, r)
    ψ = sortperm(e_enc)

    sort!(e_enc)

    (; g, pk) = enc

    proposition = Shuffle(g, pk, e, e_enc)
    secret = ShuffleSecret(ψ, r)
    
    return proposition, secret
end

function gen_commitment(g::G, 𝐡::Vector{G}, b::Vector, r::Integer) where G <: Group

    com = g^r * prod(𝐡 .^ b)

    return com
end

# Need to ensure 𝐫 to be a vector here
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


∑(𝐱, q) = mod(sum(𝐱), q) ### Need to improve
∏(𝐱) = prod(𝐱)
∏(f, 𝐱) = prod(f, 𝐱)


using Random: RandomDevice

function gen_roprg(ρ::AbstractVector{UInt8})

    rohash = HashSpec("sha256")
    prghash = HashSpec("sha256")
    roprg = ROPRG(ρ, rohash, prghash)

    return roprg
end

gen_roprg() = gen_roprg(rand(RandomDevice(), UInt8, 32))


function prove(proposition::Shuffle{G}, secret::ShuffleSecret, verifier::Verifier; roprg = gen_roprg()) where G <: Group

    (; 𝛙, 𝐫′) = secret
    (; g, pk, 𝐞, 𝐞′) = proposition
    
    v1 = step(verifier, proposition) # So I could keep a proposition in the coresponding state machine in the end
    𝐡, h = challenge(v1) 

    # Would make more sense for length(proposition) == length(secret)
    @assert length(𝛙) == length(𝐞)

    N = length(𝛙)
    q = order(g)
    #n = bitlength(q)

    𝐫 = rand(roprg(:𝐫), 2:q - 1, N) # n is part of the sampler here
    𝐫̂ = rand(roprg(:𝐫̂), 2:q - 1, N)
    𝛚 = rand(roprg(:𝛚), 2:q - 1, 4) 
    𝛚̂ = rand(roprg(:𝛚̂), 2:q - 1, N)
    𝛚̂′ = rand(roprg(:𝛚̂′), 2:q - 1, N)

    𝐜 = gen_perm_commitment(g, 𝐡, 𝛙, 𝐫)

    v2 = step(v1, 𝐜)
    𝐮 = challenge(v2)

    𝐮′ = 𝐮[𝛙]

    𝐜̂ = gen_commitment_chain(g, h, 𝐮′, 𝐫̂)

    𝐯 = Vector{BigInt}(undef, N) 
    𝐯[N] = 1
    for i in N-1:-1:1
        𝐯[i] = 𝐮′[i+1] * 𝐯[i+1] 
    end

    r̄ = ∑(𝐫, q) 
    r̂ = ∑(𝐫̂ .* 𝐯, q)
    r̃ = ∑(𝐫 .* 𝐮, q)
    
    𝐫′ = reshape(𝐫′, length(𝐫′)) # Need to figure out generalization here
    r′ = ∑(𝐫′ .* 𝐮, q) # a vector of width 𝔀

    t₁ = g^𝛚[1] 
    t₂ = g^𝛚[2]
    t₃ = g^𝛚[3] * ∏(𝐡 .^ 𝛚̂′) 

    # This is going to be simplified when t₄ will be made ElGamalRow
    #𝐞′ = [i[1] for i in 𝐞′] 
    enc = Enc(pk, g)
    t₄ = enc(-𝛚[4]) * ∏(𝐞′ .^ 𝛚̂′) # a vector of width 𝔀
#    t₄ = (t₄.a, t₄.b)

    𝐭̂ = Vector{G}(undef, N)
    𝐭̂[1] = g^𝛚̂[1] * h^𝛚̂′[1]
    for i in 2:N
        𝐭̂[i] = g^𝛚̂[i] * 𝐜̂[i-1]^𝛚̂′[i]
    end

    y = (𝐞, 𝐞′, 𝐜, 𝐜̂, pk) # seems redundant
    t = (t₁, t₂, t₃, t₄, 𝐭̂) 

    v3 = step(v2, 𝐜̂, t)
    c = challenge(v3)

    s₁ = mod(𝛚[1] + c * r̄, q)
    s₂ = mod(𝛚[2] + c * r̂, q)
    s₃ = mod(𝛚[3] + c * r̃, q)
    s₄ = mod(𝛚[4] + c * r′, q) # A vector of width 𝔀; Can ω[4] be the same here?
    
    𝐬̂ = mod.(𝛚̂ .+ c .* 𝐫̂, q) ### What can I do if I have a 0 as one of the elements?
    𝐬′ = mod.(𝛚̂′ .+ c .* 𝐮′, q) ### What to do if 𝐬′ is 0?

    # It would be bad if any s point to 0
    @assert s₁ != 0 
    @assert s₂ != 0
    @assert s₃ != 0
    @assert s₄ != 0
    @assert !(0 in 𝐬̂)
    @assert !(0 in 𝐬′)
    
    s = (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) # Do I need to ensure that `s` are without 0 elements

    proof = PoSProof(𝐜, 𝐜̂, t, s)

    #simulator = Simulator(proposition, proof, verifier) 
    #return simulator
    return proof
end


function verify(proposition::Shuffle, proof::PoSProof, verifier::Verifier)
    
    v1 = step(verifier, proposition)

    (; 𝐜) = proof
    v2 = step(v1, 𝐜)

    (; 𝐜̂, t) = proof
    v3 = step(v2, 𝐜̂, t)

    chg = PoSChallenge(v3)
    return verify(proposition, proof, chg)
end


function verify(proposition::Shuffle, proof::PoSProof, challenge::PoSChallenge; verbose=false)

    (; g, pk, 𝐞, 𝐞′) = proposition
    (; 𝐜, 𝐜̂, t, s) = proof
    (; 𝐡, 𝐮, c) = challenge
    h = 𝐡[1]

    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s 
    (t₁, t₂, t₃, t₄, 𝐭̂) = t 

    q = order(g)
    N = length(𝐞)

    
    c̄ = ∏(𝐜) / ∏(𝐡)
    u = mod(∏(𝐮), q)
    
    ĉ = 𝐜̂[N] / h^u
    c̃ = ∏(𝐜 .^ 𝐮)

    e′ =  ∏(𝐞 .^ 𝐮)

    t₁′ = c̄^(-c) * g^s₁
    t₂′ = ĉ^(-c) * g^s₂
    t₃′ = c̃^(-c) * g^s₃ * ∏(𝐡 .^ 𝐬′) # 𝐬′ is 0!

    enc = Enc(pk, g)
    t₄′ = e′^(-c) * enc(-s₄) * ∏(𝐞′ .^ 𝐬′)

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


verify(simulator::Simulator) = verify(simulator.proposition, simulator.proof, simulator.verifier)


function shuffle(𝐞::AbstractVector{<:ElGamalRow{G, N}}, g::G, pk::G; roprg = gen_roprg()) where {N, G <: Group}

    𝐫′ = rand(roprg(:𝐫′), 2:order(g) - 1, (N, length(𝐞))) 
    enc = Enc(pk, g)
    
    return gen_shuffle(enc, 𝐞, 𝐫′)
end


# function shuffle(𝐞::ElGamal{G}, g::G, pk::G; roprg = gen_roprg()) where G <: Group

#     # Need to abstract this into a function argument
#     q = order(g)
#     N = length(𝐞)

#     #n = bitlength(q)

#     𝐫′ = rand(roprg(:𝐫′), 2:q - 1, N)

#     enc = Enc(pk, g)
    
#     return gen_shuffle(enc, 𝐞, 𝐫′) # I may also refactor it as shuffle. 
# end

#shuffle(𝐦::Vector{G}, g::G, pk::G; roprg = gen_roprg()) where G <: Group = shuffle(ElGamal(ones(𝐦), 𝐦), g, pk; roprg)

# A convert method could be cleaner
shuffle(𝐦::Vector{G}, g::G, pk::G; roprg = gen_roprg()) where G <: Group = shuffle([ElGamalRow(one(mi), mi) for mi in 𝐦], g, pk; roprg)

#shuffle(𝐞::Union{ElGamal{G}, Vector{G}}, enc::Enc; roprg = gen_roprg()) where G <: Group = shuffle(𝐞, enc.g, enc.pk; roprg)

shuffle(𝐞::Union{Vector{<:ElGamalRow{G}}, Vector{G}}, enc::Enc; roprg = gen_roprg()) where G <: Group = shuffle(𝐞, enc.g, enc.pk; roprg)


function shuffle(𝐞::Vector{<:ElGamalRow{G}}, g::G, pk::G, verifier::Verifier; roprg = gen_roprg()) where G <: Group
    proposition, secret = shuffle(𝐞, g, pk; roprg)
    #return prove(proposition, secret, verifier; roprg)
    proof = prove(proposition, secret, verifier; roprg)
    return Simulator(proposition, proof, verifier)
end

shuffle(𝐦::Vector{G}, g::G, pk::G, verifier::Verifier; roprg = gen_roprg()) where G <: Group = shuffle([ElGamalRow(one(mi), mi) for mi in 𝐦], g, pk, verifier; roprg)

shuffle(𝐞::Union{Vector{<:ElGamalRow{G}}, Vector{G}}, enc::Enc, verifier::Verifier; roprg = gen_roprg()) where G <: Group = shuffle(𝐞, enc.g, enc.pk, verifier; roprg)
