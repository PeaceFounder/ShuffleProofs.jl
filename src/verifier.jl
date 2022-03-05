# GOAL: refactor the code in such a way so that verifier could be written outsied the main module. 

# verify(proposition, proof, verifier) -> Bool
# verify(simulator) -> Bool

# The proposition of course can be verified knowing the secret (secret key or randomization factors) alone:
# verify(proposition, secret) -> Bool

# The challnege is last step obtained executing finite state machine. Does not need to contain responses. 
# verify(proposition, proof, challenge) -> Bool

# prove(proposition, secret, verifier) -> Simulator

# shuffle(𝔀, g, pk) -> Tuple{Proposition, Secret}
# shuffle(𝔀, g, pk, verifier) -> Simulator


# decrypt(A, g, sk) -> Proposition # secret key is the one which is possible to be used 
# decrypt(A, g, sk, verifier) -> Simulator

# Derives a public key for a given secret key
# Proving knowldge of sk such that: x = g^sk
# power(g, sk) -> Proposition
# power(g, sk, verifier) -> Simulator


abstract type Proposition end
abstract type Proof end
abstract type Verifier end


function step end
function challenge end

struct Simulator
    proposition::Proposition # Proposition type is the one which selects a type of prover being used
    proof::Proof
    verifier::Verifier
end


struct Shuffle <: Proposition
    g
    pk
    𝐞
    𝐞′
end

struct ShuffleSecret
    𝛙
    𝐫′
end


struct PoSProof <: Proof
    𝐜
    𝐜̂
    t
    s
end

import Base: ==

==(x::PoSProof, y::PoSProof) = x.𝐜 == y.𝐜 && x.𝐜̂ == y.𝐜̂ && x.t == y.t && x.s == y.s

struct PoSChallenge
    𝐡 # Independent set of generators
    𝐮 # PoS commitment challenge
    c # Last bit of a challenge
end

### 
function verify(proposition::Shuffle, secret::ShuffleSecret)
    
    (; 𝐞, 𝐞′, g, pk) = proposition
    (; 𝛙, 𝐫′) = secret

    enc = Enc(pk, g)

    return enc(𝐞, 𝐫′)[𝛙] == 𝐞′
end


function verify(proposition::Shuffle, sk::Integer)
    
    (; 𝐞, 𝐞′, g, pk) = proposition

    @assert g^sk == pk
    
    dec = Dec(sk)
    
    return sort(dec(𝐞)) == sort(dec(𝐞′))
end


function gen_shuffle(enc::Enc, e::ElGamal, r::Vector{T}) where T <: Integer

    e_enc = enc(e, r)
    ψ = sortperm(e_enc)

    sort!(e_enc)

    (; g, pk) = enc

    proposition = Shuffle(g, pk, e, e_enc)
    secret = ShuffleSecret(ψ, r)
    
    return proposition, secret
end


function gen_commitment(g::G, 𝐡::Vector{G}, b::Vector, r::Integer) where G <: Generator

    #(; g, h) = crs
    com = g^r * prod(𝐡 .^ b)

    return com
end


function gen_perm_commitment(g::G, 𝐡::Vector{G}, 𝛙::Vector, 𝐫::Vector) where G <: Generator

    #(; g, 𝐡) = crs

    commitments = [g^𝐫[j] * 𝐡[i] for (i, j) in enumerate(𝛙)]
    sorted_commitments = commitments[𝛙]

    return sorted_commitments
end

function gen_commitment_chain(g::Generator, c0::T, 𝐮::Vector, 𝐫::Vector) where T
    
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


_a(x) = b(x)
_b(x) = a(x)

using Random: default_rng, rand


function prove(proposition::Shuffle, secret::ShuffleSecret, verifier::Verifier; rng = default_rng())

    (; 𝛙, 𝐫′) = secret
    (; g, pk, 𝐞, 𝐞′) = proposition
    
    v1 = step(verifier, proposition) # So I could keep a proposition in the coresponding state machine in the end
    𝐡, h = challenge(v1) 

    @assert length(𝛙) == length(𝐞)

    N = length(𝛙)
    q = order(g)
    
    𝐫 = rand(rng, 2:q-1, N) 
    𝐫̂ = rand(rng, 2:q-1, N)
    𝛚 = rand(rng, 2:q-1, 4)
    𝛚̂ = rand(rng, 2:q-1, N)
    𝛚̂′ = rand(rng, 2:q-1, N)

    𝐚′ = _a(𝐞′)
    𝐛′ = _b(𝐞′)

    𝐜 = gen_perm_commitment(g, 𝐡, 𝛙, 𝐫)

    v2 = step(v1, 𝐜)
    𝐮 = challenge(v2)

    𝐮′ = 𝐮[𝛙]

    𝐜̂ = gen_commitment_chain(g, h, 𝐮′, 𝐫̂)

    𝐯 = Vector(undef, N)
    𝐯[N] = 1
    for i in N-1:-1:1
        𝐯[i] = 𝐮′[i+1] * 𝐯[i+1] 
    end

    r̄ = ∑(𝐫, q) 
    r̂ = ∑(𝐫̂ .* 𝐯, q)
    r̃ = ∑(𝐫 .* 𝐮, q)
    r′ = ∑(𝐫′ .* 𝐮, q)

    t₁ = g^𝛚[1] 
    t₂ = g^𝛚[2]

    t₃ = g^𝛚[3] * ∏(𝐡 .^ 𝛚̂′)

    t₄₁ = pk^(-𝛚[4]) * ∏(𝐚′ .^ 𝛚̂′)
    t₄₂ = g^(-𝛚[4]) * ∏(𝐛′ .^ 𝛚̂′)

    𝐭̂ = Vector(undef, N)
    𝐭̂[1] = g^𝛚̂[1] * h^𝛚̂′[1]
    for i in 2:N
        𝐭̂[i] = g^𝛚̂[i] * 𝐜̂[i-1]^𝛚̂′[i]
    end

    y = (𝐞, 𝐞′, 𝐜, 𝐜̂, pk)
    t = (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) 

    v3 = step(v2, 𝐜̂, t)
    c = challenge(v3)

    s₁ = mod(𝛚[1] + c * r̄, q)
    s₂ = mod(𝛚[2] + c * r̂, q)
    s₃ = mod(𝛚[3] + c * r̃, q)
    s₄ = mod(𝛚[4] + c * r′, q)
    
    𝐬̂ = mod.(𝛚̂ .+ c .* 𝐫̂, q) ### What can I do if I have a 0 as one of the elements?
    𝐬′ = mod.(𝛚̂′ .+ c .* 𝐮′, q)
    
    s = (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) # Do I need to ensure that `s` are without 0 elements

    proof = PoSProof(𝐜, 𝐜̂, t, s)

    simulator = Simulator(proposition, proof, verifier) 

    return simulator
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



function verify(proposition::Shuffle, proof::PoSProof, challenge::PoSChallenge)

    (; g, pk, 𝐞, 𝐞′) = proposition
    (; 𝐜, 𝐜̂, t, s) = proof
    (; 𝐡, 𝐮, c) = challenge

    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s 
    (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) = t 

    𝐚 = _a(𝐞)
    𝐛 = _b(𝐞)
    𝐚′ = _a(𝐞′)
    𝐛′ = _b(𝐞′)
    h = 𝐡[1]

    q = order(g)
    N = length(𝐞)

    
    c̄ = ∏(𝐜) / ∏(𝐡)
    u = mod(∏(𝐮), q)
    
    ĉ = 𝐜̂[N] / h^u
    c̃ = ∏(𝐜 .^ 𝐮)

    a′ = ∏(𝐚 .^ 𝐮)
    b′ = ∏(𝐛 .^ 𝐮)

    t₁′ = c̄^(-c) * g^s₁
    t₂′ = ĉ^(-c) * g^s₂
    t₃′ = c̃^(-c) * g^s₃ * ∏(𝐡 .^ 𝐬′)

    t₄₁′ = a′^(-c) * pk^(-s₄) * ∏(𝐚′ .^ 𝐬′)
    t₄₂′ = b′^(-c) * g^(-s₄) * ∏(𝐛′ .^ 𝐬′)

    𝐭̂′ = Vector(undef, N)

    𝐭̂′[1] = 𝐜̂[1]^(-c) * g^𝐬̂[1] * h^𝐬′[1]    #ĉ0 = h

    for i in 2:N
        𝐭̂′[i] = 𝐜̂[i]^(-c) * g^𝐬̂[i] * 𝐜̂[i-1]^𝐬′[i]
    end
    
    @show t₁ == t₁′
    @show t₂ == t₂′ 
    @show t₃ == t₃′
    @show t₄₁ == t₄₁′
    @show t₄₂ == t₄₂′ 

    for i in 1:N
        @show 𝐭̂[i] == 𝐭̂′[i]
    end

    return true # ToDo
end


verify(simulator::Simulator) = verify(simulator.proposition, simulator.proof, simulator.verifier)



function shuffle(𝐞::ElGamal{G}, g::G, pk::G) where G <: Generator 

    # Need to abstract this into a function argument
    q = order(g)
    N = length(𝐞)

    𝐫′ = rand(2:q-1, N)

    enc = Enc(pk, g)
    
    return gen_shuffle(enc, 𝐞, 𝐫′) # I may also refactor it as shuffle. 
end


function shuffle(𝐞::ElGamal{G}, g::G, pk::G, verifier::Verifier) where G <: Generator
    proposition, secret = shuffle(𝐞, g, pk)
    return prove(proposition, secret, verifier)
end
