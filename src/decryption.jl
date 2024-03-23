struct Decryption{G<:Group} <: Proposition
    g::G
    pk::G
    𝔀::Vector{G} # encrypted
    𝔀′::Vector{G} # decrypted
end

Base.:(==)(x::Decryption{G}, y::Decryption{G}) where G <: Group = x.g == y.g && x.pk == y.pk && x.𝔀 == y.𝔀 && x.𝔀′ == y.𝔀′

struct DecryptionProof{G <: Group} <: Proof
    τ::Vector{G}
    r::BigInt # I could prevent r being larger than the order
end

Base.:(==)(x::DecryptionProof{G}, y::DecryptionProof{G}) where G <: Group = x.τ == y.τ && x.r == y.r

Base.length(proposition) = length(proposition.𝔀)


function decrypt(g::G, 𝔀::Vector{G}, key::Integer) where G <: Group
    
    pk = g^key
    𝔀′ = 𝔀 .^ key
    
    return Decryption(g, pk, 𝔀, 𝔀′)
end


function verify(proposition::Decryption, secret::Integer)

    (; g, pk, 𝔀, 𝔀′) = proposition

    g^secret == pk || return false
    
    for (x, y) in zip(𝔀, 𝔀′)
        x^secret == y || return false
    end

    return true
end


function decryption_commitment(g::G, 𝔀::Vector{G}, r::Integer) where G <: Group

    N = length(𝔀)

    commitment = Vector{G}(undef, N + 1)

    for i in 1:N
        commitment[i] = 𝔀[i]^r
    end

    commitment[N + 1] = g^r
    
    return commitment
end


function challenge(verifier::ProtocolSpec{G}, proposition::Decryption{G}, commitments::Vector{G}) where G <: Group

    # A decryption proof g can be relative with respect to verifier

    (; g, 𝔀) = proposition
    (; rohash, nv) = verifier

    ρ = ro_prefix(verifier)

    tree = Tree((g, 𝔀, commitments))

    ro = RO(rohash, nv)
    𝓿 = interpret(BigInt, ro([ρ..., encode(tree)...]))

    return 𝓿
end

function prove(proposition::Decryption{G}, secret::Integer, verifier::Verifier; roprg = gen_roprg()) where G <: Group

    (; g, pk, 𝔀, 𝔀′) = proposition

    q = order(G)
    n = bitlength(q) 

    s = rand(roprg(:r), n, 1)[1] # I could try to use the newly added method here. Also putting explicit BigInt could be good!

    τ = decryption_commitment(g, 𝔀, s)

    c = challenge(verifier, proposition, τ)

    r = s + c * secret 

    #return DecryptionProof(τ, r)
    return DecryptionProof(τ, mod(r, q))
end


function verify(proposition::Decryption{G}, proof::DecryptionProof{G}, verifier::Verifier) where G <: Group

    (; g, pk, 𝔀, 𝔀′) = proposition
    (; τ, r) = proof
    
    c = challenge(verifier, proposition, τ)

    N = length(𝔀)

    for i in 1:N
        𝔀[i]^r == τ[i] * 𝔀′[i]^c || return false
    end
    g^r == τ[N + 1] * pk^c || return false
    
    return true
end


function decrypt(g::G, 𝔀::Vector{G}, key::Integer, verifier::Verifier) where G <: Group
        
    proposition = decrypt(g, 𝔀, key)
    proof = prove(proposition, key, verifier)

    return Simulator(proposition, proof, verifier)
end
