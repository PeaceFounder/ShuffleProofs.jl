import CryptoGroups

struct Braid{G<:Group} <: Proposition
    shuffle::Shuffle{G}
    decryption::Decryption{G}
    members::Vector{G} # output_members
end

Base.:(==)(x::Braid{G}, y::Braid{G}) where G <: Group = x.shuffle == y.shuffle && x.decryption == y.decryption && x.members == y.members

input_generator(braid::Braid) = braid.decryption.g
input_members(braid::Braid) = CryptoGroups.b(braid.shuffle.𝐞)
output_generator(braid::Braid) = braid.decryption.pk
output_members(braid::Braid) = braid.members


struct BraidSecret
    shuffle::ShuffleSecret
    key::BigInt
end

using Infiltrator

function braid(g::G, Y::Vector{G}; roprg = gen_roprg()) where G <: Group
    
    q = order(g)
    n = bitlength(q)

    x = rand(roprg(:x), n, 1)[1] % q # Is a slight bias an issue?
    X = g^x

    shuffle_proposition, shuffle_secret = shuffle(Y, X, g)
    
    a = CryptoGroups.a(shuffle_proposition.𝐞′)
    b = CryptoGroups.b(shuffle_proposition.𝐞′)

    decryption = decrypt(g, b, x)

    b′ = decryption.𝔀′
    Y′ = b′ ./ a  #Y′ = b.^x ./ a

    braid_proposition = Braid(shuffle_proposition, decryption, Y′)
    braid_secret = BraidSecret(shuffle_secret, x)

    return braid_proposition, braid_secret
end

function isconsistent(braid::Braid)

    b = CryptoGroups.b(braid.shuffle.𝐞′)
    b == braid.decryption.𝔀 || return false

    a = CryptoGroups.a(braid.shuffle.𝐞′)
    b′ = braid.decryption.𝔀′
    
    braid.members == b′ ./ a || return false
    
    return true
end


function verify(braid::Braid, secret::BraidSecret)

    isconsistent(braid) || return false

    verify(braid.shuffle, secret.shuffle) || return false
    verify(braid.decryption, secret.key) || return false

    return true
end


struct BraidProof{G<:Group} <: Proof
    shuffle::PoSProof{G}
    decryption::DecryptionProof{G}
end

Base.:(==)(x::BraidProof{G}, y::BraidProof{G}) where G <: Group = x.shuffle == y.shuffle && x.decryption == y.decryption


function prove(proposition::Braid, secret::BraidSecret, verifier::Verifier)

    shuffle_proof = prove(proposition.shuffle, secret.shuffle, verifier)
    decryption_proof = prove(proposition.decryption, secret.key, verifier)

    return BraidProof(shuffle_proof, decryption_proof)
end


function verify(braid::Braid, proof::BraidProof, verifier::Verifier)

    isconsistent(braid) || return false
    
    verify(braid.shuffle, proof.shuffle, verifier) || return false
    verify(braid.decryption, proof.decryption, verifier) || return false

    return true
end


function braid(g::G, Y::Vector{G}, verifier::Verifier; roprg = gen_roprg()) where G <: Group

    proposition, secret = braid(g, Y; roprg)
    proof = prove(proposition, secret, verifier)

    return Simulator(proposition, proof, verifier)
end
