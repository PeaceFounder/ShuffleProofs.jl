using SigmaProofs.DecryptionProofs: DecryptionInv, decryptinv
using SigmaProofs.LogProofs: ChaumPedersenProof

import CryptoGroups

struct Braid{G<:Group} <: Proposition
    shuffle::Shuffle{G}
    decryption::DecryptionInv{G}
    #members::Vector{G} # output_members
end

Base.:(==)(x::Braid{G}, y::Braid{G}) where G <: Group = x.shuffle == y.shuffle && x.decryption == y.decryption

function Base.permute!(braid::Braid, perm::AbstractVector{<:Integer})

    # Mutations are not that simple here as struct may hold a pointer to the same reference hence permutation needs to be skipped here
    if !(braid.decryption.cyphertexts === braid.shuffle.𝐞′)
        permute!(braid.shuffle, perm)
    end

    permute!(braid.decryption, perm)

    return
end

input_generator(braid::Braid) = braid.decryption.g
input_members(braid::Braid) = [i[1].a for i in braid.shuffle.𝐞] 
output_generator(braid::Braid) = braid.decryption.pk
output_members(braid::Braid) = Iterators.flatten(braid.decryption.trackers) |> collect

Base.sortperm(braid::Braid) = sortperm(output_members(braid))

gen_x(g::Group; roprg = gen_roprg()) = rand(roprg(:x), 2:order(g) - 1, 1)[1] 

function braid(Y::Vector{G}, g::G; roprg = gen_roprg(), x = gen_x(g; roprg), 𝐫′ = gen_r(Y; roprg)) where G <: Group
    
    𝐞 = [ElGamalRow(yi, one(yi)) for yi in Y]
    shuffle_proposition = shuffle(𝐞, g, g^x; 𝐫′)

    decryptioninv = decryptinv(g, shuffle_proposition.𝐞′, x)

    braid_proposition = Braid(shuffle_proposition, decryptioninv)

    return braid_proposition 
end

isconsistent(braid::Braid) = braid.shuffle.𝐞′ == braid.decryption.cyphertexts

function verify(braid::Braid, 𝐫′::Vector{<:Integer}, 𝛙::Vector{<:Integer}, x::Integer)

    isconsistent(braid) || return false
    verify(braid.shuffle, 𝐫′, 𝛙) || return false
    verify(braid.decryption, x) || return false

    return true
end

struct BraidProof{G<:Group} <: Proof
    shuffle::PoSProof{G}
    decryption::ChaumPedersenProof{G}
end

Base.:(==)(x::BraidProof{G}, y::BraidProof{G}) where G <: Group = x.shuffle == y.shuffle && x.decryption == y.decryption

proof_type(::Type{Braid{G}}) where G <: Group = BraidProof{G}
proof_type(::Type{Braid}) = BraidProof

# prove proposition to a verifier using a secret...
function prove(proposition::Braid, verifier::Verifier, 𝐫′::Vector{<:Integer}, 𝛙::Vector{<:Integer}, x::Integer)
    
    shuffle_proof = prove(proposition.shuffle, verifier, 𝐫′, 𝛙)
    decryption_proof = prove(proposition.decryption, verifier, x)

    return BraidProof(shuffle_proof, decryption_proof)
end


function verify(braid::Braid, proof::BraidProof, verifier::Verifier)

    isconsistent(braid) || return false
    verify(braid.shuffle, proof.shuffle, verifier) || return false
    verify(braid.decryption, proof.decryption, verifier) || return false

    return true
end


function braid(Y::Vector{G}, g::G, verifier::Verifier; roprg = gen_roprg(), x = gen_x(g; roprg), 𝛙 = nothing) where G <: Group

    𝐫′ = gen_r(Y; roprg)

    proposition = braid(Y, g; 𝐫′, x)

    if isnothing(𝛙)
        𝛙 = sortperm(proposition)
    end
    permute!(proposition, 𝛙)

    proof = prove(proposition, verifier, 𝐫′, 𝛙, x)

    return Simulator(proposition, proof, verifier)
end
