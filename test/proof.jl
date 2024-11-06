using Test

import CryptoGroups: @PGroup, @ECGroup
import SigmaProofs.ElGamal: ElGamalRow, Enc, Dec
import CryptoGroups

import SigmaProofs: generator_basis

import ShuffleProofs: prove, verify, Simulator, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof
import ShuffleProofs: PoSChallenge, gen_roprg, challenge_perm, challenge_reenc, seed


### 
struct HonestVerifier <: Verifier
    challenge::PoSChallenge
end

PoSChallenge(verifier::HonestVerifier) = verifier.challenge

generator_basis(verifier::HonestVerifier, G, n) = verifier.challenge.𝐡

challenge_perm(verifier::HonestVerifier, proposition, 𝐜; kwargs...) = verifier.challenge.𝐮

challenge_reenc(verifier::HonestVerifier, proposition, 𝐜, 𝐜̂, t; kwargs...) = verifier.challenge.c


function test_prover(g)

    sk = 5
    pk = g^sk

    enc = Enc(pk, g)
    dec = Dec(sk)


    𝐦 = [g^4, g^2, g^3]
    𝐞 = enc(𝐦, [2, 3, 7]) .|> ElGamalRow

    N = length(𝐞)

    𝐡 = [g^i for i in 2:N+1]

    𝐫′ = [4, 2, 5] #, (1, 3))
    
    proposition = shuffle(𝐞, g, pk; 𝐫′)
    
    𝛙 = sortperm(proposition)
    permute!(proposition, 𝛙)

    @test verify(proposition, 𝐫′, 𝛙)
    @test verify(proposition, sk)

    (; 𝐞, 𝐞′) = proposition
    @test dec(𝐞)[𝛙] == dec(𝐞′) # checks that the correct permuation is used

    𝐡 = [g^i for i in 2:N+1]
    𝐮 = [3, 4, 5]
    c = 9

    chg = PoSChallenge(𝐡, 𝐮, c)

    verifier = HonestVerifier(chg)

    # Since the group is small
    # chances that at least one group element will point to 1 are large
    roprg = gen_roprg(reinterpret(UInt8, Int[38])) # 14, 27, 152, 204, 689, 961
    proof = prove(proposition, verifier, 𝐫′, 𝛙; roprg)
    @test verify(proposition, proof, verifier)

    roprg = gen_roprg(reinterpret(UInt8, Int[409])) # 14, 27, 152, 204, 689, 961
    simulator = shuffle(𝐞, g, pk, verifier; roprg)
    @test verify(simulator)

    ### Testing proof translation and verification with Verificatum notation written verifier

    (; proof) = simulator
    vproof = VShuffleProof(proof)
    @test verify(simulator.proposition, vproof, chg)

    ### To make it easier I need to type vproof
    @test proof == PoSProof(vproof)

end

# It is hard to escape degeneracy with such a small group
# p = 23
# q = 11
# G = concretize_type(PGroup, p, q)
# g = G(3)

# test_prover(g)

g = @PGroup{RFC5114_1024}()
test_prover(g)

g = @ECGroup{P_192}()
test_prover(g)
