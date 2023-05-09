using Test

import CryptoGroups: ElGamal, PGroup, Enc, Dec, specialize, ECGroup, generator, <|
import CryptoGroups

import ShuffleProofs: prove, verify, Simulator, gen_shuffle, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof

import ShuffleProofs: step, challenge, PoSChallenge, gen_roprg


@enum VState Config Init PermCommit PoSCommit

### 
struct HonestVerifier{T} <: Verifier
    challenge::PoSChallenge
end

HonestVerifier(challenge::PoSChallenge) = HonestVerifier{Config}(challenge)
HonestVerifier{T}(verifier::HonestVerifier) where T = HonestVerifier{T}(verifier.challenge)

PoSChallenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge

step(verifier::HonestVerifier{Config}, proposition::Shuffle) = HonestVerifier{Init}(verifier)
step(verifier::HonestVerifier{Init}, 𝐜) = HonestVerifier{PermCommit}(verifier)
step(verifier::HonestVerifier{PermCommit}, 𝐜̂, t) = HonestVerifier{PoSCommit}(verifier)
#step(verifier::HonestVerifier{PoSCommit}, s) = HonestVerifier{End}(verifier)


challenge(verifier::HonestVerifier{Init}) = (verifier.challenge.𝐡, verifier.challenge.𝐡[1])
challenge(verifier::HonestVerifier{PermCommit}) = verifier.challenge.𝐮
challenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge.c


function test_prover(g)

    sk = 5
    pk = g^sk

    enc = Enc(pk, g)
    dec = Dec(sk)


    𝐦 = [g^4, g^2, g^3]
    𝐞 = enc(𝐦, [2, 3, 7])

    N = length(𝐞)

    𝐡 = [g^i for i in 2:N+1]


    𝐫′ = [4, 2, 3] 
    proposition, secret = gen_shuffle(enc, 𝐞, 𝐫′) # In practice total of random factors can't match as it reveals 
    @test verify(proposition, secret)
    @test verify(proposition, sk)


    (; 𝛙) = secret
    (; 𝐞, 𝐞′) = proposition
    @test dec(𝐞)[𝛙] == dec(𝐞′)


    𝐡 = [g^i for i in 2:N+1]
    𝐮 = [3, 4, 5]
    c = 9

    chg = PoSChallenge(𝐡, 𝐮, c)

    verifier = HonestVerifier(chg)

    # Since the group is small
    # chances that at least one group element will point to 1 are large
    #roprg = gen_roprg(UInt8[7]) # 14, 27, 152
    roprg = gen_roprg(reinterpret(UInt8, Int[304])) # 14, 27, 152, 204, 689, 961
    proof = prove(proposition, secret, verifier; roprg)
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

p = 23
q = 11
G = specialize(PGroup, p, q)
g = G(3)

test_prover(g)


spec = CryptoGroups.Specs.MODP_1024
G = specialize(PGroup, spec)
g = G <| generator(spec)

test_prover(g)


spec = CryptoGroups.Specs.Curve_P_256
G = specialize(ECGroup, spec; name = :P_256)
g = G <| generator(spec)

test_prover(g)
