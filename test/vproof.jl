using Test

import ShuffleProofs: prove, verify, Simulator, gen_shuffle, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof, ProtocolSpec, gen_roprg

import CryptoGroups: ElGamal, PGroup, Enc, Dec

SPEC = "$(@__DIR__)/../ref/demo/protInfo.xml"
verifier = ProtocolSpec(SPEC)

(; g) = verifier
sk = 123
pk = g^sk


enc = Enc(pk, g)

𝐦 = [g^4, g^2, g^3]
𝐞 = enc(𝐦, [2, 3, 4])

N = length(𝐞)

𝐡 = [g^i for i in 2:N+1]

𝐫′ = [4, 2, 10] 


proposition, secret = gen_shuffle(enc, 𝐞, 𝐫′) # In practice total of random factors can't match as it reveals 

@test verify(proposition, secret)

simulator = prove(proposition, secret, verifier)
(; proof) = simulator

@test verify(simulator)

### Testing proof translation and verification with Verificatum notation written verifier
vproof = VShuffleProof(proof)
@test verify(proposition, vproof, verifier)

### Higher order API

roprg = gen_roprg(UInt8[2])

simulator2 = shuffle(𝐞, g, pk, verifier; roprg)
@test verify(simulator2)
