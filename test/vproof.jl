using Test

import ShuffleProofs: ElGamal, PrimeGenerator, prove, verify, Simulator, Enc, Dec, gen_shuffle, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof, ProtocolSpec

DEMO_DIR = "$(@__DIR__)/../ref/demo/"
verifier = ProtocolSpec(DEMO_DIR)

(; g, pk) = verifier

enc = Enc(pk, g)

𝐦 = [g, g^2, g^3]
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

simulator2 = shuffle(𝐞, g, pk, verifier)
@test verify(simulator2)
