using Test

import ShuffleProofs: prove, verify, Simulator, gen_shuffle, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof, ProtocolSpec, gen_roprg, load

import CryptoGroups: PGroup
import SigmaProofs.ElGamal: Enc, Dec, ElGamalRow

SPEC = "$(@__DIR__)/validation_sample/verificatum/MODP/protInfo.xml"
verifier = load(ProtocolSpec, SPEC)

(; g) = verifier
sk = 123
pk = g^sk


enc = Enc(pk, g)

𝐦 = [g^4, g^2, g^3]
𝐞 = ElGamalRow.(enc(𝐦, [2, 3, 4]))

N = length(𝐞)

𝐡 = [g^i for i in 2:N+1]

𝐫′ = reshape([4, 2, 10], (1, 3))


proposition, secret = gen_shuffle(enc, 𝐞, 𝐫′) # In practice total of random factors can't match as it reveals 

@test verify(proposition, secret)

proof = prove(proposition, secret, verifier)
@test verify(proposition, proof, verifier)

### Testing proof translation and verification with Verificatum notation written verifier
vproof = VShuffleProof(proof)
@test verify(proposition, vproof, verifier)

### Higher order API

roprg = gen_roprg(UInt8[2])

simulator = shuffle(𝐞, g, pk, verifier; roprg)
@test verify(simulator)
