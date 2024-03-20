using Test

import ShuffleProofs: prove, verify, decrypt, ProtocolSpec

SPEC = "$(@__DIR__)/validation_sample/verificatum/MODP/protInfo.xml"
verifier = ProtocolSpec(SPEC)

(; g) = verifier
𝐦 = [g^4, g^2, g^3]

key = 123

proposition = decrypt(g, 𝐦, key)
@test verify(proposition, key)

proof = prove(proposition, key, verifier)
@test verify(proposition, proof, verifier)

# Higher order API
simulator2 = decrypt(g, 𝐦, key, verifier)
@test verify(simulator2)

