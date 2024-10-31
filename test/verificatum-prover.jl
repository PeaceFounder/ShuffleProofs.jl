using Test

# Why does this file have such a name?

import ShuffleProofs: prove, verify, Simulator, Verifier, PoSChallenge, Shuffle, shuffle, VShuffleProof, PoSProof, ProtocolSpec, gen_roprg, load

using CryptoGroups
import SigmaProofs.ElGamal: Enc, Dec, ElGamalRow 

g = @ECGroup{P_192}()

verifier = ProtocolSpec(; g)

sk = 123
pk = g^sk

enc = Enc(pk, g)

𝐦 = [g^4, g^2, g^3]
𝐞 = enc(𝐦, [2, 3, 4]) .|> ElGamalRow # Necessary because it returns ElGamalElement

𝐫′ = [4, 2, 10]
e_enc = enc(𝐞, 𝐫′)

proposition = shuffle(𝐞, g, pk; 𝐫′) 
𝛙 = sortperm(proposition)
permute!(proposition, 𝛙)

@test verify(proposition, 𝐫′, 𝛙)

proof = prove(proposition, verifier, 𝐫′, 𝛙)
@test verify(proposition, proof, verifier)

### Testing proof translation and verification with Verificatum notation written verifier
vproof = VShuffleProof(proof)
@test verify(proposition, vproof, verifier)

### Higher order API

roprg = gen_roprg(UInt8[2])

simulator = shuffle(𝐞, g, pk, verifier; roprg)
@test verify(simulator)

### Testing width

𝐦 = [
    (g^2, g^4),
    (g^4, g^5),
    (g^7, g^3)
]

𝐫 = [
    2 5;
    4 6;
    9 8;
]

𝐞 = enc(𝐦, 𝐫)

simulator = shuffle(𝐞, g, pk, verifier)
@test verify(simulator)

dec = Dec(sk)
@test sort(𝐦) == sort(dec(simulator.proposition.𝐞′))
