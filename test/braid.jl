using Test

import ShuffleProofs: prove, verify, ProtocolSpec, shuffle, ShuffleProofs, braid, load
import CryptoGroups: PGroup, CryptoGroups, @ECGroup
import SigmaProofs.ElGamal: Enc, Dec, ElGamalRow
import SigmaProofs.DecryptionProofs: decrypt, decryptinv

verifier = ProtocolSpec(; g = @ECGroup{P_192}())

(; g) = verifier

y = [g^4, g^2, g^3]

s = 123
h = g^s

𝐞 = [ElGamalRow(yi, one(g)) for yi in y]

proposition = shuffle(𝐞, g, h)

decryption = decrypt(g, proposition.𝐞′, s)
@test sort([inv(i) for (i,) in decryption.plaintexts]) == sort(y .^ s)

# Alternative using decryptinv
decryptioninv = decryptinv(g, proposition.𝐞′, s)
@test sort([i for (i,) in decryptioninv.trackers]) == sort(y .^ s)


######### braid method test ########

(; g) = verifier
Y = [g^4, g^2, g^3]
𝐫′ = [2, 4, 5] #, (1, 3))
x = 23 # exponentiation factor

proposition = braid(Y, g; x, 𝐫′)

𝛙 = collect(1:3)
𝛙 = sortperm(proposition)
permute!(proposition, 𝛙)

@test ShuffleProofs.input_generator(proposition) == g
@test ShuffleProofs.input_members(proposition) == Y
@test ShuffleProofs.output_generator(proposition) == g^x

Y′ = ShuffleProofs.output_members(proposition)
@test Y′ == (Y .^ x)[𝛙]

@test verify(proposition.shuffle, 𝐫′, 𝛙)
@test verify(proposition.decryption, x)

@test verify(proposition, 𝐫′, 𝛙, x)

function test_braid(g, y)

    verifier = ProtocolSpec(;g)

    Y = g .^ y

    simulator = braid(Y, g, verifier)
    @test verify(simulator)

    X = ShuffleProofs.output_generator(proposition)
    Y′ = ShuffleProofs.output_members(proposition)

    @test sort(Y′) == sort(X .^ y)

end

y = [4, 2, 3]

####### Testing on some ModP group #####

(; g) = verifier
test_braid(g, y)

###### Testing on elliptic curve

g = @ECGroup{P_192}()
test_braid(g, y)
