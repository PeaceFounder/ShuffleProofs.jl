using Test

import ShuffleProofs: prove, verify, decrypt, ProtocolSpec, shuffle, ShuffleProofs, braid
import CryptoGroups: ElGamal, PGroup, Enc, Dec, CryptoGroups, ECGroup, <|

SPEC = "$(@__DIR__)/../ref/demo/protInfo.xml"
verifier = ProtocolSpec(SPEC)

(; g) = verifier
Y = [g^4, g^2, g^3]

x = 123
X = g^x

#proposition, secret = shuffle(Y, g, X)
proposition, secret = shuffle(Y, X, g) # changing roles

a = CryptoGroups.a(proposition.𝐞′)
b = CryptoGroups.b(proposition.𝐞′)


decryption = decrypt(g, b, x)

b′ = decryption.𝔀′

#Y′ = b.^x ./ a

Y′ = b′ ./ a

sort(Y′) == sort(Y .^ x)

######### braid method test ########

(; g) = verifier
Y = [g^4, g^2, g^3]

proposition, secret = braid(g, Y)

@test ShuffleProofs.input_generator(proposition) == g
@test ShuffleProofs.input_members(proposition) == Y
@test ShuffleProofs.output_generator(proposition) == g^secret.key

Y′ = ShuffleProofs.output_members(proposition)
@test sort(Y′) == sort(Y .^ secret.key)

@test verify(proposition, secret)


function test_braid(g, y)

    verifier = ProtocolSpec(;g)

    Y = g .^ y

    simulator = braid(g, Y, verifier)
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

spec = CryptoGroups.curve("P-256")
G = CryptoGroups.specialize(ECGroup, spec; name = :P_256)
g = G <| CryptoGroups.generator(spec)

test_braid(g, y)
