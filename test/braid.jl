using Test

import ShuffleProofs: prove, verify, decrypt, ProtocolSpec, shuffle, ShuffleProofs, braid, load
import CryptoGroups: PGroup, CryptoGroups, ECGroup, <|
import CryptoGroups.ElGamal: Enc, Dec, ElGamalRow

SPEC = "$(@__DIR__)/validation_sample/verificatum/MODP/protInfo.xml"
verifier = load(ProtocolSpec, SPEC)

(; g) = verifier
Y = [g^4, g^2, g^3]

x = 123
X = g^x

proposition, secret = shuffle(Y, X, g) # changing roles

a = [i[1].a for i in proposition.𝐞′]
b = [i[1].b for i in proposition.𝐞′]

#a = CryptoGroups.a(proposition.𝐞′)
#b = CryptoGroups.b(proposition.𝐞′)

decryption = decrypt(g, b, x)

b′ = decryption.𝔀′

#Y′ = b.^x ./ a

Y′ = b′ ./ a

@test sort(Y′) == sort(Y .^ x)

### An alternative approach according as presented in poster (fixed)

y = [g^4, g^2, g^3]

s = 123
h = g^s

#𝐞 = ElGamal(fill(h, length(y)), y)
𝐞 = [ElGamalRow(h, yi) for yi in y]


proposition, secret = shuffle(𝐞, h, g)

(; 𝐞′) = proposition

a = [i[1].a for i in 𝐞′]
b = [i[1].b for i in 𝐞′]

c = b.^s

y′ = h .* c ./ a # This is where the error was lying in EVoteID 2023 poster

@test sort(y′) == sort(y .^ s)

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

spec = CryptoGroups.curve("P_256")
G = CryptoGroups.specialize(ECGroup, spec)
g = G <| CryptoGroups.generator(spec)

test_braid(g, y)
