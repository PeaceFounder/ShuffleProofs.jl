using Test

using CryptoGroups
using OpenSSLGroups
import ShuffleProofs: shuffle, verify, load_verificatum_simulator, braid, Braid, save, load, Simulator
import SigmaProofs.ElGamal: Enc, Dec
import SigmaProofs.Verificatum: ProtocolSpec

g = @ECGroup{OpenSSLGroups.Prime256v1}()

verifier = ProtocolSpec(; g)

sk = 123
pk = g^sk

enc = Enc(pk, g)

𝐦 = [g^4, g^2, g^3] .|> tuple
𝐞 = enc(𝐦, [2, 3, 4]) 

simulator = shuffle(𝐞, g, pk, verifier)
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

# braiding

Y = [g^4, g^2, g^3]
braid_simulator = braid(Y, g, verifier)
@test verify(braid_simulator)

# Testing serialization

BRAID_DIR = joinpath(tempdir(), "braid")
rm(BRAID_DIR, recursive=true, force=true)
mkpath(BRAID_DIR)

save(braid_simulator, BRAID_DIR)

# need to allow loading zero for elliptic curves and one for ElGamal
loaded_braid_simulator = load(Simulator{Braid}, BRAID_DIR) # Simulator{Braid{G}}
@test verify(loaded_braid_simulator)

openssl_braid_simulator = load(Simulator{Braid{typeof(g)}}, BRAID_DIR)
@test verify(openssl_braid_simulator)

### Testing proof loading

BASE_DIR = "$(@__DIR__)/validation_sample/verificatum/P256/"
simulator = load_verificatum_simulator(BASE_DIR; G = @ECGroup{OpenSSLGroups.Prime256v1})
@test verify(simulator)

simulator_ord = load_verificatum_simulator("$(@__DIR__)/validation_sample/verificatum/P256/")
@test verify(simulator_ord)

### For extended width 

simulator = load_verificatum_simulator("$(@__DIR__)/validation_sample/verificatum/P192w3/"; G = @ECGroup{OpenSSLGroups.Prime192v1})
@test verify(simulator) 
