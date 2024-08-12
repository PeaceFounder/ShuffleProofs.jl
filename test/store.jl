using Test
using ShuffleProofs: load, Shuffle, PoSProof, save, ProtocolSpec, braid, digest
using CryptoPRG: HashSpec

BASE_DIR = joinpath(@__DIR__, "validation_sample")

shuffle_proposition = load(Shuffle, joinpath(BASE_DIR, "shuffle"))
shuffle_proof = load(PoSProof, joinpath(BASE_DIR, "shuffle", "nizkp"), shuffle_proposition.g)
simulator = load(joinpath(BASE_DIR, "shuffle"), name="Shuffle")


SHUFFLE_DIR = joinpath(tempdir(), "shuffle")
rm(SHUFFLE_DIR, recursive=true, force=true)
mkpath(SHUFFLE_DIR)

save(simulator, SHUFFLE_DIR)
loaded_simulator = load(SHUFFLE_DIR)

@test simulator == loaded_simulator

# Testing braid simulator

BRAID_DIR = joinpath(tempdir(), "braid")
rm(BRAID_DIR, recursive=true, force=true)
mkpath(BRAID_DIR)

verifier = load(ProtocolSpec, joinpath(BASE_DIR, "shuffle", "protInfo.xml"))
(; g) = verifier
Y = [g^4, g^2, g^3]

braid_simulator = braid(g, Y, verifier)

save(braid_simulator, BRAID_DIR)

# need to allow loading zero for elliptic curves and one for ElGamal
loaded_braid_simulator = load(BRAID_DIR)

@test loaded_braid_simulator == braid_simulator

# Now the hasher

hasher = HashSpec("sha256")
@test digest(BRAID_DIR, hasher) == digest(braid_simulator, hasher)

# Braid reference

@test bytes2hex(digest(joinpath(BASE_DIR, "braid"), hasher)) == "01403b4deb097382deafa179e06962f7ea7f7d1e9d81a78c1a003712d49374ab"

