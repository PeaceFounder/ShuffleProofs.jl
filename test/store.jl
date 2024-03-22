using Test
using ShuffleProofs: load_shuffle_proposition, load_shuffle_proof, save, load_shuffle_simulator, ProtocolSpec, load_braid_simulator, braid

BASE_DIR = joinpath(@__DIR__, "validation_sample")

shuffle_proposition = load_shuffle_proposition(joinpath(BASE_DIR, "shuffle"))
shuffle_proof = load_shuffle_proof(joinpath(BASE_DIR, "shuffle", "nizkp"), shuffle_proposition.g)
simulator = load_shuffle_simulator(joinpath(BASE_DIR, "shuffle"))


SHUFFLE_DIR = joinpath(tempdir(), "shuffle")
rm(SHUFFLE_DIR, recursive=true, force=true)
mkpath(SHUFFLE_DIR)

save(simulator, SHUFFLE_DIR)
loaded_simulator = load_shuffle_simulator(SHUFFLE_DIR)

@test simulator == loaded_simulator

# Testing braid simulator

BRAID_DIR = joinpath(tempdir(), "braid")
rm(BRAID_DIR, recursive=true, force=true)
mkpath(BRAID_DIR)

verifier = ProtocolSpec(joinpath(BASE_DIR, "shuffle", "protInfo.xml"))
(; g) = verifier
Y = [g^4, g^2, g^3]

braid_simulator = braid(g, Y, verifier)

save(braid_simulator, BRAID_DIR)

# need to allow loading zero for elliptic curves and one for ElGamal
# loaded_braid_simulator = load_braid_simulator(BRAID_DIR)
