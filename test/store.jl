using Test
using ShuffleProofs: load_shuffle_proposition, load_shuffle_proof, save, load_shuffle_simulator

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


