using Test
using ShuffleProofs: load_shuffle_proposition, load_shuffle_proof

BASE_DIR = joinpath(@__DIR__, "validation_sample")

shuffle_proposition = load_shuffle_proposition(joinpath(BASE_DIR, "shuffle"))
shuffle_proof = load_shuffle_proof(joinpath(BASE_DIR, "shuffle", "nizkp"), shuffle_proposition.g)
