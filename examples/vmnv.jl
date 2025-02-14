# Implementation of a verifiable shuffle compatible with Verificatum's Java verifier (vmnv)
#
# This module demonstrates how to create a shuffle proof that can be verified using
# the Verificatum Mix-Net implementation. The proof generation process is designed
# to be compatible with Verificatum's verification tools while maintaining the
# independence of the shuffling process.
#
# Key Challenges and Solutions:
# ----------------------------
# 1. Verificatum Verifier Coupling:
#    The vmnv verifier is tightly coupled with threshold decryption ceremony
#    parameters. This creates compatibility issues when parsing `protInfo.xml`,
#    as our implementation doesn't require these ceremony-specific parameters.
#
# 2. Compatibility Solution:
#    To maintain compatibility, we use a pre-generated Verificatum protInfo.xml
#    file as a template. This file contains all necessary parameters while
#    preserving the integrity of the verification process.
#
# Usage Instructions:
# -----------------
# To verify the generated proof:
#   vmnv -shuffle P256/protInfo.xml P256
#
# Important Notes:
# - Ensure the vmnv version matches your installation
# - For multi-width shuffles, specify the width using the `-width` option
# - Example: for width=2, use: vmnv -shuffle -width 2 P256/protInfo.xml P256w2

using SigmaProofs.Verificatum: ProtocolSpec
using SigmaProofs.Serializer: load
import SigmaProofs.ElGamal: Enc, Dec, ElGamalRow 

using ShuffleProofs
using ShuffleProofs: store_verificatum_nizkp, prove, verify

# Path to the reference Verificatum protocol specification file
P256_VERIFIER_SPEC = "$(@__DIR__)/../test/validation_sample/verificatum/P256/protInfo.xml"

function store(simulator, name)
    # Determine output directory based on environment configuration
    dir = @isdefined(VERIFICATUM_SIMULATOR_OUTPUT_DIR) ? joinpath(VERIFICATUM_SIMULATOR_OUTPUT_DIR, name) : joinpath(tempdir(), name)
    rm(dir, force = true, recursive = true)
    mkdir(dir)

    # Store the proof and copy the protocol specification
    store_verificatum_nizkp(dir, simulator)
    cp(P256_VERIFIER_SPEC, joinpath(dir, "protInfo.xml"))
end

# Initialize the verifier with the protocol specification
verifier = load(ProtocolSpec, P256_VERIFIER_SPEC)
(; g) = verifier

# Example 1: Single-width shuffle demonstration
# -------------------------------------------
sk = 123  # Secret key
pk = g^sk # Public key

enc = Enc(pk, g)
𝐦 = [g^4, g^2, g^3]  # Messages to be shuffled

# Create encrypted elements (required by vmnv verifier)
𝐞 = enc.(𝐦, [3, 4, 5]) .|> ElGamalRow

simulator = shuffle(𝐞, g, pk, verifier)
verify(simulator)
store(simulator, "P256")

# Example 2: Double-width shuffle demonstration
# ------------------------------------------
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
verify(simulator)
store(simulator, "P256w2")
