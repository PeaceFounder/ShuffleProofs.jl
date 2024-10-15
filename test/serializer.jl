using Test
using ShuffleProofs: load, Shuffle, Braid, PoSProof, save, ProtocolSpec, braid#, digest
using SigmaProofs: Simulator
using SigmaProofs.Serializer: digest, treespec
using CryptoPRG: HashSpec

BASE_DIR = joinpath(@__DIR__, "validation_sample")

shuffle_proposition = load(Shuffle, joinpath(BASE_DIR, "shuffle"))
G = typeof(shuffle_proposition.g)
shuffle_proof = load(PoSProof{G}, joinpath(BASE_DIR, "shuffle", "nizkp"))
simulator = load(Simulator{Shuffle}, joinpath(BASE_DIR, "shuffle"))

SHUFFLE_DIR = joinpath(tempdir(), "shuffle")
rm(SHUFFLE_DIR, recursive=true, force=true)
mkpath(SHUFFLE_DIR)

save(simulator, SHUFFLE_DIR)
loaded_simulator = load(Simulator{Shuffle}, SHUFFLE_DIR)

@test simulator == loaded_simulator

# Testing braid simulator

BRAID_DIR = joinpath(tempdir(), "braid")
rm(BRAID_DIR, recursive=true, force=true)
mkpath(BRAID_DIR)

verifier = load(ProtocolSpec, joinpath(BASE_DIR, "shuffle", "protInfo.xml"))
(; g) = verifier
Y = [g^4, g^2, g^3]

braid_simulator = braid(Y, g, verifier)

save(braid_simulator, BRAID_DIR)

# need to allow loading zero for elliptic curves and one for ElGamal
loaded_braid_simulator = load(Simulator{Braid}, BRAID_DIR)

@test loaded_braid_simulator == braid_simulator

# Now the hasher

hasher = HashSpec("sha256")
@test digest(Simulator{Braid}, BRAID_DIR, hasher) == digest(braid_simulator, hasher)

# Braid reference

# Compatability


@test treespec(Simulator{Shuffle}) == (
    "ProtInfo.xml", 

    # proposition
    "publicKey.bt", 
    "Ciphertexts.bt", 
    "ShuffledCiphertexts.bt", 

    # proof
    "nizkp/PermutationCommitment.bt", 
    "nizkp/PoSCommitment.bt", 
    "nizkp/PoSReply.bt"
)

@test treespec(Simulator{Braid}) == (
    "ProtInfo.xml", 

    # proposition
    "shuffle/publicKey.bt", 
    "shuffle/Ciphertexts.bt", 
    "shuffle/ShuffledCiphertexts.bt", 
    "decryption/publicKey.bt", 
    "decryption/Ciphertexts.bt", 
    "decryption/DecryptionInv.bt", 

    # proof
    "shuffle/nizkp/PermutationCommitment.bt", 
    "shuffle/nizkp/PoSCommitment.bt", 
    "shuffle/nizkp/PoSReply.bt", 
    "decryption/nizkp/DecryptionInvCommitment.bt", 
    "decryption/nizkp/DecryptionInvReply.bt"
)

@test digest(Simulator{Braid}, joinpath(BASE_DIR, "braid"), hasher) |> bytes2hex == "14c6838c0b149c452bc2c4b97ea8eefa34e2d8a3ce265c07c40060f87a9137cc"

# previously
#"01403b4deb097382deafa179e06962f7ea7f7d1e9d81a78c1a003712d49374ab"

