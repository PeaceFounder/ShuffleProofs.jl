# ShuffleProofs.jl

[![codecov](https://codecov.io/gh/PeaceFounder/ShuffleProofs.jl/graph/badge.svg?token=4VCLLS1YEF)](https://codecov.io/gh/PeaceFounder/ShuffleProofs.jl)

ShuffleProofs.jl is a Julia package that implements zero-knowledge proofs of shuffle, particularly useful for E2E verifiable e-voting systems and privacy-preserving applications. It provides a Verificatum-compatible implementation of the Wikstrom proof of shuffle protocol, widely used in real-world electronic voting systems.

Unlike traditional cryptographic tools that focus solely on confidentiality and security, ShuffleProofs.jl addresses the more complex challenge of providing both privacy and verifiability. This is particularly crucial in systems where authorities cannot be blindly trusted, such as electronic voting or anonymous auction systems.

## Key Features

- **Core Functionality**
  - Zero-knowledge proof generation and verification for ElGamal reencryption shuffles
  - Full compatibility with Verificatum's Wikström proof of shuffle protocol
  - Support for verifiable braiding proofs for public key anonymization
  - Extended ciphertext width support for proof generation and verification
  - Reorganised, flat directory structure for proof serializations

- **Cryptographic Infrastructure**
  - Abstract and extensible cryptographic group support:
    - Elliptic curves (with planned OpenSSL optimization)
    - Modular prime groups
  - Secure random number generation for proof components
  - Flexible verifier interface for custom implementations

- **Verificatum Compatibility**
  - Loading and verification of Verificatum-generated proofs
  - Proof generation matching Verificatum verifier specification
  - Compliant with Verificatum file format specifications

- **Developer Experience**
  - Clean implementation following [Haenni et al.](https://link.springer.com/chapter/10.1007/978-3-319-70278-0_23#citeas) pseudocode
  - Comprehensive test suite with high coverage
  - Type-safe implementation leveraging Julia's type system
  - Readiness to integrate with Julia's high-performance computing ecosystem
  - Modular architecture supporting extension and customization

The package implements state-of-the-art protocols according to the Verificatum verifier specification, with which Verificatum-generated proofs pass. The prover is implemented according to Haenni et al. pseudocode, which is mapped to the Verificatum verifier specification, so the created shuffle proofs are Verificatum verifier compatible. The Verificatum specification has been deployed in national-scale electronic voting systems in Estonia, Norway, and Switzerland, making this implementation suitable for aspiring production environments.

## Installation

```julia
using Pkg
Pkg.add("ShuffleProofs")
```

The package is registered in Julia's general registry and can be installed with the standard package manager on Julia-supported platforms: Linux, MacOS, Windows, FreeBSD and others. All dependencies are automatically handled during installation; no binary artefacts are compiled locally. Hence, the package shall work robustly for all future environments with few updates.

## Quick Start: Electronic Voting Example

Here's a simplified example of how ShuffleProofs.jl can be used in an electronic voting system:

```julia
using CryptoGroups
using SigmaProofs.ElGamal: Enc, ElGamalRow
using SigmaProofs.DecryptionProofs: decrypt
using SigmaProofs.Verificatum: ProtocolSpec
using ShuffleProofs: shuffle, verify

# Setup
g = @ECGroup{P_192}()
verifier = ProtocolSpec(; g)
sk = 123  # Secret key (in practice, distributed in threshold ceremony)
pk = g^sk
options = [g, g^2, g^3]  # Voting options

# Step 1: Voters submit encrypted votes
bbord = let
    enc = Enc(pk, g)
    ciphertexts_in = [enc(options[rand(1:3)], rand(1:10)) |> ElGamalRow for i in 1:10]
    (; ciphertexts_in)
end

# Step 2: Re-encryption and shuffle
bbord = let
    enc = Enc(pk, g)
    simulator = shuffle(bbord.ciphertexts_in, enc, verifier)
    (; bbord..., 
       ciphertexts_out = simulator.proposition.𝐞′,
       shuffle_proof = simulator.proof)
end

# Step 3: Decryption
bbord = let
    simulator = decrypt(g, bbord.ciphertexts_out, sk, verifier)
    (; bbord...,
       votes = simulator.proposition.plaintexts,
       dec_proof = simulator.proof)
end
```

This example demonstrates a complete electronic voting workflow: vote submission, shuffling, and decryption. The process ensures that while votes remain anonymous, the entire process is verifiable. Each step produces cryptographic proofs that can be independently verified, ensuring that no votes have been added, removed, or modified during the process.

The bulletin board (`bbord`) acts as a public ledger where all operations are recorded along with their proofs. This transparency allows anyone to verify the integrity of the election while maintaining voter privacy through the shuffle mechanism.

## Verifying Shuffles

To verify a shuffle proof:

```julia
# Generate proof
proof = prove(proposition, secret, verifier)

# Verify
verify(proposition, proof, verifier)
```

The verification process is a crucial component of the system's security. It allows any party to independently verify that a shuffle was performed correctly without learning anything about the actual permutation used. This is achieved through zero-knowledge proofs, which provide mathematical certainty about the correctness of the shuffle without revealing any information about how the shuffling was performed.

## Braiding Example

Braiding allows for anonymous group signatures. Here's how to use it:

```julia
using CryptoGroups
using ShuffleProofs

# Setup
_curve = curve("P-256")
G = specialize(ECGroup, _curve, name = :P_256)
g = G(generator(_curve))

# Create member keys
y = [4, 2, 3]
Y = g .^ y

# Perform braiding
verifier = ProtocolSpec(;g)
simulator = braid(Y, g, verifier)

# Verify braiding
@assert verify(simulator)

# Get outputs
h = output_generator(simulator.proposition)
Y′ = output_members(simulator.proposition)

# Verify membership preservation
@assert sort(h .^ y) == sort(Y′)
```

Braiding is an advanced feature that creates knot-like structures where inputs are related to outputs through privately known exponents. This is particularly useful in scenarios where group members need to prove their membership without revealing their identity, such as in whistleblower protection systems or in voting systems where votes are signed pseudonymously.

## Working with Verificatum

To verify proofs generated by Verificatum:

```julia
simulator = load_verificatum_simulator(DEMO_DIR)
verify(simulator)
```

Verificatum compatibility is a key feature of ShuffleProofs.jl, allowing it to interoperate with one of the most widely deployed mix-net systems. This means proofs generated by Verificatum can be verified using this package, and vice versa (in principle, if serialisation is done properly). The implementation follows Verificatum's rigorous specification, ensuring complete compatibility.

## Custom Verifiers

The package supports custom verifier implementations:

```julia
struct HonestVerifier{T} <: Verifier
    challenge::PoSChallenge
end

generator_basis(verifier::HonestVerifier, G, n) = verifier.challenge.𝐡
challenge_perm(verifier::HonestVerifier, proposition, 𝐜) = verifier.challenge.𝐮
challenge_reenc(verifier::HonestVerifier, proposition, 𝐜, 𝐜̂, t) = verifier.challenge.c
```

The verifier architecture is designed to be extensible, allowing users to implement custom verification strategies. This is particularly useful for specialized applications or research purposes where the standard verification process needs to be modified. 

## References

- Wikstrom, "How To Implement A Stand-Alone Verifier for the Verificatum Mix-Net"
- Wikström, "A Commitment-Consistent Proof of a Shuffle"
- Wikström, "User Manual for the Verificatum Mix-Net"
- Haenni et al., "Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets"
- [verificatum.org](https://verificatum.org)

These references provide the theoretical foundation and implementation details for the protocols used in this package. They are essential reading for understanding the security properties and mathematical underpinnings of the shuffle proofs.
