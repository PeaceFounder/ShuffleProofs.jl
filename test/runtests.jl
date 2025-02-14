using SafeTestsets

using CryptoGroups
CryptoGroups.set_strict_mode(true)

@safetestset "HonestVerifier prover and verifier for reencryption shuffle" begin
    include("proof.jl")
end

@safetestset "Bare Verificatum Proof Parsing and Verifying with PGroup" begin
    include("verificatum_schema/proofparser.jl")
end

@safetestset "Verificatum Verifier tests" begin
    include("verificatum_schema/ecparser.jl")
    include("verificatum_schema/ciphertexts.jl")
    include("verificatum_schema/ciphertexts_w3.jl")
    include("verificatum-verifier.jl")
end

@safetestset "Verifiactum verifier compatible proof generation" begin
    include("verificatum-prover.jl")
end

@safetestset "Braid proofs" begin
    include("braid.jl")
    include("braid_example.jl")
end

@safetestset "Serilization tests" begin
    include("serializer.jl")
end

@safetestset "Verificatum Serilization tests" begin
    include("verificatum_schema/serializer.jl")
end

@safetestset "Testing OpenSSL integration" begin
    include("openssl.jl")
end

@safetestset "Testing voting example" begin
    include("../examples/voting.jl")
end

@safetestset "Testing vmnv example" begin
    include("../examples/vmnv.jl")
end
