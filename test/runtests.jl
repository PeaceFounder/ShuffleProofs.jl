using SafeTestsets

using CryptoGroups
CryptoGroups.set_strict_mode(true)

@safetestset "Number conversations" begin
    include("utils.jl")
end

@safetestset "WikstromTererlius prover and verifier for reencryption shuffle" begin
    include("proof.jl")
end

@safetestset "Verificatum schema" begin
    include("verificatum_schema/runtests.jl")
end

@safetestset "Verificatum verifier" begin
    include("verificatum-verifier.jl")
end

@safetestset "Verifiactum verifier compatible proof generation" begin
    include("verificatum-prover.jl")
end

@safetestset "Decryption proofs" begin
    include("decryption.jl")
end

@safetestset "Braid proofs" begin
    include("braid.jl")
    include("braid_example.jl")
end

@safetestset "Serilization tests" begin
    include("store.jl")
end
