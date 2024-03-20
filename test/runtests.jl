using Test

@testset "Number conversations" begin
    include("utils.jl")
end

@testset "WikstromTererlius prover and verifier for reencryption shuffle" begin
    include("proof.jl")
end

@testset "Verificatum schema" begin
    include("verificatum_schema/runtests.jl")
end

@testset "Verificatum verifier" begin
    include("verificatum-verifier.jl")
end

@testset "Verifiactum verifier compatible proof generation" begin
    include("verificatum-prover.jl")
end

@testset "Decryption proofs" begin
    include("decryption.jl")
end

@testset "Braid proofs" begin
    include("braid.jl")
    include("braid_example.jl")
end

@testset "Serilization tests" begin
    include("store.jl")
end
