using Test

@testset "Binary tree parser tests" begin
    include("parser.jl")
end

@testset "Random number generators and oracles" begin
    include("rho.jl")
end

@testset "Groups, generators" begin
    include("generators.jl")
end

@testset "Independent basis vectors" begin
    include("crs.jl")
end

@testset "ElGamal test" begin
    include("ciphertexts.jl")
end

@testset "Bare Verifier" begin
    include("proofparser.jl")
end

@testset "Elliptic curve tests (under development)" begin
    include("ecparser.jl")
end

