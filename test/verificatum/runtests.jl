using Test


@testset "Number conversations" begin
    include("utils.jl")
end

@testset "Binary tree parser tests" begin
    include("parser.jl")
end

@testset "Random number generators and oracles" begin
    include("primitives.jl")
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


