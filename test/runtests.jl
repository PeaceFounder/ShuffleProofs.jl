using Test


@testset "Number conversations" begin
    include("utils.jl")
end

@testset "Binary tree parser tests" begin
    include("parser.jl")
end

@testset "Random number generators and oracles" begin
    include("primitives.jl")
end

@testset "Calculation of ρ" begin
    include("rho.jl")
end

@testset "Groups, generators" begin
    include("generators.jl")
end

@testset "Independent basis vectors" begin
    include("generators.jl")
end

