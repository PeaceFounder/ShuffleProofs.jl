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

@testset "Groups, generators and independent basis" begin
    include("generators.jl")
end
