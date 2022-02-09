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
    include("gvector.jl")
end

@testset "Independent basis vectors" begin
    include("crs.jl")
end



