using Test

@testset "Testing ElGamal" begin
    include("elgamal.jl")
end

@testset "Testing Generator Basis" begin
    include("gbasis.jl")
    include("gecbasis.jl")
end
