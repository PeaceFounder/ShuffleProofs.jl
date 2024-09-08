using SafeTestsets

@safetestset "Testing ElGamal" begin
    include("elgamal.jl")
end

@safetestset "Testing PGroup Generator Basis" begin
    include("gbasis.jl")
end

@safetestset "Testing ECGroup Generator Basis" begin
    include("gecbasis.jl")
end


