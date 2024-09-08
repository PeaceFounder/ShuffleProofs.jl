using SafeTestsets

@safetestset "Binary tree parser tests" begin
    include("parser.jl")
end

@safetestset "Random number generators and oracles" begin
    include("rho.jl")
end

@safetestset "Groups, generators" begin
    include("generators.jl")
end

@safetestset "Independent basis vectors" begin
    include("crs.jl")
end

@safetestset "ElGamal test" begin
    include("ciphertexts.jl")
end

@safetestset "Bare Verifier" begin
    include("proofparser.jl")
end

@safetestset "Elliptic curve tests (under development)" begin
    include("ecparser.jl")
end

