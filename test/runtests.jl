using Test

@testset "Implementation of WikstromTererlius prover and verifier using Haines paper" begin
    include("proof.jl")
end

@testset "Some Verificatum proof parsing tests" begin
    include("verificatum/runtests.jl")
end

@testset "Verificatum proof verification API" begin
    include("verificatum.jl")
end

@testset "Verifiactum verifier compatible proof generation" begin
    include("vproof.jl")
end

@testset "Elliptic curve tests (under development)" begin
    include("ecverificatum/ecparser.jl")
end
