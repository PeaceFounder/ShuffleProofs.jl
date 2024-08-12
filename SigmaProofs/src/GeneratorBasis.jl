module GeneratorBasis

using CryptoGroups: modulus, order, bitlength
using CryptoGroups.Specs: MODP, ECP
#using ..CryptoGroups.CSPRG: PRG, RO
using CryptoPRG.Verificatum: PRG, RO
using CryptoUtils: is_quadratic_residue, sqrt_mod_prime


function modp_generator_basis(prg::PRG, p::Integer, q::Integer, N::Integer; nr::Integer = 0)

    np = bitlength(p)

    𝐭 = rand(prg, BigInt, N; n = np + nr)

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐡 = powermod.(𝐭′, (p - 1) ÷ q, p)
    
    return 𝐡
end

function ecp_generator_basis(prg::PRG, (a, b)::Tuple{Integer, Integer}, p::Integer, q::Integer, N::Integer; nr::Integer = 0)

    np = bitlength(p) # 1

    𝐭 = rand(prg, BigInt, N*10; n = np + nr)  # OPTIMIZE (I would need it as an iterator)

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐳 = mod.(𝐭′, p)

    𝐡 = Vector{Tuple{BigInt, BigInt}}(undef, N)

    l = 1

    f(x) = x^3 + a*x + b # This assumes that I do know how to do arithmetics with fields.

    for zi in 𝐳
        y2 = mod(f(zi), p)

        if is_quadratic_residue(y2, p)

            x = zi
            y = sqrt_mod_prime(y2, p)

            # The smallest root is taken
            if p - y < y
                y = p - y
            end

            𝐡[l] = (x, y)

            if l == N
                break
            else
                l += 1                
            end
        end
    end

    if l != N
        error("Not enough numbers for 𝐭 have been allocated")
    end

    return 𝐡
end

# ToDo: consider deprecating and redirect to generator_basis function
function Base.rand(prg::PRG, spec::MODP, N::Integer; nr::Integer = 0) 

    p = modulus(spec)
    q = order(spec)

    @assert !isnothing(q) "Order of the group must be known"

    return modp_generator_basis(prg, p, q, N; nr)
end

Base.rand(prg::PRG, spec::ECP, N::Integer; nr::Integer = 0) = ecp_generator_basis(prg, (spec.a, spec.b), modulus(spec), order(spec), N; nr)

end
