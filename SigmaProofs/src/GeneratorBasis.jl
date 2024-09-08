module GeneratorBasis

using CryptoGroups.Utils: @check
using CryptoGroups: modulus, order, bitlength, Group, spec
using CryptoGroups.Specs: MODP, ECP
using CryptoPRG.Verificatum: PRG, RO
using CryptoUtils: is_quadratic_residue, sqrt_mod_prime


function modp_generator_basis(prg::PRG, p::Integer, q::Integer, N::Integer; nr::Integer = 0)

    np = bitlength(p)

    𝐭 = rand(prg, BigInt, N; n = np + nr)

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐡 = powermod.(𝐭′, (p - 1) ÷ q, p)
    
    return 𝐡
end

modp_generator_basis(prg::PRG, spec::MODP, N::Integer; nr::Integer = 0) = modp_generator_basis(prg, modulus(spec), order(spec), N; nr)

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

function ecp_generator_basis(prg::PRG, spec::ECP, N::Integer; nr::Integer = 0)
    (; a, b) = spec
    return ecp_generator_basis(prg, (a, b), modulus(spec), order(spec), N; nr)
end


# For pattern matching
_generator_basis(prg::PRG, spec::MODP, N::Integer; nr) = modp_generator_basis(prg, spec, N; nr)
_generator_basis(prg::PRG, spec::ECP, N::Integer; nr) = ecp_generator_basis(prg, spec, N; nr)

function generator_basis(prg::PRG, ::Type{G}, N::Integer; nr::Integer = 0) where G <: Group
    @check !isnothing(order(G)) "Order of the group must be known"
    _spec = spec(G)
    g_vec = _generator_basis(prg, _spec, N; nr)
    return G.(g_vec)
end

export generator_basis

end
