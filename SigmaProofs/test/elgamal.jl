using Test
import CryptoGroups
import CryptoGroups: @PGroup, concretize_type, generator, ECGroup, @ECGroup
import SigmaProofs.ElGamal: Enc, Dec

function elgamal_test(g)

    sk = 5
    pk = g^sk
    r = 3
    m = g^5
    r2 = 6

    enc = Enc(pk, g)
    dec = Dec(sk)

    @test dec(enc(m, r)) == m
    @test enc(enc(m, r), r2) == enc(m, r + r2)

    ### Shuffle generation

    sk = 5
    pk = g^sk

    enc = Enc(pk, g)

    m_vec = [g^4, g^2, g^3]
    e_vec = enc.(m_vec, [2, 3, 7]) 

    ### The shuffling
    r_vec = Int[4, 2, 3]

    e_enc = enc.(e_vec, r_vec)
    ψ = sortperm(e_enc)
    sort!(e_enc)

    @test sort(dec.(e_enc)) == sort(m_vec)

    messages = [
        (g, g^2),
        (g^2, g^3),
        (g^3, g^4)
    ]

    messages_enc = enc(messages, [2, 3, 7])
    @test messages == dec(messages_enc)

    messages_enc = enc(messages, [(2, 3), (3, 5), (7, 2)])
    @test messages == dec(messages_enc)

    #m_vec = [g, g^2, g^3]
    #e_vec = enc.(m_vec, 1)
end


let
    g = @PGroup{p = 23, q = 11}(3)
    elgamal_test(g)
end


import CryptoGroups
import CryptoGroups: concretize_type, generator, PGroup, ECGroup, Specs


let
    g = @PGroup{RFC5114_1024}()
    elgamal_test(g)
end


let
    g = @ECGroup{P_192}()
    elgamal_test(g)
end


let
    spec = CryptoGroups.Specs.Curve_B_163_PB
    G = concretize_type(ECGroup, spec; name = :B_163_PB)
    g = G(generator(spec))

    elgamal_test(g)
end



