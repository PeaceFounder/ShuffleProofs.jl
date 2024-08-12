using Test
import ShuffleProofs: decode, encode, Tree, unmarshal, marshal_publickey, unmarshal_publickey, unmarshal_privatekey
import CryptoGroups: PGroup
import SigmaProofs.ElGamal: Dec, ElGamalRow


CIPHERTEXT_FILE = "$(@__DIR__)/../validation_sample/verificatum/MODP/ciphertexts"
CIPHERTEXTOUT_FILE = "$(@__DIR__)/../validation_sample/verificatum/MODP/ciphertextsout"
PUBLIC_KEY = "$(@__DIR__)/../validation_sample/verificatum/publicKey"
PRIVATE_KEY = "$(@__DIR__)/../validation_sample/verificatum/privateKey" 


y, g = let
    bytes = read(PUBLIC_KEY)
    tree = decode(bytes)
    unmarshal_publickey(tree)
end


sk, g′ = let
    bytes = read(PRIVATE_KEY)
    tree = decode(bytes)
    unmarshal_privatekey(tree)
end

@test g′ == g
@test y == g^sk # This way we can be sure that correct inputs have been choosen.

# It would be cool to also to input my own ciphertexts!

G = typeof(g)

#𝓖 = group(g)

𝐞 = let
    bytes = read(CIPHERTEXT_FILE)
    tree = decode(bytes)
    𝐚, 𝐛 = convert(Tuple{Vector{BigInt}, Vector{BigInt}}, tree)
    #ElGamal{G}(𝐚, 𝐛)
    [ElGamalRow(G(ai), G(bi)) for (ai, bi) in zip(𝐚, 𝐛)]
end

𝐞′ = let
    bytes = read(CIPHERTEXTOUT_FILE)
    tree = decode(bytes)
    #convert(ElGamal{G}, tree)
    convert(Vector{ElGamalRow{G, 1}}, tree)
end


dec = Dec(sk)

𝐦 = g .^ (2:11)
@test getindex.(dec(𝐞), 1) == 𝐦


𝐦′ = getindex.(dec(𝐞′), 1)
@test sort(𝐦) == sort(𝐦′)
