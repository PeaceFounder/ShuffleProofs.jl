using Test
using ShuffleProofs: decode, encode, Tree, unmarshal, ElGamal, Generator, marshal_publickey, unmarshal_publickey, unmarshal_privatekey, Dec


CIPHERTEXT_FILE = "$(@__DIR__)/../../ref/demo/ciphertexts"
CIPHERTEXTOUT_FILE = "$(@__DIR__)/../../ref/demo/ciphertextsout"
PUBLIC_KEY = "$(@__DIR__)/../../ref/demo/publicKey"
PRIVATE_KEY = "$(@__DIR__)/../../ref/privateKey" 


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


𝓖 = group(g)


𝐞 = let
    bytes = read(CIPHERTEXT_FILE)
    tree = decode(bytes)
    𝐚, 𝐛 = convert(Tuple{Vector{BigInt}, Vector{BigInt}}, tree)
    ElGamal{Generator[𝓖]}(𝐚, 𝐛)
end

𝐞′ = let
    bytes = read(CIPHERTEXTOUT_FILE)
    tree = decode(bytes)
    convert(ElGamal{Generator[𝓖]}, tree)
end


dec = Dec(sk)

𝐦 = g .^ (2:11)
@test dec(𝐞) == 𝐦


𝐦′ = dec(𝐞′)
@test sort(𝐦) == sort(𝐦′)
