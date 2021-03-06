using Test
import ShuffleProofs: decode, encode, Tree, unmarshal, marshal_publickey, unmarshal_publickey, unmarshal_privatekey
import CryptoGroups: ElGamal, PGroup, Dec



CIPHERTEXT_FILE = "$(@__DIR__)/../../ref/demo/ciphertexts"
CIPHERTEXTOUT_FILE = "$(@__DIR__)/../../ref/demo/ciphertextsout"
PUBLIC_KEY = "$(@__DIR__)/../../ref/demo/publicKey"
PRIVATE_KEY = "$(@__DIR__)/../../ref/privateKey" 


y, g = let
    bytes = read(PUBLIC_KEY)
    tree = decode(bytes)
    unmarshal_publickey(tree)
end


sk, gā² = let
    bytes = read(PRIVATE_KEY)
    tree = decode(bytes)
    unmarshal_privatekey(tree)
end

@test gā² == g
@test y == g^sk # This way we can be sure that correct inputs have been choosen.

# It would be cool to also to input my own ciphertexts!

G = typeof(g)

#š = group(g)


š = let
    bytes = read(CIPHERTEXT_FILE)
    tree = decode(bytes)
    š, š = convert(Tuple{Vector{BigInt}, Vector{BigInt}}, tree)
    ElGamal{G}(š, š)
end

šā² = let
    bytes = read(CIPHERTEXTOUT_FILE)
    tree = decode(bytes)
    convert(ElGamal{G}, tree)
end


dec = Dec(sk)

š¦ = g .^ (2:11)
@test dec(š) == š¦


š¦ā² = dec(šā²)
@test sort(š¦) == sort(š¦ā²)
