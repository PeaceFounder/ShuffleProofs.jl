using Test
using Verificatum: unmarshal_publickey, ElGamal, Enc, Tree, decode #, encode


PUBLIC_KEY = "$(@__DIR__)/publicKey"
CIPHERTEXTS = "$(@__DIR__)/ciphertexts"


pk, g = let
    bytes = read(PUBLIC_KEY)
    tree = decode(bytes)
    unmarshal_publickey(tree)
end


enc = Enc(pk, g)

𝐦 = g .^ (2:11)
𝐫 = 102:111

𝐞 = enc(𝐦, 𝐫)

tree = Tree(𝐞)
write(CIPHERTEXTS, tree)

### Checking that writing was succesful

bytes = read(CIPHERTEXTS)
tree′ = decode(bytes)

𝓖 = group(g)
𝐞′ = convert(ElGamal{Generator{𝓖}}, tree′)

@test 𝐞 == 𝐞′

#dec = Dec(sk)

