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

π¦ = g .^ (2:11)
π« = 102:111

π = enc(π¦, π«)

tree = Tree(π)
write(CIPHERTEXTS, tree)

### Checking that writing was succesful

bytes = read(CIPHERTEXTS)
treeβ² = decode(bytes)

π = group(g)
πβ² = convert(ElGamal{Generator{π}}, treeβ²)

@test π == πβ²

#dec = Dec(sk)

