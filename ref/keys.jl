using Test
using Verificatum: encode, decode, marshal_publickey, marshal_privatekey, unmarshal, unmarshal_publickey, unmarshal_privatekey

PUBLIC_KEY = "$(@__DIR__)/publicKey"
PRIVATE_KEY = "$(@__DIR__)/privateKey"

group_spec = "00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"

tree = decode(group_spec)

g = unmarshal(BigInt, tree)

sk = BigInt(11112)

y = g^sk

pubkey_tree = marshal_publickey(g, y)
write(PUBLIC_KEY, pubkey_tree)


privkey_tree = marshal_privatekey(g, sk)
write(PRIVATE_KEY, privkey_tree)


### Let's test that writing was succesful

y′, g′ =  unmarshal_publickey(decode(read(PUBLIC_KEY)))

@test y′ == y
@test g′ == g

sk′, g′′ =  unmarshal_privatekey(decode(read(PRIVATE_KEY)))

@test g′′ == g
@test sk′ == sk


