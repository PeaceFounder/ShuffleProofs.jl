using Test
using Verificatum: Leaf, Generator, marshal, unmarshal, decode, encode, PrimeGroup, 𝐙

p = 3452531
#𝓖 = PrimeGroup(p)

x = 2
#g = Generator(x, 𝓖)

g = Generator{𝐙/p}(x)

leaf = Leaf(g)

@test convert(BigInt, leaf) == 2
@test length(leaf.x) == 3

#y = PrimeGenerator[g, g, g]
#Tree(y)

@test unmarshal(Int, marshal(g)) == g

x = "00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"

# Mocking
#tree.x[2].x[2] = Leaf(UInt8[0, tree.x[2].x[2].x...])

tree = decode(x)
#tree.x[2].x[2].x[1] = UInt8(0) # Checking if manipulation of the prime is noticed
g = unmarshal(BigInt, tree)


@test encode(decode(x)) == hex2bytes(x) ### Belongs to original tests

# Temporary solved it by adding zero byte to the number.
@test marshal(unmarshal(BigInt, tree)) == tree # which is false

@test string(marshal(unmarshal(BigInt, tree))) == x


@test decode(encode(marshal(g))) == marshal(g)


