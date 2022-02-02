using Test
using Verificatum: Leaf, Tree, Node, encode, decode, Hash, PRG

h = Hash("sha256")

version = "3.0.4"
sid = "SessionID"
auxsid = "default"
nr = UInt32(100)
nv = UInt32(256)
ne = UInt32(256)

s_H = "SHA-256"
s_PRG = "SHA-256"
s_Gq = "ModPGroup(safe-prime modulus=2*order+1. order bit-length = 511)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"

data = (version, sid * "." * auxsid, Leaf(nr, trim = false), Leaf(nv, trim = false), Leaf(ne, trim = false), s_PRG, s_Gq, s_H)

tree = Tree(data)
binary = encode(Vector{UInt8}, tree)


ρ = "15e6c97600bbe30125cbc08598dcde01a769c15c8afe08fe5b7f5542533159e9"
@test bytes2hex(h(binary)) == ρ


