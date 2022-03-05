using Test
using ShuffleProofs: Node, Leaf, Tree, encode, decode

### Testing parser

@test decode("01 00000002 2D52") == Leaf(UInt8[0x2d, 0x52])
@test decode("00 00000002 01 00000001 AF 01 00000002 03E1") == Node([Leaf(UInt8[0xaf]), Leaf(UInt8[0x03, 0xe1])])
@test decode("00 00000002 00 00000002 01 00000001 AF 01 00000002 03E1 01 00000002 2D52") == Node([Node([Leaf(UInt8[0xaf]), Leaf(UInt8[0x03, 0xe1])]), Leaf(UInt8[0x2d, 0x52])])


#@test convert(Tree, "01 00000002 2D52") == Leaf(UInt8[0x2d, 0x52])
#@test convert(Tree, "00 00000002 01 00000001 AF 01 00000002 03E1") == Node([Leaf(UInt8[0xaf]), Leaf(UInt8[0x03, 0xe1])])
#@test convert(Tree, "00 00000002 00 00000002 01 00000001 AF 01 00000002 03E1 01 00000002 2D52") == Node([Node([Leaf(UInt8[0xaf]), Leaf(UInt8[0x03, 0xe1])]), Leaf(UInt8[0x2d, 0x52])])


y = hex2bytes(replace("00 00000002 00 00000002 01 00000001 AF 01 00000002 03E1 01 00000002 2D52", " "=>""))
tree = decode(y) 
@test convert(Tuple{Tuple{Int32, Int32}, String}, tree) == ((175, 993), "-R")


@test Tree(((UInt8(175), UInt16(993)), "-R")) == tree

### Real life example for prime group specification:

group_spec = "00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"


@test encode(decode(group_spec)) == hex2bytes(group_spec);


tree = decode(group_spec)

(group_name, (p, q, g, e)) = convert(Tuple{String, Tuple{BigInt, BigInt, BigInt, UInt32}}, tree)

@test p == 2*q + 1
@test powermod(g, q + 1, p) == g
