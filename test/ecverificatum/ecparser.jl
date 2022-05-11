# Tesing internals for elliptic curve parsing with verificatum
using Test

import ShuffleProofs: marshal_s_Gq, unmarshal, decode, marshal
import CryptoGroups: spec

s_Gq = "com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536"

tree = decode(split(s_Gq, "::")[2])
g = unmarshal(tree)

tree′ = marshal(g)

@test tree == tree′



