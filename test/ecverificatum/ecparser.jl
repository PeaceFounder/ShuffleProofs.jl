# Tesing internals for elliptic curve parsing with verificatum
using Test

import ShuffleProofs: marshal_s_Gq, unmarshal, decode, marshal, unmarshal_publickey, marshal_publickey
import CryptoGroups: spec

s_Gq = "com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536"

tree = decode(split(s_Gq, "::")[2])
g = unmarshal(tree)

tree′ = marshal(g)

@test tree == tree′


### Encoding and decoding public key

BASE_DIR = "$(@__DIR__)/../../ref/P256/"
#auxsid = "default"
#NIZKP = "$(@__DIR__)/../../ref/demo/dir/nizkp/$auxsid/"


PUBLIC_KEY = "$BASE_DIR/publicKey"

pk_tree = decode(read(PUBLIC_KEY))
g, pk = unmarshal_publickey(pk_tree)

# So that things can be properly understood
@test unmarshal_publickey(marshal_publickey(g, pk)) == (g, pk)
@test pk_tree == marshal_publickey(g, pk)

