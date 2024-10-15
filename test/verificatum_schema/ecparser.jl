# Tesing internals for elliptic curve parsing with verificatum
using Test

import ShuffleProofs.SigmaProofs.ElGamal: ElGamalRow
import SigmaProofs.Parser: unmarshal, decode, marshal, unmarshal_publickey, marshal_publickey, marshal_privatekey, unmarshal_privatekey
import SigmaProofs.Verificatum: ro_prefix
import ShuffleProofs: load_verificatum_simulator, verify

s_Gq = "com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536"

tree = decode(split(s_Gq, "::")[2])
g = unmarshal(tree)

tree′ = marshal(g)

@test tree == tree′

### Encoding and decoding public key

BASE_DIR = "$(@__DIR__)/../validation_sample/verificatum/P256/"
PUBLIC_KEY = "$BASE_DIR/publicKey"

pk_tree = decode(read(PUBLIC_KEY))
pk, g = unmarshal_publickey(pk_tree)

# So that things can be properly understood
@test unmarshal_publickey(marshal_publickey(pk, g)) == (pk, g)
@test pk_tree == marshal_publickey(pk, g)

sk = BigInt(123234)

@test unmarshal_privatekey(marshal_privatekey(g, sk)) == (sk, g)

### Decoding of ciphertexts

CIPHERTEXT_FILE = "$BASE_DIR/ciphertexts"

G = typeof(g)

bytes = read(CIPHERTEXT_FILE)
tree = decode(bytes)
ciphertexts = convert(Vector{ElGamalRow{G, 1}}, tree)

### Loading of the whole Proposition

simulator = load_verificatum_simulator(BASE_DIR)

@test ro_prefix(simulator.verifier) == hex2bytes("355806458d6cd42655a52be242705c8e824584ccdb6b1c016cad36c591413de4")

@test verify(simulator)
