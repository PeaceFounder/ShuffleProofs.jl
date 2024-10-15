# A test sample can be generated with setting a GROUP as environment variable in bash which can be created with an internal method `String(SigmaProofs.Verificatum.marshal_s_Gq(g).x)` and then running a follwing set of commands:

# Generating demo data
# vmnd -pkey "$GROUP" publicKey
# vmnd -ciphs -width 3 publicKey 10 ciphertexts

# Doing the shuffle
# vmni -prot -sid "SessionID" -name "Ellection" -nopart 1 -thres 1 -width 3 -pgroup "$GROUP" stub.xml
# vmni -party -name "Santa Claus" stub.xml privInfo.xml protInfo.xml
# vmn -setpk privInfo.xml protInfo.xml publicKey
# vmn -shuffle privInfo.xml protInfo.xml ciphertexts ciphertextsout

# Verification can be done via
# time vmnv -shuffle protInfo.xml dir/nizkp/default

using Test
import SigmaProofs.Parser: decode, encode, Tree, unmarshal, marshal_publickey, unmarshal_publickey, unmarshal_privatekey
import CryptoGroups: PGroup
import SigmaProofs.ElGamal: Dec, ElGamalRow
import ShuffleProofs: load_verificatum_simulator, verify, PoSProof

BASE_DIR = "$(@__DIR__)/../validation_sample/verificatum/MODP/"
CIPHERTEXT_FILE = "$BASE_DIR/ciphertexts"
CIPHERTEXTOUT_FILE = "$BASE_DIR/ciphertextsout"
PUBLIC_KEY = "$(@__DIR__)/../validation_sample/verificatum/publicKey"
PRIVATE_KEY = "$(@__DIR__)/../validation_sample/verificatum/privateKey" 

y, g = let
    bytes = read(PUBLIC_KEY)
    tree = decode(bytes)
    unmarshal_publickey(tree)
end

sk, g′ = let
    bytes = read(PRIVATE_KEY)
    tree = decode(bytes)
    unmarshal_privatekey(tree)
end

@test g′ == g
@test y == g^sk # This way we can be sure that correct inputs have been choosen.

# It would be cool to also to input my own ciphertexts!

G = typeof(g)

𝐞 = let
    bytes = read(CIPHERTEXT_FILE)
    tree = decode(bytes)
    𝐚, 𝐛 = convert(Tuple{Vector{BigInt}, Vector{BigInt}}, tree)
    [ElGamalRow(G(ai), G(bi)) for (ai, bi) in zip(𝐚, 𝐛)]
end

𝐞′ = let
    bytes = read(CIPHERTEXTOUT_FILE)
    tree = decode(bytes)
    convert(Vector{ElGamalRow{G, 1}}, tree)
end

dec = Dec(sk)

@test sort(dec(𝐞)) == sort(dec(𝐞′))

simulator = load_verificatum_simulator(BASE_DIR)
@test verify(simulator)

@test verify(simulator.proposition, PoSProof(simulator.proof), simulator.verifier)
