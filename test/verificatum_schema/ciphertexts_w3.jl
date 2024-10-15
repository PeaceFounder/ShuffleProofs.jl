using Test
import SigmaProofs.Parser: decode, encode, Tree, unmarshal, marshal_publickey, unmarshal_publickey, unmarshal_privatekey
import CryptoGroups: PGroup
import SigmaProofs.ElGamal: Dec, ElGamalRow
import ShuffleProofs: load_verificatum_simulator, verify, PoSProof

N = 3 # width of cyphertexts

BASE_DIR = "$(@__DIR__)/../validation_sample/verificatum/MODPw3/"
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
    vec =convert(Vector{ElGamalRow{G, N}}, tree)
    @test encode(Tree(vec)) == bytes
    vec
end

𝐞′ = let
    bytes = read(CIPHERTEXTOUT_FILE)
    tree = decode(bytes)
    vec = convert(Vector{ElGamalRow{G, N}}, tree)
    @test encode(Tree(vec)) == bytes
    vec
end

dec = Dec(sk)

@test sort(dec(𝐞)) == sort(dec(𝐞′))

# Testing parser and verifier

simulator = load_verificatum_simulator(BASE_DIR)
@test verify(simulator)

@test verify(simulator.proposition, PoSProof(simulator.proof), simulator.verifier)

# Now lets try out width 3 with P_192 basis

BASE_DIR = "$(@__DIR__)/../validation_sample/verificatum/P192w3/"

simulator = load_verificatum_simulator(BASE_DIR)
@test verify(simulator) # with Verificatum library I am getting 0.6 sec wheras in Julia around 0.4 sec.
