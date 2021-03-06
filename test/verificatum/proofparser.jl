using Test
using XMLDict
import ShuffleProofs: decode, convert, unmarshal_publickey, interpret, Tree, encode, Leaf, Leaf, ro_prefix, map_hash_name, unmarshal, unmarshal_full_public_key, gen_verificatum_basis
import CryptoGroups: ElGamal, PGroup, RO, Hash, PRG, value, order, outlen


PROT_INFO = "$(@__DIR__)/../../ref/demo/protInfo.xml"
auxsid = "default"
NIZKP = "$(@__DIR__)/../../ref/demo/dir/nizkp/$auxsid/"
#AUXSID = "$(@__DIR__)/../ref/demo/dir/nizkp/default/auxsid"


xml = String(read(PROT_INFO))
protinfo = parse_xml(xml)

s_H = protinfo["rohash"]  
s_PRG = protinfo["prg"]
s_Gq = protinfo["pgroup"]


rohash = Hash(map_hash_name(protinfo["rohash"]))
prghash = Hash(map_hash_name(protinfo["prg"]))

nr = parse(Int32, protinfo["statdist"])
nv = parse(Int32, protinfo["vbitlenro"])
ne = parse(Int32, protinfo["ebitlenro"])


FULL_PUBLIC_KEY = "$NIZKP/FullPublicKey.bt"


CIPHERTEXTS = "$NIZKP/Ciphertexts.bt"
SHUFFLED_CIPHERTEXTS = "$NIZKP/ShuffledCiphertexts.bt"

PERMUTATION_COMMITMENT = "$NIZKP/proofs/PermutationCommitment01.bt"
PoS_COMMITMENT = "$NIZKP/proofs/PoSCommitment01.bt"
PoS_REPLY = "$NIZKP/proofs/PoSReply01.bt"


g = unmarshal(decode(split(s_Gq, "::")[2]))
G = typeof(g)

pk_tree = decode(read(FULL_PUBLIC_KEY))
pk = unmarshal_full_public_key(g, pk_tree)

# auxsid could be a default value

Ļ = ro_prefix(protinfo)
@test bytes2hex(Ļ) == "15e6c97600bbe30125cbc08598dcde01a769c15c8afe08fe5b7f5542533159e9"


# Step 1

L_tree = decode(read(CIPHERTEXTS))
Lā²_tree = decode(read(SHUFFLED_CIPHERTEXTS))

š = convert(ElGamal{G}, L_tree)
šā² = convert(ElGamal{G}, Lā²_tree)

Ī¼_tree = decode(read(PERMUTATION_COMMITMENT))
š® = convert(Vector{G}, Ī¼_tree)

Ļ_tree = decode(read(PoS_COMMITMENT))
š, Aā², šā², Cā², Dā², Fā² = convert(Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}, Ļ_tree)

Ļ_tree = decode(read(PoS_REPLY))
k_A, š¤_B, k_C, k_D, š¤_E, k_F = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, G}, Ļ_tree)

N = length(š)


### This is where I need to forward stuff to algorithm 22. 


š” = gen_verificatum_basis(G, prghash, rohash, N; nr, Ļ)

h_str = "(1da949a3dfbeb316e9b225bc7d75b78d0ddd5e44fc382e74f3de95ad10eac798c4cc7be7e57d3afb259964c90fe7eb7e28a7673228d6b35a789dabd0d8351675,2937c1c4771b70c8b3dc935681aa8cef45ed24cf0c74cd2f9599ea5876850936168c5a092270d6396e634b9e46ab59836f509d0a68a65edc1426a87fd157798f,3767a5e108ecc067c31cd8bf544bcebfa3e3002f2af499ad3568e6fdb2775f4147bcf9485aeea3180b81aad365e3f4375c280941fdae10812bf1ba445030ab00,5c83d2d4f9cf3b3c2267788dd95a14740964e89f177690d06c43adfd137a101698c6bdc7ea9565fd0b18b3cfa89a2d5ea860de3912af4ffbae2c1f722912f6b9,2c453b082a201f3410d0b2906e7f2998a2c50d84f8eb0af017bf76124424bd385c15446eaad77b3ef1831798093f688331475c754f9e737d1485d80f0ef8289b,534897b93e335b0de44f3426aa6597170857f610ce0e4ff8af8efc5010ab5dc205ec53da9759e0c5ad0d2fdbf3d116e1ad7a94629c2ee331e8ceb29417983c50,7d09ab7d0704e68376e933ccfbbaa0a2e8b10a270ce72a5add597ae66e692bd930b019cc9be30b25e859dd6ba5e3bd74a872588b1e14885bacaeca3b254cc86a,33ff08f3aae9132accec73805ec2cd98ce871779369d69d135a7e1fb75b653d415480be64116feda3176dc83b2d54cf8240f8c6f1d85168081efb4f013106cdb,921ce5123ccb3b891f9e1f314d84b8ca827c44dc2027dd4fd8272189ba076eba7c2cfe7e8f8a8915b263fc72232e5d5f193f15ff6aece5b9c55f4ca9c1887fcf,410494b95d3e453e46d0b8915765f2316fcf4db7d7eff0349fe674a6498d3aaa2c3bae2b4e3c7ec1a5d5fd90d88a1e9886914f4b8d039cd470d69642b0203b73)"
š”ā² = interpret.(BigInt, hex2bytes.(split(h_str[2:end-1], ",")))

@test š”ā² == value.(š”)


# Step 2

ns = outlen(prghash)
ro = RO(rohash, ns)

tree = Tree((g, š”, š®, pk_tree, š, šā²))
s = ro([Ļ..., encode(tree)...])

# Step 3

prg = PRG(prghash, s)
š­ = rand(prg, BigInt, N; n = ne)
š = mod.(š­, BigInt(2)^ne)

# Step 4

ro_challenge = RO(rohash, nv)
tree_challenge = Tree((Leaf(s), Ļ_tree))
šæ = interpret(BigInt, ro_challenge([Ļ..., encode(tree_challenge)...]))


# Step 5 
A = prod(š® .^ š)

C = prod(š®) / prod(š”)
D = š[N] * inv(š”[1])^prod(š)

@show A^šæ * Aā² == g^k_A * prod(š” .^ š¤_E)
@show C^šæ * Cā² == g^k_C
@show D^šæ * Dā² == g^k_D

@show š[1]^šæ * šā²[1] == g^š¤_B[1] * š”[1]^š¤_E[1]

for i in 2:N
    @show š[i]^šæ * šā²[i] == g^š¤_B[i] * š[i - 1]^š¤_E[i]
end
