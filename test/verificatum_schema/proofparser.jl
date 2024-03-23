using Test
using XMLDict
import ShuffleProofs: decode, convert, unmarshal_publickey, interpret, Tree, encode, Leaf, Leaf, ro_prefix, map_hash_name, unmarshal, unmarshal_full_public_key, gen_verificatum_basis
import CryptoGroups: ElGamal, PGroup, RO, HashSpec, PRG, value, order, CryptoGroups#, bitlength #, outlen


PROT_INFO = "$(@__DIR__)/../validation_sample/verificatum/MODP/protInfo.xml"
auxsid = "default"
NIZKP = "$(@__DIR__)/../validation_sample/verificatum/MODP/dir/nizkp/$auxsid/"
#AUXSID = "$(@__DIR__)/../ref/demo/dir/nizkp/default/auxsid"


xml = String(read(PROT_INFO))
protinfo = parse_xml(xml)

s_H = protinfo["rohash"]  
s_PRG = protinfo["prg"]
s_Gq = protinfo["pgroup"]


rohash = HashSpec(map_hash_name(protinfo["rohash"]))
prghash = HashSpec(map_hash_name(protinfo["prg"]))

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

ρ = ro_prefix(protinfo)
@test bytes2hex(ρ) == "15e6c97600bbe30125cbc08598dcde01a769c15c8afe08fe5b7f5542533159e9"


# Step 1

L_tree = decode(read(CIPHERTEXTS))
L′_tree = decode(read(SHUFFLED_CIPHERTEXTS))

𝔀 = convert(ElGamal{G}, L_tree)
𝔀′ = convert(ElGamal{G}, L′_tree)

μ_tree = decode(read(PERMUTATION_COMMITMENT))
𝐮 = convert(Vector{G}, μ_tree)

τ_tree = decode(read(PoS_COMMITMENT))
𝐁, A′, 𝐁′, C′, D′, F′ = convert(Tuple{Vector{G}, G, Vector{G}, G, G, Tuple{G, G}}, τ_tree)

σ_tree = decode(read(PoS_REPLY))
k_A, 𝐤_B, k_C, k_D, 𝐤_E, k_F = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, G}, σ_tree)

N = length(𝔀)


### This is where I need to forward stuff to algorithm 22. 


𝐡 = gen_verificatum_basis(G, prghash, rohash, N; nr, ρ)

h_str = "(1da949a3dfbeb316e9b225bc7d75b78d0ddd5e44fc382e74f3de95ad10eac798c4cc7be7e57d3afb259964c90fe7eb7e28a7673228d6b35a789dabd0d8351675,2937c1c4771b70c8b3dc935681aa8cef45ed24cf0c74cd2f9599ea5876850936168c5a092270d6396e634b9e46ab59836f509d0a68a65edc1426a87fd157798f,3767a5e108ecc067c31cd8bf544bcebfa3e3002f2af499ad3568e6fdb2775f4147bcf9485aeea3180b81aad365e3f4375c280941fdae10812bf1ba445030ab00,5c83d2d4f9cf3b3c2267788dd95a14740964e89f177690d06c43adfd137a101698c6bdc7ea9565fd0b18b3cfa89a2d5ea860de3912af4ffbae2c1f722912f6b9,2c453b082a201f3410d0b2906e7f2998a2c50d84f8eb0af017bf76124424bd385c15446eaad77b3ef1831798093f688331475c754f9e737d1485d80f0ef8289b,534897b93e335b0de44f3426aa6597170857f610ce0e4ff8af8efc5010ab5dc205ec53da9759e0c5ad0d2fdbf3d116e1ad7a94629c2ee331e8ceb29417983c50,7d09ab7d0704e68376e933ccfbbaa0a2e8b10a270ce72a5add597ae66e692bd930b019cc9be30b25e859dd6ba5e3bd74a872588b1e14885bacaeca3b254cc86a,33ff08f3aae9132accec73805ec2cd98ce871779369d69d135a7e1fb75b653d415480be64116feda3176dc83b2d54cf8240f8c6f1d85168081efb4f013106cdb,921ce5123ccb3b891f9e1f314d84b8ca827c44dc2027dd4fd8272189ba076eba7c2cfe7e8f8a8915b263fc72232e5d5f193f15ff6aece5b9c55f4ca9c1887fcf,410494b95d3e453e46d0b8915765f2316fcf4db7d7eff0349fe674a6498d3aaa2c3bae2b4e3c7ec1a5d5fd90d88a1e9886914f4b8d039cd470d69642b0203b73)"
𝐡′ = interpret.(BigInt, hex2bytes.(split(h_str[2:end-1], ",")))

@test 𝐡′ == value.(𝐡)


# Step 2

#ns = outlen(prghash)
ns = CryptoGroups.bitlength(prghash)
ro = RO(rohash, ns)

tree = Tree((g, 𝐡, 𝐮, pk_tree, 𝔀, 𝔀′))
s = ro([ρ..., encode(tree)...])

# Step 3

prg = PRG(prghash, s)
𝐭 = rand(prg, BigInt, N; n = ne)
𝐞 = mod.(𝐭, BigInt(2)^ne)

# Step 4

ro_challenge = RO(rohash, nv)
tree_challenge = Tree((Leaf(s), τ_tree))
𝓿 = interpret(BigInt, ro_challenge([ρ..., encode(tree_challenge)...]))


# Step 5 
A = prod(𝐮 .^ 𝐞)

C = prod(𝐮) / prod(𝐡)
D = 𝐁[N] * inv(𝐡[1])^prod(𝐞)

@test A^𝓿 * A′ == g^k_A * prod(𝐡 .^ 𝐤_E)
@test C^𝓿 * C′ == g^k_C
@test D^𝓿 * D′ == g^k_D

@test 𝐁[1]^𝓿 * 𝐁′[1] == g^𝐤_B[1] * 𝐡[1]^𝐤_E[1]

for i in 2:N
    @test 𝐁[i]^𝓿 * 𝐁′[i] == g^𝐤_B[i] * 𝐁[i - 1]^𝐤_E[i]
end
