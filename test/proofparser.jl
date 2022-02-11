using Test
using Verificatum: decode, convert, unmarshal_publickey, ElGamal, group, Generator, RO, crs, Hash, outlen, interpret, Tree, encode, Leaf, PRG, value, order, interpret, Leaf

h = Hash("sha256")

nr = 100
nv = 256
ne = 256

N = 10

#PUBLIC_KEY = "$(@__DIR__)/../ref/demo/dir/nizkp/default/FullPublicKey.bt"
PUBLIC_KEY = "$(@__DIR__)/../ref/demo/publicKey" # This one contains also a genrator and thus is more convinient
# A btter way would be to parse XML file and get the relevant parameters from there
CIPHERTEXTS = "$(@__DIR__)/../ref/demo/dir/nizkp/default/Ciphertexts.bt"
SHUFFLED_CIPHERTEXTS = "$(@__DIR__)/../ref/demo/dir/nizkp/default/ShuffledCiphertexts.bt"

PERMUTATION_COMMITMENT = "$(@__DIR__)/../ref/demo/dir/nizkp/default/proofs/PermutationCommitment01.bt"
PoS_COMMITMENT = "$(@__DIR__)/../ref/demo/dir/nizkp/default/proofs/PoSCommitment01.bt"
PoS_REPLY = "$(@__DIR__)/../ref/demo/dir/nizkp/default/proofs/PoSReply01.bt"




pk_tree = decode(read(PUBLIC_KEY))
pk, g = unmarshal_publickey(pk_tree)
𝓖 = group(g)
𝓰 = Generator{𝓖}


ρ = let
    version = "3.0.4"
    sid = "SessionID"
    auxsid = "default"

    s_H = "SHA-256"
    s_PRG = "SHA-256"
    s_Gq = "ModPGroup(safe-prime modulus=2*order+1. order bit-length = 511)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"
    
    data = (version, sid * "." * auxsid, UInt32(nr), UInt32(nv), UInt32(ne), s_PRG, s_Gq, s_H)

    tree = Tree(data)
    binary = encode(tree)

    ρ = h(binary)

    @test bytes2hex(ρ) == "15e6c97600bbe30125cbc08598dcde01a769c15c8afe08fe5b7f5542533159e9"

    ρ
end



### Independent generators for Verificatunm can be obtained as follows

𝐡 = let
    ns = outlen(h)
    ro = RO(h, ns)

    leaf = Leaf("generators")
    d = [ρ..., encode(leaf)...]

    s = ro(d) # The seed 

    prg = PRG(h, s)

    𝐡 = crs(𝓖, 10, prg, nr)


    h_str = "(1da949a3dfbeb316e9b225bc7d75b78d0ddd5e44fc382e74f3de95ad10eac798c4cc7be7e57d3afb259964c90fe7eb7e28a7673228d6b35a789dabd0d8351675,2937c1c4771b70c8b3dc935681aa8cef45ed24cf0c74cd2f9599ea5876850936168c5a092270d6396e634b9e46ab59836f509d0a68a65edc1426a87fd157798f,3767a5e108ecc067c31cd8bf544bcebfa3e3002f2af499ad3568e6fdb2775f4147bcf9485aeea3180b81aad365e3f4375c280941fdae10812bf1ba445030ab00,5c83d2d4f9cf3b3c2267788dd95a14740964e89f177690d06c43adfd137a101698c6bdc7ea9565fd0b18b3cfa89a2d5ea860de3912af4ffbae2c1f722912f6b9,2c453b082a201f3410d0b2906e7f2998a2c50d84f8eb0af017bf76124424bd385c15446eaad77b3ef1831798093f688331475c754f9e737d1485d80f0ef8289b,534897b93e335b0de44f3426aa6597170857f610ce0e4ff8af8efc5010ab5dc205ec53da9759e0c5ad0d2fdbf3d116e1ad7a94629c2ee331e8ceb29417983c50,7d09ab7d0704e68376e933ccfbbaa0a2e8b10a270ce72a5add597ae66e692bd930b019cc9be30b25e859dd6ba5e3bd74a872588b1e14885bacaeca3b254cc86a,33ff08f3aae9132accec73805ec2cd98ce871779369d69d135a7e1fb75b653d415480be64116feda3176dc83b2d54cf8240f8c6f1d85168081efb4f013106cdb,921ce5123ccb3b891f9e1f314d84b8ca827c44dc2027dd4fd8272189ba076eba7c2cfe7e8f8a8915b263fc72232e5d5f193f15ff6aece5b9c55f4ca9c1887fcf,410494b95d3e453e46d0b8915765f2316fcf4db7d7eff0349fe674a6498d3aaa2c3bae2b4e3c7ec1a5d5fd90d88a1e9886914f4b8d039cd470d69642b0203b73)"
    𝐡′ = interpret.(BigInt, hex2bytes.(split(h_str[2:end-1], ",")))

    @test 𝐡′ == value.(𝐡)

    𝐡
end

# Step 1

L_tree = decode(read(CIPHERTEXTS))
L′_tree = decode(read(SHUFFLED_CIPHERTEXTS))

𝔀 = convert(ElGamal{Generator{𝓖}}, L_tree)
𝔀′ = convert(ElGamal{Generator{𝓖}}, L′_tree)

μ_tree = decode(read(PERMUTATION_COMMITMENT))
𝐮 = convert(Vector{𝓰}, μ_tree)

τ_tree = decode(read(PoS_COMMITMENT))
𝐁, A′, 𝐁′, C′, D′, F′ = convert(Tuple{Vector{𝓰}, 𝓰, Vector{𝓰}, 𝓰, 𝓰, Tuple{𝓰, 𝓰}}, τ_tree)

σ_tree = decode(read(PoS_REPLY))
k_A, 𝐤_B, k_C, k_D, 𝐤_E, k_F = convert(Tuple{BigInt, Vector{BigInt}, BigInt, BigInt, Vector{BigInt}, 𝓰}, σ_tree)


# Step 2

ns = outlen(h)
ro = RO(h, ns)

#tree = Tree((g, 𝐡, 𝐮, pk_tree, 𝔀, 𝔀′))
#tree = Tree((g, 𝐡, 𝐮, pk, 𝔀, 𝔀′))
tree = Tree((g, 𝐡, 𝐮, pk_tree.x[2], 𝔀, 𝔀′))
s = ro([ρ..., encode(tree)...])


# Step 3

prg = PRG(h, s)
𝐭 = rand(prg, BigInt, N; n = ne)
𝐞 = mod.(𝐭, BigInt(2)^ne)

A = prod(𝐮 .^ 𝐞)

# Step 4

ro_challenge = RO(h, nv)
tree_challenge = Tree((Leaf(s), τ_tree))
𝓿 = interpret(BigInt, ro_challenge([ρ..., encode(tree_challenge)...]))

# Step 5 

C = prod(𝐮) / prod(𝐡)
D = 𝐁[N] * inv(𝐡[1])^prod(𝐞)

@show A^𝓿 * A′ == g^k_A * prod(𝐡 .^ 𝐤_E)
@show C^𝓿 * C′ == g^k_C
@show D^𝓿 * D′ == g^k_D

@show 𝐁[1]^𝓿 * 𝐁′[1] == g^𝐤_B[1] * 𝐡[1]^𝐤_E[1]

for i in 2:N
    @show 𝐁[i]^𝓿 * 𝐁′[i] == g^𝐤_B[i] * 𝐁[i - 1]^𝐤_E[i]
end
