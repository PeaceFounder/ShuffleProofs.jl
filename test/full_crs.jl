using Test
using Verificatum: Tree, Hash, Node, Leaf, tobig, decode, encode, outlen


### Let's make the setup complete. From repo I ahve a following public parameters:
nr = 100
h = Hash("sha256")

ρ = "15e6c97600bbe30125cbc08598dcde01a769c15c8afe08fe5b7f5542533159e9"

group_spec = "00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"

h_str = "(1da949a3dfbeb316e9b225bc7d75b78d0ddd5e44fc382e74f3de95ad10eac798c4cc7be7e57d3afb259964c90fe7eb7e28a7673228d6b35a789dabd0d8351675,2937c1c4771b70c8b3dc935681aa8cef45ed24cf0c74cd2f9599ea5876850936168c5a092270d6396e634b9e46ab59836f509d0a68a65edc1426a87fd157798f,3767a5e108ecc067c31cd8bf544bcebfa3e3002f2af499ad3568e6fdb2775f4147bcf9485aeea3180b81aad365e3f4375c280941fdae10812bf1ba445030ab00,5c83d2d4f9cf3b3c2267788dd95a14740964e89f177690d06c43adfd137a101698c6bdc7ea9565fd0b18b3cfa89a2d5ea860de3912af4ffbae2c1f722912f6b9,2c453b082a201f3410d0b2906e7f2998a2c50d84f8eb0af017bf76124424bd385c15446eaad77b3ef1831798093f688331475c754f9e737d1485d80f0ef8289b,534897b93e335b0de44f3426aa6597170857f610ce0e4ff8af8efc5010ab5dc205ec53da9759e0c5ad0d2fdbf3d116e1ad7a94629c2ee331e8ceb29417983c50,7d09ab7d0704e68376e933ccfbbaa0a2e8b10a270ce72a5add597ae66e692bd930b019cc9be30b25e859dd6ba5e3bd74a872588b1e14885bacaeca3b254cc86a,33ff08f3aae9132accec73805ec2cd98ce871779369d69d135a7e1fb75b653d415480be64116feda3176dc83b2d54cf8240f8c6f1d85168081efb4f013106cdb,921ce5123ccb3b891f9e1f314d84b8ca827c44dc2027dd4fd8272189ba076eba7c2cfe7e8f8a8915b263fc72232e5d5f193f15ff6aece5b9c55f4ca9c1887fcf,410494b95d3e453e46d0b8915765f2316fcf4db7d7eff0349fe674a6498d3aaa2c3bae2b4e3c7ec1a5d5fd90d88a1e9886914f4b8d039cd470d69642b0203b73)"

𝐡 = tobig.(reverse.(hex2bytes.(split(h_str[2:end-1], ","))))

# For the begining I can load the generator

tree = decode(group_spec)

(group_name, (p, q, g, e)) = convert(Tuple{String, Tuple{BigInt, BigInt, BigInt, UInt32}}, tree)

@test p == 2*q + 1
@test powermod(g, q + 1, p) == g

# I can now also test that the generators are correcly parsed

for hi in 𝐡
    @test powermod(hi, q + 1, p) == hi
end

# Let's now create functions for primitives

struct PRG
    h::Hash
    s::Vector{UInt8}
end

(prg::PRG)(i::UInt32) = prg.h([prg.s..., reverse(reinterpret(UInt8, UInt32[i]))...])


function Base.getindex(prg::PRG, range)
    (; start, stop) = range
    
    # I will be rather primitive on the matter here. 
    
    a = outlen(prg.h) ÷ 8 # which just gives 32

    K = div(stop, a, RoundUp) - 1

    r = UInt8[]
    
    for i in UInt32(0):UInt32(K)
        ri = prg(i)
        append!(r, ri)
    end
    
    return r[range]
end

# We are now in a position to make a test

s = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
prg = PRG(h, s)

@test bytes2hex(prg[1:128]) == "70f4003d52b6eb03da852e93256b5986b5d4883098bb7973bc5318cc66637a8404a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d244"

# Random oracles are similar beasts

struct RO
    h::Hash
    n_out::Int
end

zerofirst(x, n) = (x << n) >> n # Puts first n bits of a number x to zero. 

function (ro::RO)(d::Vector{UInt8})
    (; h, n_out) = ro

    nb = reinterpret(UInt8, UInt32[n_out])
    s = h([reverse(nb)...,d...]) # Numbers on Java are represented in reverse
    prg = PRG(h, s)

    a = prg[1:div(n_out, 8, RoundUp)]
    
    if mod(n_out, 8) != 0 
        a[1] = zerofirst(a[1], 8 - mod(n_out, 8))
    end

    return a
end

ro = RO(h, 65)
d = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
@test bytes2hex(ro(d)) == "001a8d6b6f65899ba5"

ro = RO(h, 261)
d = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
@test bytes2hex(ro(d)) == "1c04f57d5f5856824bca3af0ca466e283593bfc556ae2e9f4829c7ba8eb76db878"


# Now the last function is the derivation of coresponding generators

bitlength(p) = Int(ceil(log2(p)))


function crs(p::BigInt, N::Int, prg::PRG, nr::Int)
    
    q = (p - 1) ÷ 2 # Because of safe primes: p = 2*q + 1

    np = bitlength(p)

    M = div(np + nr, 8, RoundUp) # bytes for each number

    total = M * N

    #@infiltrate
    𝐫 = prg[1:total]
    
    𝐮 = reshape(𝐫, (M, N)) 

    #𝐭 = [tobig(𝐮[:, i]) for i in 1:N]
    𝐭 = [tobig(reverse(𝐮[:, i])) for i in 1:N]

    𝐭′ = mod.(𝐭, big(2)^(np + nr))

    𝐡 = powermod.(𝐭′, (p - 1) ÷ q, p)

    return 𝐡
end


# Now the test is a bit interesting


ns = outlen(h)
ro = RO(h, ns)

leaf = Leaf("generators")
d = [hex2bytes(ρ)..., encode(Vector{UInt8}, leaf)...]

s = ro(d) # The seed 

prg = PRG(h, s)

𝐡′ = crs(p, 10, prg, nr)

for hi in 𝐡′
    @test powermod(hi, q + 1, p) == hi
end

@test 𝐡 == 𝐡′
