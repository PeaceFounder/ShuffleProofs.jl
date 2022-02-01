using Test
using Verificatum: Hash, PRG, RO



h = Hash("sha256")

s = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")


prg = PRG(h, s)

### The expansion then can be split into bytes as needed

## An optional argument for BigInt as it is unbound type. 


# As can be found on page 36 in:
# Wikstrom, “How To Implement A Stand-Alone Veriﬁer for the Veriﬁcatum Mix-Net.”
@test bytes2hex(rand(prg, UInt8, 128)) == "70f4003d52b6eb03da852e93256b5986b5d4883098bb7973bc5318cc66637a8404a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d244"


ro = RO(h, 65)
x = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
@test bytes2hex(ro(x)) == "001a8d6b6f65899ba5"


x = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
ro = RO(h, 261)
@test bytes2hex(ro(x)) == "1c04f57d5f5856824bca3af0ca466e283593bfc556ae2e9f4829c7ba8eb76db878"
