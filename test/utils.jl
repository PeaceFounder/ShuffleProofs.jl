using Test
using Verificatum: tobig, int2bytes, bitlength, interpret

x = big(2)^100

@test tobig(int2bytes(x)) == x

x = 2^63 - 1

@test int2bytes(big(x)) == reinterpret(UInt8, [x])

y = UInt64(2)^63 + UInt64(1)

@test int2bytes(big(y)) == reinterpret(UInt8, [y])

z = UInt128(2)^128 - UInt128(1)

@test int2bytes(big(z)) == reinterpret(UInt8, [z])


u = 300
q = interpret(Vector{UInt8}, u)
#@test Int(frombytes(UInt64, copy(q))) == u

@test interpret(UInt64, copy(q)) == UInt64(u)

#@test frombytes(BigInt, copy(q)) == big(u)
@test interpret(BigInt, copy(q)) == big(u)


# Test cases can be generated on:
# https://compiler.javatpoint.com/opr/test.jsp?filename=BigIntegerBitLengthExample

x = 2323535352 ## Java says 32
@test bitlength(x) == bitlength(big(x)) == 32

x = 121232 # Java says 17
@test bitlength(x) == bitlength(big(x)) == 17

x = 23235323423415352
@test bitlength(x) == bitlength(big(x)) == 55

