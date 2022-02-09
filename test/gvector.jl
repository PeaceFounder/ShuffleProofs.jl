using Test
using Verificatum: Generator, order, modulus, value, validate, Enc, Dec, 𝐙, ElGamal, group

q = 11
p = 2*q + 1  #safeprime(q)

#g^(div(p - 1), 2)

# Checking prime order

@test validate(Generator{𝐙/p}(3)) == true
@test validate(Generator{𝐙/p}(11)) == false

n = let 
    n = 0
    for i in 1:p
        validate(Generator{𝐙/p}(i)) && (n+=1)
    end
    n
end
@test n == q - 1


g = Generator{𝐙/p}(3)


#q = 17
#g = PrimeGenerator(3, q)

@test g*g^2 == g^3
@test (g^2)^2 == g^4
@test g^(order(g) + 1) == g

h = g^7

@test h*h^2 == h^3
@test (h^2)^2 == h^4
@test h^(order(h) + 1) == h


@test inv(g)*g^2 == g
@test (g^7)^6 == g^(7*6) # This is only true for a cyclic group
@test g*g*g == g^3 # Checking multiplication
@test g^2/g == g


### Testing some basics for vectors

#gv = GVector([g, g^2, g^3], g)
gv = [g, g^2, g^3]

@test gv .^ 2 == [g^2, g^4, g^6]
@test value.(gv .* gv) == [9, 12, 16]
@test g .* gv == gv .* g

### Now the ElGammal encrytption. 

sk = 5
pk = g^sk
r = 3
m = g^5
r2 = 4

enc = Enc(pk, g)
dec = Dec(sk)

@test dec(enc(m, r)) == m
@test enc(enc(m, r), r2) == enc(m, r + r2)


e = ElGamal([g, g, g], [g, g, g])

m = [g, g, g]
e′ = enc(m, [1, 2, 3])
@test dec(e′) == m


