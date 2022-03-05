using Test
import ShuffleProofs: PrimeGenerator, validate, order, Enc, Dec, modulus, value


q = 11
p = 2*q + 1

@test validate(PrimeGenerator(3, p)) == true
@test validate(PrimeGenerator(11, p)) == false

n = let 
    n = 0
    for i in 1:p
        validate(PrimeGenerator(i, p)) && (n+=1)
    end
    n
end
@test n == q - 1



g = PrimeGenerator(3, p)

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



### Let's test ElGammal encryption


sk = 5
pk = g^sk
r = 3
m = g^5
r2 = 4

enc = Enc(pk, g)
dec = Dec(sk)

@test dec(enc(m, r)) == m
@test enc(enc(m, r), r2) == enc(m, r + r2)

### Shuffle generation

sk = 5
pk = g^sk

enc = Enc(pk, g)


m_vec = [g, g^2, g^3]
e_vec = enc.(m_vec, 1) # It is not necessary to randomize encryption for user. It however does make sense to do so for intermidiatery who collects messages from users to not reveal internals. 

### The shuffling
r_vec = Int[1, 2, 3]

e_enc = enc.(e_vec, r_vec)
ψ = sortperm(e_enc)
sort!(e_enc)

@test sort(dec.(e_enc)) == sort(m_vec)


m_vec = [g, g^2, g^3]
e_vec = enc.(m_vec, 1)



