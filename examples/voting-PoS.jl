# This version shows how verifiability for proof of shuffle is added

using ShuffleProofs
import ShuffleProofs: PrimeGenerator, Enc, Dec, shuffle, ElGamal, ProtocolSpec, verify, Shuffle

sk = 123 # Only authorithy who do decryption would know

g = PrimeGenerator(3, 23)
options = [g, g^2, g^3] 
pk = g^sk

verifier = ProtocolSpec(; g) # Some default parameters. In practice needs to be chosen carefully.

bbord = (;) # A representation of a buletinboard

######## Step 1. ########

bbord = let
    enc = Enc(pk, g)
    ciphertexts_in = ElGamal([enc(options[rand(1:3)], rand(1:10)) for i in 1:10])
    (; bbord..., ciphertexts_in)
end

######## Step 2. ########

bbord = let
    enc = Enc(pk, g)
    simulator = shuffle(bbord.ciphertexts_in, enc, verifier) # now returns simulator as verifier is added
    ciphertexts_out = simulator.proposition.𝐞′
    (; bbord..., ciphertexts_out, simulator.proof)
end

####### Step 3. ########

bbord = let
    dec = Dec(sk)
    votes = dec(bbord.ciphertexts_out)
    (; bbord..., votes)
end

######### As last step we can tally the votes ############

# Before counting we perform an audit that reencryption have happened honestly
proposition = Shuffle(g, pk, bbord.ciphertexts_in, bbord.ciphertexts_out)
@assert verify(proposition, bbord.proof, verifier)

for (i, o) in enumerate(options)
    s = 0
    for v in bbord.votes
        if v == o
            s += 1
        end
    end

    println("Choice $i received $s votes")
end
