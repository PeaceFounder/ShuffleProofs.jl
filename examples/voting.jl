using ShuffleProofs
import ShuffleProofs: PrimeGenerator, Enc, Dec, shuffle, ElGamal


sk = 123 # Only authorithy who do decryption would know

g = PrimeGenerator(3, 23)
options = [g, g^2, g^3] 
pk = g^sk

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
    proposition, secret = shuffle(bbord.ciphertexts_in, enc) # reencrypts and sorts output
    ciphertexts_out = proposition.𝐞′
    (; bbord..., ciphertexts_out)
end

####### Step 3. ########

bbord = let
    dec = Dec(sk)
    votes = dec(bbord.ciphertexts_out)
    (; bbord..., votes)
end


######### As last step we can tally the votes ############

for (i, o) in enumerate(options)
    s = 0
    for v in bbord.votes
        if v == o
            s += 1
        end
    end

    println("Choice $i received $s votes")
end
