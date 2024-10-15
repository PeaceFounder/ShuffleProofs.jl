using CryptoGroups
using ShuffleProofs
using SigmaProofs.ElGamal: Enc, Dec, ElGamalRow
using SigmaProofs.Verificatum: ProtocolSpec
import SigmaProofs.DecryptionProofs: Decryption, decrypt
import ShuffleProofs: shuffle, verify, Shuffle

sk = 123 # Only authorithy who do decryption would know

g = @ECGroup{P_192}()

options = [g, g^2, g^3] 
pk = g^sk

verifier = ProtocolSpec(; g) # Some default parameters. In practice needs to be chosen carefully.

bbord = (;) # A representation of a buletinboard

######## Step 1. ########

bbord = let
    enc = Enc(pk, g)
    ciphertexts_in = [enc(options[rand(1:3)], rand(1:10)) |> ElGamalRow for i in 1:10]
    (; bbord..., ciphertexts_in)
end

######## Step 2. ########

bbord = let
    enc = Enc(pk, g)
    simulator = shuffle(bbord.ciphertexts_in, enc, verifier) # now returns simulator as verifier is added
    ciphertexts_out = simulator.proposition.𝐞′
    shuffle_proof = simulator.proof
    (; bbord..., ciphertexts_out, shuffle_proof)
end

####### Step 3. ########

bbord = let
    simulator = decrypt(g, bbord.ciphertexts_out, sk, verifier)
    votes = simulator.proposition.plaintexts
    dec_proof = simulator.proof
    (; bbord..., votes, dec_proof)
end

######### As last step we can tally the votes ############

# Before counting we perform an audit that reencryption have happened honestly
proposition_shuffle = Shuffle(g, pk, bbord.ciphertexts_in, bbord.ciphertexts_out)
@assert verify(proposition_shuffle, bbord.shuffle_proof, verifier)

proposition_dec = Decryption(g, pk, bbord.ciphertexts_out, bbord.votes)
@assert verify(proposition_dec, bbord.dec_proof, verifier)

for (i, o) in enumerate(options)
    s = 0
    for (v,) in bbord.votes
        if v == o
            s += 1
        end
    end

    println("Choice $i received $s votes")
end
