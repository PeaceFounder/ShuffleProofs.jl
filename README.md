# Verificatum.jl

Verifier for Verificatum generated NIZK proofs. 

## Current progress

  * [x] Binary tree parser
  * [x] Random oracles according to specification[^1] (according to verifier document)
  * [x] Independent generators (as generated from output `vmnv -t bas.h`)[^3] 
  * [ ] Verifying ciphertexts shufling by decrypting with a secret key. (Tests correctness of ElGamal and correct input of the key)
  * [ ] Verifying NIZK proof
    * [x] Generation of a proof to be parsed
    * [ ] Parsing of proof ouputs into relevant variables.
    * [ ] NIZK verifier. (Partially done using other reference)[^2][^ 4]
  * [ ] Upstream to `CryptoGroups.jl`

[^1]: Wikstrom, “How To Implement A Stand-Alone Veriﬁer for the Veriﬁcatum Mix-Net.”
[^2]: Wikström, “A Commitment-Consistent Proof of a Shuffle.”
[^3]: Wikström, “User Manual for the Verificatum Mix-Net.”
[^4]: Haenni et al., “Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets.”
