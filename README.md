# ShuffleProofs.jl

Verifier for Verificatum generated NIZK proofs. 

## Current progress

  * [x] Binary tree parser
  * [x] Random oracles according to specification[^1] (according to verifier document)
  * [x] Independent generators (as generated from output `vmnv -t bas.h`)[^3] 
  * [x] Verifying ciphertexts shufling by decrypting with a secret key. (Tests correctness of ElGamal and correct input of the key)
  * [x] Verifying NIZK proof
    * [x] Generation of a proof to be parsed
    * [x] Parsing of proof ouputs into relevant variables.
    * [x] NIZK verifier. (Partially done using other reference)[^2][^ 4]
  * [x] Feed in the verifier in `WikstromTerelius.jl` to obtain a proof
  * [ ] Cleanup
    * [ ] Implement checking proof from multiple parties
    * [x] Adding code for F in the Verificatum verifier
    * [ ] Upstream to `CryptoGroups.jl`
    * [x] Remove `g` and `pk` from `ProtocolSpec`
    * [x] Consistent notation between `g, G, 𝓰, 𝓖`
    * [x] Adding `verbose::Bool` option to `verify` and evalueate the return value
    * [x] Abstract cryptographic operations in Haines proof and find a way to remove `_a, _b`
    * [ ] Strong random numbers in the proofs (pass as function argument)
    * [x] Make releavnt types concrete
    * [ ] `t₃` sensitive to randomization factors (to investigate).
    * [ ] Review possible overflow errors due to wrong integer types
  * [ ] Elliptic groups
  * [ ] Benchmarks
  * [ ] Storing the simulator in convinient directory structure
  * [ ] Storing the simulator in Verificatum understandable way
  * [ ] Decryption proofs
  * [ ] Documentation

[^1]: Wikstrom, “How To Implement A Stand-Alone Veriﬁer for the Veriﬁcatum Mix-Net.”
[^2]: Wikström, “A Commitment-Consistent Proof of a Shuffle.”
[^3]: Wikström, “User Manual for the Verificatum Mix-Net.”
[^4]: Haenni et al., “Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets.”
