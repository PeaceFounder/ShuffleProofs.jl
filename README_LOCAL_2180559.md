# ShuffleProofs.jl

Cryptography is often looked at as a tool to secure and make communications confidential. It only requires to have a digital signature algorithm (DSA), Diffie Hellman key exchange (computation) and a good block cypher to satisfy security requirements of 99% (metaphorically) of current online marketplaces and internet banking. However, security with those tools comes with a price of privacy and the necessity to trust the other end to keep your transactions private. 

A much more difficult case is present for systems that do require a high order of privacy and transparency, such as voting and auctions where an authority can not be blindly trusted neither with security nor privacy. Complex multiparty protocols can be structured so that security and privacy do not lie in hands of few. However eliminating the effects of dishonest participants do require synchronous interactions between participants and thus are not scalable.  

Cryptography does offer an alternative known as zero-knowledge proofs (ZKP), which can often eliminate the need for synchronous interactions between participants to obtain an honest result. An excellent example is the zero-knowledge proof of shuffle, which we shall illustrate with a simple voting system. 

(Actually, arguments, but a common reference string can be constructed in a verifiably random way)

It's best to illustrate it with the ElGamal cryptosystem. Let's say that officials have set up keypair `sk`, `pk = g^sk` and let everyone know `g, pk`. 

1. The voter selects an option corresponding to a message `m` and encrypts it with a freely secretly chosen randomization factor `r` and obtains a tuple `c <- (g^r, m*pk^r)`, which they submit to a bulletin board. 
2. The votes are re-encrypted and shuffled
   a. each received ciphertext is re-encrypted as `c′ <- (c[1]*g^p, c[2] * pk^p)
   `b. all re-encrypted ciphertexts are sorted constituting a shuffle and published to a buletinboard
3. The authority who knows the secret key `sk` (`pk = g^sk`) decrypts each ciphertext `c′` as `m <- c′[2] * c′[1]^(-sk)` and publishes that to a bulletin board.

This scheme, however, does pose serious drawbacks for election integrity. If the election authority is malicious, it can deviate from the re-encryption procedure in step 2. omit and substitute their own desired ciphertexts. Similarly, in the third step, nothing prevents the adversary from publishing their own desired decryption at step 3. 

Fortunately, zero-knowledge proofs are here to make such a system verifiable. Even if the adversary controlled, all election authorities would not be able to add, remove or modify votes. 

## The example situation

Let's consider the vorting system above. To simplify the ilustration we shall use `let ... end` block as represenation for privacy barrier between different computers.; `bbord` for a messages published to a public buletinboard appart from protocol setup parameters `g, pk`; `options` shall represent valid set of ellection candidates which voters can choose from and `rand` function their free will. Then the voting system can be represented as a code as follows:

```
# This code yet to be tested
using ShuffleProofs

sk = 123 # Only authorithy who do decryption would know

g = PrimeGenerator(23)
options = [g, g^2, g^3] 
pk = g^sk

bbord = (;) # A representation of a buletinboard

######## Step 1. ########

bbord = let
    enc = Enc(pk, g)
    ciphertexts_in = [enc(options[rand(1:3)], rand(1:10)) for i in 1:3]
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
```
where ellection outcome is afterwards obtainned by tallying like `count(x-> x == options[1], bbord.votes)`. Alternativelly homomorphic tallying could also be used making easier to airgap the system with secret key. 

(A confused reader may assert that authorithy knowing secret key knows how every participant had voted. However this is not so bad in practice. The last step of decryption can be done between multiple parties so no single party knows the full secret key. Alternativelly the decryption can hapen in gapless computer put in a Faraday cage only for ciphertexts which come out of reencryption step 2. A curios reader may dwelve into details Helios voting system after which the example is modeled)

Although the all information is accesable to a buletinboard we can not convince the voters that their vote have been properly counted and that adversary as corrupt authorithy or malware had not deviated from honest shuffling or decription (steps 2 or 3) where it can add, modify or remove the votes.

## Proving a correct shuffle

When we did a shuffle at step 2, the `shuffle` function returned two arguments: `proposition` and `secret`. The `proposition` contains all information about the statement whose truth should be asserted by a piece of evidence. The `secret` contains re-encryption factors and permutations. This can be used as evidence to validate the truth of the statement:

```
verify(proposition, secret)
```

However, if `secret` is used as evidence, it can't be made public; otherwise, it would violate the anonymity of the voters. Instead, we really want to prove that we know a `secret` such that `verify(proposition, secret) == true`, which in the literature is known as zero-knowledge proofs and, in particular, proofs of shuffle.

Currently, WikstromTerelius proof of shuffle is the most widely used protocol implemented in Verificatum, CHVote and has been used to add verifiability for remote electronic voting systems used in Estonia, Norway, Switzerland and others[^5]. Verification, in particular, has a diligently written specification encouraging anyone willing to implement an independent verifier[^1] so that proofs would not need to be trusted at face value. On the other hand, Haines[^4] provides the most concise pseudocode for anyone willing to implement the prover but does deviate with verifier implementation from the Verifiactum protocol. The `ShuffleProofs.jl` implements a Verificatum verifier and compatible prover (so that the original Java code for Verificatum, in principle, could validate the integrity of the statement).

To prove a statement for a corresponding proposition, it is necessary to instantiate a verifier which challenges the prover. A non-interactive zero-knowledge verifier compatible with Verifiactum can be initiated as:
```
verifier = ProtocolSpec(; g) 
```
It contains details on how independent basis vectors are chosen in a verifiable way, how challenges are computed from provers outputs like hash function to be used for random oracles and pseudo-random number generators, and how many bits are needed for random numbers. With such a verifier, a proof then can be constructed easily as:
```
proof = prove(proposition, secret, verifier)
```

Now finally, the proposition that no votes have been added, modified (spoiled) or removed at step 2. can be verified as:
```
verify(proposition, proof, verifier)
```
where `proof` and `verifier` can be published on the bulletin board along with `proposition` so that everyone can verify the integrity of elections. 

Lastly, the `SuffleProofs.jl` implements a `shuffle(e::ElGamal, g, pk, verifier::Verifier)::Simulator`, which does the proof generation at the time of shuffling for convenience. The returned type then is `Simulator` which contains three fields `simulator.proposition` (discussed earlier), `simulator.verifier` and lastly, the proof as `simulator.proof`. The simulator contains all necessary information and can be published on the bulletin board (The exact way duplication of data is avoided up to the user of the library to decide). 

## Verifying Verificatum generated proof of shuffle

Verification of Verifiactum generated proof is quite simple. First, a simulator needs to be generated, which can be done as follows:
```
simulator = load_verificatum_simulator(DEMO_DIR)
```
whihc parses `XML`, `protocolSpec.xml` and other relevant files encoded in binary tree notation as specified in the Verificatum verifier document. When loaded, the simulator can be verified:
```
verify(simulator)
```

## Customizing verifier

Originally, I implemented Haines[^4] described prover and verifier first directly resembling pseudocode and then implemented Verificatum verifier[^1]. Unfortunately, implementing the Verificatum prover from the research papers was not within my capabilities, so I focused on merging both implementations. It, however, became clear quickly that it would be highly cumbersome to specify challenges as multiple function arguments. To alleviate that, I made a verifier as an entry point of the finite state machine (FSM). 

Every verifier state does have two methods `step(verifier::Verifier, msg)::Verifier` where `msg` is new commitments from prover at a particular stage of execution. The other method is `challenge(verifier::Verifier)`, which returns a challenge to the prover upon which the protocol's security lies. 

For example, let's consider a verifier, `HonestVerifier`, which has chosen all challenges in advance. Although it is insecure, it will help to illustrate the point. We shall use the `PoSChallenge` type, which runs the last verification step after which challenges from proof have been computed. The resulting implementation can be represented as:
```
import ShuffleProofs: step, challenge, PoSChallenge

@enum VState Config Init PermCommit PoSCommit

struct HonestVerifier{T} <: Verifier
    challenge::PoSChallenge
end

HonestVerifier(challenge::PoSChallenge) = HonestVerifier{Config}(challenge)
HonestVerifier{T}(verifier::HonestVerifier) where T = HonestVerifier{T}(verifier.challenge)

PoSChallenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge

step(verifier::HonestVerifier{Config}, proposition::Shuffle) = HonestVerifier{Init}(verifier)
step(verifier::HonestVerifier{Init}, 𝐜) = HonestVerifier{PermCommit}(verifier)
step(verifier::HonestVerifier{PermCommit}, 𝐜̂, t) = HonestVerifier{PoSCommit}(verifier)

challenge(verifier::HonestVerifier{Init}) = (verifier.challenge.𝐡, verifier.challenge.𝐡[1])
challenge(verifier::HonestVerifier{PermCommit}) = verifier.challenge.𝐮
challenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge.c

```
`HonestVerifier` here is a parametrized struct with enums, but in practice each state does have it's own relevant variables and makes sense to represent them with their own types. For example, see Verificatum verifier implementation in the the `src/vverifier.jl`. 

The generality of the verifier can easily be extended to satisfy all kinds of variations available of WikstromTerelius proof of shuffle. For instance, an interactive protocol can be implemented in each challenge method to read from IO. Or verifier for `CHVote`, which computes generator basis differently, can be supported by subtyping verifier. 

# Limitations

  * [ ] Only prime groups are currently supported (FIPS implementations of elliptic groups are comming)
  * Only proof of shuffle can be verified for Verificatum protocol. Implementing verificaion of correct decryption in multiparty setting has a low priority now.
  * Current Julia implementation is probably slower than the Java one as little care have been taken to make code type stable and minimize the amount of allocations. 

# Current progress

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
    * [x] Strong random numbers in the proofs (pass as function argument)
    * [x] Make releavnt types concrete
    * [x] `t₃` sensitive to randomization factors (to investigate).
  * [ ] Elliptic groups
      * [x] Implementation of fields Fp and F2 (done internally)
      * [x] Elliptic curve point multiplication by an integer (done internally; tested on P-192 curve)
      * [ ] Upstream and expose curve implementations in `CryptoGroups.jl`
      * [ ] Basis generation
      * [ ] Test that prover and verifier works also with elliptic groups
      * [ ] Field, Point encoding according to X9.62 spec
      * [ ] Parser for cyphertexts
  * [ ] Benchmarks
  * [ ] Storing the simulator in convinient directory structure
  * [ ] Storing the simulator in Verificatum understandable way
  * [ ] Decryption proofs
  * [ ] Documentation
    * [x] Put a first draft of README.md
    * [ ] Add some docstrings in the code
    * [ ] Set up docummenter
    * [ ] Add examples and make them run

[^1]: Wikstrom, “How To Implement A Stand-Alone Veriﬁer for the Veriﬁcatum Mix-Net.”
[^2]: Wikström, “A Commitment-Consistent Proof of a Shuffle.”
[^3]: Wikström, “User Manual for the Verificatum Mix-Net.”
[^4]: Haenni et al., “Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets.”
[^5]: verificatum.org
