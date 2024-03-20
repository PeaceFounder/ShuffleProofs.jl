#!/bin/bash

# Generates a set of outputs which I can use to validate the implementation

# So the short version also works 
#GROUP2="ModPGroup(safe-prime modulus=2*order+1. order bit-length = 511)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b30100000040300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"


GROUP="ModPGroup(safe-prime modulus=2*order+1. order bit-length = 511)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f757000000000040100000041009a91c3b704e382e0c772fa7cf0e5d6363edc53d156e841555702c5b6f906574204bf49a551b695bed292e0218337c0861ee649d2fe4039174514fe2c23c10f6701000000404d48e1db8271c17063b97d3e7872eb1b1f6e29e8ab7420aaab8162db7c832ba1025fa4d2a8db4adf69497010c19be0430f7324e97f201c8ba28a7f1611e087b3010000004100300763b0150525252e4989f51e33c4e6462091152ef2291e45699374a3aa8acea714ff30260338bddbb48fc7446b273aaada90e3ee8326f388b582ea8a073502010000000400000001"


#GROUP="com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536"

# publicKey and ciphertexts are now imported from outside

# vmnd -pkey "$GROUP" publicKey 
# vmnd -ciphs publicKey 10 ciphertexts

# Public key and ciphertexts can now be imported from local storage

# TODO: try to generate my own public key [Done]
# TODO: parse ciphertexts and try to decrypt them.

vmni -prot -sid "SessionID" -name "Ellection" -nopart 1 -thres 1 -pgroup "$GROUP" stub.xml

vmni -party -name "Santa Claus" stub.xml privInfo.xml protInfo.xml

vmn -setpk privInfo.xml protInfo.xml publicKey # Does it do anything?

vmn -shuffle privInfo.xml protInfo.xml ciphertexts ciphertextsout

# TODO: try to decrypt ciphertextsout (compare with original decryption)

vmnv -shuffle protInfo.xml dir/nizkp/default

mkdir tv

vmnv -shuffle -t "bas.h" protInfo.xml dir/nizkp/default > tv/h
vmnv -shuffle -t "bas.pk" protInfo.xml dir/nizkp/default > tv/pk # Just for a simple test that parsing worked
vmnv -shuffle -t "der.rho" protInfo.xml dir/nizkp/default > tv/rho
vmnv -shuffle -t "par.n_r" protInfo.xml dir/nizkp/default > tv/n_r
vmnv -shuffle -t "par.s_PRG" protInfo.xml dir/nizkp/default > tv/s_PRG

# Two directories are generated: dir and httproot

 #      CCPoS - Commitment-consistent proof of a shuffle.
 #     CCPoS.s - CCPoS. Seed to derive batching vector in hexadecimal notation.
 #    CCPoS.v - CCPoS. Integer challenge in hexadecimal notation.
 #         Dec - Proof of correct decryption.
 #       Dec.s - Dec. Seed to derive batching vector in hexadecimal notation.
 #       Dec.v - Dec. Integer challenge in hexadecimal notation.
 #         PoS - All test vectors for proofs of shuffles.
 #       PoS.A - PoS. Batched permutation commitment.
 #      PoS.Ap - PoS. Commitment components.
 #       PoS.B - PoS. Commitment components.
 #      PoS.Bp - PoS. Commitment components.
 #       PoS.C - PoS. Derived intermediate values.
 #      PoS.Cp - PoS. Commitment components.
 #       PoS.D - PoS. Derived intermediate values.
 #      PoS.Dp - PoS. Commitment components.
 #       PoS.F - PoS. Batched input ciphertexts.
 #      PoS.Fp - PoS. Commitment components.
 #     PoS.k_A - PoS. Reply components.
 #     PoS.k_B - PoS. Reply components.
 #     PoS.k_C - PoS. Reply components.
 #     PoS.k_D - PoS. Reply components.
 #     PoS.k_E - PoS. Reply components.
 #     PoS.k_F - PoS. Reply components.
 #       PoS.s - PoS. Seed to derive batching vector in hexadecimal notation.
 #       PoS.v - PoS. Integer challenge in hexadecimal notation.
 #        PoSC - Proof of shuffle of commitments.
 #      PoSC.s - PoSC. Seed to derive batching vector in hexadecimal notation.
 #      PoSC.v - PoSC. Integer challenge in hexadecimal notation.
 #         bas - Basic inputs.
 # bas.C_omega - Space of ciphertexts.
 #     bas.L_0 - Original list of ciphertexts.
 #     bas.L_l - Intermediate list of ciphertexts.
 # bas.M_omega - Space of plaintexts.
 # bas.R_omega - Space of randomness.
 #       bas.h - Independent generators.
 #      bas.pk - Joint public key.
 #     bas.x_l - Secret keys of some mix-servers (null if a key is not present).
 #     bas.y_l - Public keys of threshold number of mix-servers.
 #         der - Derived values.
 #     der.rho - Derived prefix bytes to all random oracle queries.
 #         par - Parameters.
 #     par.N_0 - Number of ciphertexts for which precomputation is done.
 #       par.k - Number of mix-servers.
 #  par.lambda - Threshold number of parties needed to decrypt.
 #     par.n_e - Bit length of components in random vectors used for batching.
 #     par.n_r - Bit length of random paddings.
 #     par.n_v - Bit length of challenges.
 #   par.omega - Width of ciphertexts.
 #    par.s_Gq - Description of underlying group.
 #     par.s_H - Description of hash function used to implement random oracles.
 #   par.s_PRG - Description of PRG used for batching.
 #     par.sid - Session identifier of mix-net.
 # par.version - Version.
 #           u - Permutation commitment.

