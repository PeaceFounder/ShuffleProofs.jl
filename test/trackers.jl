# WIP on ensuring receipt freeness in pseudonymous voting
# Currently votes are not included and only tracxkers are considered. Implementing votes would require
# extending shuffle proof with ElGamalRow that could contain multiple elgamal elements
# The reuse of secret key x in decryption may expose it in ZKP. We need to be careful here!
using Test
import CryptoGroups: @ECGroup
import ShuffleProofs: ProtocolSpec, braid, verify, decrypt

g = @ECGroup{P_192}()
verifier = ProtocolSpec(;g)

x = 31

gx = g^x
gx3 = g^(x^3)

# Preperation: Calculating eligiable member pseudonyms for each generator that can be made public
# so collection of eligiable votes could be enforced publically (result (g, Y), (gx, Yx), (gx3, Yx3) and ZKP)

y = [2, 3, 4, 5, 6, 7, 8] 
Y = g .^ y #[g^i for i in y]      

simulator_x = braid(g, Y, verifier; x)

Yx = simulator.proposition.members

# A direct way going from Yx to Yx3 would is desirable
# A simple exponentitation to go from Yx2 to Yx3 exposes knowledge 
# if a seccret owner previously had cast a vote
simulator_x2 = braid(g, Yx, verifier; x) 
Yx2 = simulator_x2.proposition.members 

simulator_x3 = braid(g, Yx2, verifier; x)
Yx3 = simulator_x3.proposition.members

#simulator_x3 = decrypt(g, Yx2, x) # the link between Yx2 and Yx3 is exposed. 
# Yx3 = simulator_x3.𝔀′

@test sort(gx .^ y) == sort(Yx)
@test sort(gx3 .^ y) == sort(Yx3)

# Preperation of trackers that are voters pseudonyms that cast votes

g_trackers = [g^y[1], g^y[2], g^y[5]]
gx_trackers = [gx^y[1], gx^y[3], gx^y[6]]
gx3_trackers = [gx3^y[1], gx3^y[2], gx3^y[6], gx3^y[7]]

# Counting procedure

colisions = Dict{String, Vector}()

simulator_gt = braid(g, g_trackers, verifier; x)
simulator_gxt = braid(g, gx_trackers, verifier; x)
simulator_gt_exp = decrypt(g, simulator_gt.proposition.members, x)

gx2a_trackers = simulator_gt_exp.proposition.𝔀′
gx2b_trackers = simulator_gxt.proposition.members

colisions["gx2"] = intersect(gx2a_trackers, gx2b_trackers)

gx2_trackers = union(gx2a_trackers, gx2b_trackers)

#g_trackers = [g^y[1], g^y[2], g^y[5]]


