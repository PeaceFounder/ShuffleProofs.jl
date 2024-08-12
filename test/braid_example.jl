import CryptoGroups: curve, ECGroup, generator, concretize_type
import ShuffleProofs: ProtocolSpec, braid, verify, output_generator, output_members

_curve = curve("P_256")
G = concretize_type(ECGroup, _curve)
g = G(generator(_curve))

y = [4, 2, 3]
Y = g .^ y

verifier = ProtocolSpec(;g)
simulator = braid(g, Y, verifier)

@assert verify(simulator)

h = output_generator(simulator.proposition)
Y′ = output_members(simulator.proposition)

@assert sort(h .^ y) == sort(Y′) 
