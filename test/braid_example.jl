import CryptoGroups: @ECGroup
import ShuffleProofs: ProtocolSpec, braid, verify, output_generator, output_members

g = @ECGroup{P_192}()

y = [4, 2, 3]
Y = g .^ y

verifier = ProtocolSpec(;g)
simulator = braid(Y, g, verifier)

@assert verify(simulator)

h = output_generator(simulator.proposition)
Y′ = output_members(simulator.proposition)

@assert sort(h .^ y) == sort(Y′) 
