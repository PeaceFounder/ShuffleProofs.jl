# - The needed time for proof generation is about the same as it is needed for verification
# - Required memory scales linearly. For N = 1 000 000 one needs around 16 GB of memory

using CryptoGroups
using OpenSSLGroups
import ShuffleProofs: shuffle, verify, load_verificatum_simulator, braid, Braid, save, load, Simulator
import SigmaProofs.ElGamal: Enc, Dec
import SigmaProofs.Verificatum: ProtocolSpec

#N = 1000000
N = 10000

g = @ECGroup{OpenSSLGroups.Prime256v1}()

verifier = ProtocolSpec(; g)

sk = 123
pk = g^sk

enc = Enc(pk, g)
𝐦 = [g^rand(2:order(g)) for i in 1:N] .|> tuple
𝐞 = enc(𝐦, rand(2:order(g), N))

@time simulator = shuffle(𝐞, g, pk, verifier)
@time verify(simulator)
