module ECBasisTest

using Test
import CryptoGroups: ECGroup, concretize_type, value, Specs
import CryptoPRG.Verificatum: HashSpec, ROPRG

tobig(x) = parse(BigInt, bytes2hex(reverse(x)), base=16)
interpret(::Type{BigInt}, x::Vector{UInt8}) = tobig(reverse(x))
interpret(::Type{Vector{UInt8}}, x::Integer) = reverse(reinterpret(UInt8, [x]))

function interpret(::Type{T}, x::AbstractString) where T
    
    if mod(length(x), 2) == 1
        x = "0" * x
    end
    
    bytes = hex2bytes(x)

    return interpret(T, bytes)
end


function leaf(x::Vector{UInt8})

    N = UInt32(length(x))

    LEAF = UInt8(1)

    Nbin = interpret(Vector{UInt8}, N)
    bin = UInt8[LEAF, Nbin..., x...]

    return bin
end

leaf(x::String) = leaf(Vector{UInt8}(x))

### Let's make the setup complete. From repo I ahve a following public parameters:
nr = 100
rohash = HashSpec("sha256")
prghash = HashSpec("sha256")

ρ = hex2bytes("355806458d6cd42655a52be242705c8e824584ccdb6b1c016cad36c591413de4")

# Need to unmarchal this into numbers

# This one I need to validate in ShuffleProofs.jl
#group_spec = "com.verificatum.arithm.ECqPGroup(P-256)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323536" 


h_str = "((760858b410b6fd5b5329457488f93eefd76f74753fc018a88a04e0d1015ccced, 750609534db7741d4ffd1f721dfca0cb3a190fba73ad71652999b6846ff6cc6e),(1bb070702fd72beb7d1d019c46bd55db16b510fcaf56ad1cf5d8f2ab46e47703, 017b045263708a3a42b81c67f2aeb0750b90693d7f177f40bb0ab71aaca2a7c7),(cca2a9b54997b340951ff8a80caffd332fc2d18cdbf10b29863960ead8754297, 2536dab68d208a689845b597bfa1cfd06ae859d381babf4afefbc49893dc55de),(19c089238d119fb04034c61481f0032cb9746b569e4ce6fdf9f8bfb019b9c300, 2737321900c4be759486508e4bec21e1850792bbbc98bc0207b992079a46c4ea),(150beafe47a388cbf6b7b62af3de801cf5f39b6c2aa07df15a14870195325d66, 4f0d59a61036e071600050a896a7206bd660b675793ae0bfefcc594157821fa9),(58d18ce2c66aedd896031d6cd791eed6cbb4fe38c805971e465ea44ff436ad, 5e93996474cf43b5f2e02c077334d2ac16120385b67f193d26dd4748252aaeb2),(cb44deb0a87c8154c7f49a3d128c60bf32825e391d09a1c604a2a8d35b110e58, 33d3316d12f822e047f48520ee774d558d3edbbfa9f5d782023f4aa22683873d),(9d378038b627c4ad3e97726bdd7189fdca7b964d842bb5b0b9eafccd84baced7, 1fb99e6bb8bdc5518dd1c8a06a925a9999e72bf74664ee9c2df76959af9b95ef),(5e6c2170c6176600bedb2efd5ef02a72a7561142754f29217b4ebfcc39fe725b, 3c1ff9ce2ac3516928cb2486e7426851ef7fd50d492907494bb275b11081d41a),(b161c3cb307823857de3c032b7c8570a93ceda3f4d8d53837907b517cba92ac9, 27736dfef353719a3d4d7b7a004e62a9e39a32ddff6a525b80b8023bfac469dd),)"


a = split(replace(h_str, "("=>"", ")"=>"", " "=>""), ",")[1:end-1]
numbers = interpret.(BigInt, a)
𝐡 = collect(zip(numbers[1:2:end], numbers[2:2:end]))


d = [ρ..., leaf("generators")...]
roprg = ROPRG(d, rohash, prghash)
prg = roprg(UInt8[]) # d is a better argument than x

G = concretize_type(ECGroup, Specs.Curve_P_192)


𝐡′ = rand(prg, Specs.Curve_P_256, 10; nr)

@test 𝐡 == 𝐡′

end
