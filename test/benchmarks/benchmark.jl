using CryptoGroups
using OpenSSLGroups
using ShuffleProofs
using ShuffleProofs: verify
using SigmaProofs.Verificatum: marshal_s_Gq
using Base: @elapsed

include("barplot.jl")

function generate_sample(dir::String, g::Group, N::Int; width::Int = 1)

    group = marshal_s_Gq(g).x |> String

    cd(dir) do

        run(`vmnd -pkey "$group" "publicKey"`)
        run(`vmnd -ciphs -width $width "publicKey" $N "ciphertexts"`)

        run(`vmni -prot -sid "SessionID" -name "Ellection" -nopart 1 -thres 1 -width $width -pgroup "$group" "stub.xml"`)
        run(`vmni -party -name "Santa Claus" "stub.xml" "privInfo.xml" "protInfo.xml"`)

        run(`vmn -setpk "privInfo.xml" "protInfo.xml" "publicKey"`)
        run(`vmn -shuffle "privInfo.xml" "protInfo.xml" "ciphertexts" "ciphertextsout"`)

    end        

    return
end

# function verificatum_verify(dir::String)
#     run(`vmnv -shuffle "$dir/protInfo.xml" "$dir/dir/nizkp/default"`)
# end

function verificatum_verify(dir::String; cpu_cores=0:(Sys.CPU_THREADS-1))

    cores = collect(cpu_cores)

    cmd = [
        "taskset",
        "-c", join(cores, ','),
        "vmnv",
        "-shuffle",
        "$dir/protInfo.xml",
        "$dir/dir/nizkp/default"
    ]
    
    try
        output = IOBuffer()
        error = IOBuffer()
        
        process = run(pipeline(`$cmd`, stdout=output, stderr=error))
        
        return (
            success = process.exitcode == 0,
            output = String(take!(output)),
            error = String(take!(error)),
            cores_used = cores
        )
    catch e
        if isa(e, SystemError)
            return (
                success = false,
                output = "",
                error = "Failed to execute command: $(e.msg)",
                cores_used = cores
            )
        end
        return (
            success = false,
            output = "",
            error = "Unexpected error: $e",
            cores_used = cores
        )
    end
end


function shuffleproofs_verify(dir::String; G = nothing)
    simulator = ShuffleProofs.load_verificatum_simulator(dir; G)
    return verify(simulator)
end


# returns output
function benchmark(g::Group, N::Int; fname = nothing, dir = joinpath(tempdir(), "shuffle"), title = "PoS Verification (N = $N)")

    rm(dir, recursive=true, force=true)
    mkpath(dir)
    generate_sample(dir, g, N) 

    println("\n$title\n")
    
    print("Verificatum single core: ")
    verificatum_single_core = @elapsed verificatum_verify(dir; cpu_cores=0:0)
    println("$verificatum_single_core seconds")

    print("Verificatum two cores: ")
    verificatum_two_cores = @elapsed verificatum_verify(dir; cpu_cores=0:1)
    println("$verificatum_two_cores seconds")

    print("ShuffleProofs deserialization and validation: ")
    shuffleproofs_validation = @elapsed (simulator = ShuffleProofs.load_verificatum_simulator(dir; G = typeof(g)))
    println("$shuffleproofs_validation seconds")

    print("ShuffleProofs verification: ")
    shuffleproofs_verification = @elapsed verify(simulator)
    println("$shuffleproofs_verification seconds")

    
    if !isnothing(fname)
        
        barplot(fname, 
                [(shuffleproofs_verification, shuffleproofs_validation), verificatum_single_core, verificatum_two_cores], 
                ["ShuffleProofs (single core)", "Verificatum (single core)", "Verificatum (2 cores)"]; 
                bar_colors = [("#3a8ad9", "#7ac0f7"), "#a5b3b3", "#a5b3b3"], 
                title,
                border_color = "#2d2d2d", 
                width = 600, 
                height = 400, 
                font_scale = 1.4,
                yrange = (shuffleproofs_validation + shuffleproofs_verification) * 1.1
                )
    end
    

end


# The sage prime generated using CryptoUtils.safe_prime(2024)
# this shall offer 128-bit security for discre logarithm problem
p = 21382745824200386598440507155450597318975927850568186995307661892981811037297261168881144465428778639798715782750831989983017501552972925363716393805743204151139763219470696077677088259096041802733626281326473577556517292979132363218956032590346933829352728780752329828816013172971209616889980498790118738799399089082309627680694844858663585459481303691612999162995050524911804677247814527046388187786574610440977393491731898010663380241945581858168893650926617195358184864871828169737311334866919621079911356627255143495523080166648673556549049197527147687314012167794605916987177326707347677098977211856674727029519

N = 10 # a warmup
g = @PGroup{p = p, q = div(p - 1, 2)}(4)
benchmark(g, N; title = "PoS Verification on MODP 2048 bit (N = $N)")

N = 1000
g = @PGroup{p = p, q = div(p - 1, 2)}(4)
benchmark(g, N; fname = joinpath(@__DIR__, "results/modp_2048_N=$N.svg"), title = "PoS Verification on MODP 2048 bit (N = $N)")

N = 10000
g = @PGroup{p = p, q = div(p - 1, 2)}(4)
benchmark(g, N; fname = joinpath(@__DIR__, "results/modp_2048_N=$N.svg"), title = "PoS Verification on MODP 2048 bit (N = $N)")

N = 10 # a warmup
g = @ECGroup{OpenSSLGroups.Prime256v1}()
benchmark(g, N)

N = 100000
g = @ECGroup{OpenSSLGroups.Prime256v1}()
benchmark(g, N; fname = joinpath(@__DIR__, "results/P-256_N=$N.svg"), title = "PoS Verification on P-256 (N = $N)")

# N = 1000000
# g = @ECGroup{OpenSSLGroups.Prime256v1}()
# benchmark(g, N; fname = joinpath(@__DIR__, "results/P-256_N=$N.svg"), title = "PoS Verification on P-256 (N = 1 000 000)")
