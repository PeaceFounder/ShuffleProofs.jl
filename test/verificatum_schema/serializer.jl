using Test
import ShuffleProofs: load_verificatum_simulator, store_verificatum_nizkp

### Storing the simulator in a temporary directory

function compare_directories(dir1::String, dir2::String)
    !isdir(dir1) || !isdir(dir2) && error("One or both directories do not exist")

    flag = true

    for (root, _, files) in walkdir(dir1)
        target = replace(root, dir1 => dir2)
        !isdir(target) && println("Dir missing: $target")
        
        for file in files
            f1, f2 = joinpath(root, file), joinpath(target, file)
            if !isfile(f2)
                println("Missing: $f1")
                flag = false
            elseif read(f1) != read(f2)
                println("Different: $f1")
                println("Different: $f2")

                flag = false
            else
                # println("Valid: $f1")
            end
        end
    end
    
    for (root, _, files) in walkdir(dir2)
        source = replace(root, dir2 => dir1)
        for file in files
            if !isfile(joinpath(source, file)) 
                println("Extra: $(joinpath(root, file))")
                flag = false
            end
        end
    end

    return flag
end

function compare_serialization(dir)

    simulator = load_verificatum_simulator(dir)

    temp_dir = joinpath(tempdir(), "nizkp")
    rm(temp_dir; force = true, recursive = true)
    mkpath(temp_dir)

    store_verificatum_nizkp(temp_dir, simulator)
    @test compare_directories(temp_dir, joinpath(dir, "dir/nizkp/default"))
end

compare_serialization("$(@__DIR__)/../validation_sample/verificatum/P256")
compare_serialization("$(@__DIR__)/../validation_sample/verificatum/P192w3")
compare_serialization("$(@__DIR__)/../validation_sample/verificatum/MODP")
compare_serialization("$(@__DIR__)/../validation_sample/verificatum/MODPw3")

