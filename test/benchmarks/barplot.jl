using Luxor
# The code was produced from a few instructions with Claude
# Using a general plotting package may have been better here

function wrap_text(text, max_width, fontsize_val)
    words = split(text, " ")
    lines = String[]
    current_line = String[]
    
    function get_text_width(text)
        return textextents(text)[3]
    end
    
    for word in words
        test_line = join([current_line..., word], " ")
        text_width = get_text_width(test_line)
        
        if text_width <= max_width
            push!(current_line, word)
        else
            if !isempty(current_line)
                push!(lines, join(current_line, " "))
                current_line = String[word]
            else
                push!(lines, word)
            end
        end
    end
    
    if !isempty(current_line)
        push!(lines, join(current_line, " "))
    end
    
    return lines
end

function barplot(fname::String, values::Vector, implementations::Vector{String}; 
                  bar_colors = ["#A8D0E6", "#F9C784", "#F9C784"], 
                  border_color = "#404040",
                  ylabel = "Time (s)", 
                  title = "Implementation Benchmarks", 
                  width = 400,
                  height = 300,
                  yrange = 200,
                 #yticks = 0:50:200,
                  font_scale = min(width/400, height/300)
                  )

    step = Int(div(yrange, 5))
    yticks = 0:step:(5 * step)

    Drawing(width, height, fname)
    
    scale_x = width/400
    scale_y = height/300
    
    title_size = 16 * font_scale
    label_size = 12 * font_scale
    value_size = 14 * font_scale #min(scale_x, scale_y)  # Size for values above bars
    
    background("white")
    
    padding_x = 60 * scale_x #
    padding_y = 50 * scale_y
    translate(padding_x, height - padding_y)
    
    bar_width = 60 * scale_x
    gap = 40 * scale_x
    first_bar_offset = 20 * scale_x
    chart_height = 200 * scale_y
    
    setline(2 * min(scale_x, scale_y))
    setcolor(border_color)
    
    # Y-axis
    line(Point(0, 0), Point(0, -chart_height), :stroke)
    
    # X-axis
    chart_width = first_bar_offset + length(implementations) * (bar_width + gap)
    line(Point(0, 0), Point(chart_width, 0), :stroke)
    
    # Y-axis label (vertical text)
    setcolor("black")
    fontsize(label_size)
    gsave()
    translate(-40 * scale_x, -chart_height/2)
    rotate(-π/2)
    text(ylabel, Point(0, 0), halign=:center)
    grestore()
    
    # Y-axis labels
    fontsize(label_size)
    for (i, y) in enumerate(yticks)
        scaled_y = (y/yrange) * chart_height
        text(string(y), Point(-10 * scale_x, -scaled_y), halign=:right)
    end
    
    # Draw bars and labels
    for (i, (impl, val)) in enumerate(zip(implementations, values))
        x = first_bar_offset + (i-1) * (bar_width + gap)

       
        bottom = 0
        for (vi, ci) in zip(val, bar_colors[i] isa String ? (bar_colors[i], ) : bar_colors[i])
            # Fill bar (representing total)

            setcolor(ci)  # Alternate between colors
            #setcolor(bar_colors[i])  # Alternate between colors
            
            scaled_height = (vi/yrange) * chart_height
            rect(Point(x, -bottom), bar_width, -scaled_height, :fill)

            bottom += scaled_height
        end
        
        # Draw border
        scaled_height = (sum(val)/yrange) * chart_height
        setcolor(border_color)
        rect(Point(x, 0), bar_width, -scaled_height, :stroke)
        
        # Draw value on top of bar
        fontsize(value_size)
        setcolor("black")
        text(string(trunc(sum(val)) |> Int), Point(x + bar_width/2, -scaled_height - 10 * scale_y), halign=:center)
        
        setcolor("black")
        # Draw wrapped label
        fontsize(label_size)
        wrapped_lines = wrap_text(impl, bar_width * 1.1, label_size) # scale here
        
        for (line_num, line) in enumerate(wrapped_lines)
            line_y = (20 + (line_num - 1) * label_size) * scale_y
            text(line, Point(x + bar_width/2, line_y), halign=:center)
        end
    end
    
    # Add title
    fontsize(title_size)
    text(title, 
         Point(0.9 * chart_width/2, -(chart_height + 30 * scale_y)), 
         halign=:center)
    
    finish()
    
end


function barplot_test(dir::String)

    barplot(joinpath(dir, "simple.svg"), [150, 100, 70], ["ShuffleProofs (single core)", "Verificatum (single core)", "Verificatum (2 cores)"]; title = "PoS Verification on P-256 (N = 1 000 000)")
    
    barplot(joinpath(dir, "modp.svg"), [80, 30, 20], ["ShuffleProofs (single core)", "Verificatum (single core)", "Verificatum (2 cores)"]; title = "PoS Verification on MODP 2048 bit (N = 10000)", yrange = 80)

    barplot(joinpath(dir, "benchmark_chart.svg"), [(120, 30), 100, 70], ["ShuffleProofs (single core)", "Verificatum (single core)", "Verificatum (2 cores)"]; bar_colors = [("#3a8ad9", "#7ac0f7"), "#a5b3b3", "#a5b3b3"], title = "PoS Verification on MODP 2048 bit (N = 10000)",
            border_color = "#2d2d2d", width = 600, height = 400, font_scale = 1.4
            )

end
