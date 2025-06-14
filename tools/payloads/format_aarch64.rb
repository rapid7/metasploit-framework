result = STDIN
    .each_line(chomp: true)
    .reject(&:empty?)
    .map do |line|
        is_label = line.start_with?("<")
        next "# #{line}" if is_label
        bytes, description = line.split("\t", 2)
        "0x#{bytes.split(" ").reverse.join}, # #{description}"
    end

puts result
