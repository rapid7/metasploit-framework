#!/usr/local/bin/ruby

if ARGV.empty?
  puts "usage: <delta value> <files ...>"
  exit(1)
end

delta = ARGV.shift.to_i

first = TRUE
last = [ ]

# simple algorithm, build up a list of all the possible addresses
# calculating the delta range for each address in the file... then
# just do a set intersection across these all and you have your results

ARGV.each do |file|
  cur = [ ]
  IO.foreach(file) do |line|
    addr = line.hex
    (-delta .. delta).each do |d|
      cur << addr + d
    end
  end

  if first
    first = FALSE
    last = cur
  else
    last = last & cur
  end
    
end

# print da results

last.each { |l|
  puts "0x%08x" % l
}

