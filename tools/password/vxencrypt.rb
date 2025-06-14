#!/usr/bin/env ruby

#
# This script can be used to calculate hash values for VxWorks passwords.
#

def hashit(inp)
  if inp.length < 8 or inp.length > 120
    raise RuntimeError, "The password must be between 8 and 120 characters"
  end
  sum   = 0
  bytes = inp.unpack("C*")
  bytes.each_index {|i| sum += (bytes[i] * (i + 1)) ^ (i + 1) }
  hackit(sum)
end

def hackit(sum)
  magic = 31695317
  res = ((sum * magic) & 0xffffffff).to_s
  res.unpack("C*").map{ |c|
    c += 0x21 if c < 0x33
    c += 0x2f if c < 0x37
    c += 0x42 if c < 0x39
    c
  }.pack("C*")
end

input = ARGV.shift || "flintstone"
$stderr.puts "[*] Hash for password '#{input}' is #{hashit(input)}"
