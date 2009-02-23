#!/usr/bin/env ruby
#
# This script cracks a half-lm challenge/response hash that uses a
# a static challenge key. The idea is you use rainbow tables to
# crack the first 7 chars and this script to complete a few remaining.
# If the password is longer than 10 characters, this script will fail.
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'

def usage
	$stderr.puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
	exit
end

def try(word)
	buf = ::Rex::Proto::SMB::Crypt.lanman_des(word, "\x11\x22\x33\x44\x55\x66\x77\x88")
	buf.unpack("H*")[0]
end

hash = pass = nil

$args = Rex::Parser::Arguments.new(
	"-n" => [ true,  "The encypted LM hash to crack"                                    ],
	"-p" => [ true,  "The decrypted LANMAN password for bytes 1-7"                                      ],
	"-h" => [ false, "Display this help information"                                      ])


$args.parse(ARGV) { |opt, idx, val|
	case opt
		when "-n"
			hash = val
		when "-p"
			pass = val
		when "-h"
			usage
		else
			usage
	end
}

if (not (hash and pass))
	usage
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
	if(try(test) == hash)
		puts "[*] Cracked: #{test}"
		exit
	end
end
etime = Time.now.to_f - stime

puts "[*] Trying two characters (eta: #{etime * cset.length} seconds)..."
0.upto(cset.length-1) do |c1|
0.upto(cset.length-1) do |c2|
	test = pass + cset[c1].chr + cset[c2].chr
	if(try(test) == hash)
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
	if(try(test) == hash)
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
	if(try(test) == hash)
		puts "[*] Cracked: #{test}"
		exit
	end
end
end
end
end
