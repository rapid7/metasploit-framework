#!/usr/bin/env ruby
#
# $Id$
#
# This script cracks HMAC SHA1 hashes. It is strangely necessary as existing tools 
# have issues with binary salt values and extremely large salt values. The primary
# goal of this tool is to handle IPMI 2.0 HMAC SHA1 hashes.
#
# Support for this format is being added to both hashcat and jtr, hopefully
# making this code obsolete.
#

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'openssl'

def usage
	$stderr.puts("\nUsage: #{$0} hashes.txt <wordlist | - >\n")
	$stderr.puts("The format of hash file is <identifier>:<hex-salt>:<hash>\n\n")
	exit
end


hash_inp  = ARGV.shift || usage()
word_inp  = ARGV.shift || usage()

usage if [hash_inp, word_inp].include?("-h") or [hash_inp, word_inp].include?("--help")

hash_fd = ::File.open(hash_inp, "rb")
word_fd = $stdin

if word_inp != "-"
	word_fd = ::File.open(word_inp, "rb")
end

hashes = []
hash_fd.each_line do |line|
	next unless line.strip.length > 0
	h_id, h_salt, h_hash = line.unpack("C*").pack("C*").strip.split(':', 3)

	unless h_id and h_salt and h_hash
		$stderr.puts "[-] Invalid hash entry, missing field: #{line}"
		next
	end
	unless h_salt =~ /^[a-f0-9]+$/i 
		$stderr.puts "[-] Invalid hash entry, salt must be in hex: #{line}"
		next
	end
	hashes << [h_id, [h_salt].pack("H*"), [h_hash].pack("H*") ]
end
hash_fd.close 


stime = Time.now.to_f
count = 0 
cracked = 0

word_fd.each_line do |line|
	# Preferable to strip so we can test passwords made of whitespace (or null)
	line = line.unpack("C*").pack("C*").sub(/\r?\n?$/, '')
	hashes.each do |hinfo|
		if OpenSSL::HMAC.digest('sha1', line.to_s, hinfo[1]) == hinfo[2]
			$stdout.puts [ hinfo[0], hinfo[1].unpack("H*").first, hinfo[2].unpack("H*").first, line.to_s ].join(":")
			$stdout.flush
			hinfo[3] = true
			cracked += 1
		end
		count += 1
		
		if count % 2500000 == 0
			$stderr.puts "[*] Found #{cracked} passwords with #{hashes.length} left (#{(count / (Time.now.to_f - stime)).to_i}/s)"
		end		
	end
	hashes.delete_if {|e| e[3] }
	break if hashes.length == 0

end
word_fd.close

$stderr.puts "[*] Cracked #{cracked} passwords with #{hashes.length} left (#{(count / (Time.now.to_f - stime)).to_i}/s)"
