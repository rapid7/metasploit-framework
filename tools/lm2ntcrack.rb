#!/usr/bin/env ruby
#
# This script cracks a NTLM hash based on the case-insensitive LANMAN password
# Credit to Yannick Hamon <yannick.hamon[at]xmcopartners.com> for the idea/perl code
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'

def usage
	$stderr.puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
	exit
end


ntlm = pass = nil

$args = Rex::Parser::Arguments.new(
	"-n" => [ true,  "The encypted NTLM hash to crack"                                    ],
	"-p" => [ true,  "The decrypted LANMAN password"                                      ],
	"-h" => [ false, "Display this help information"                                      ])


$args.parse(ARGV) { |opt, idx, val|
	case opt
		when "-n"
			ntlm = val
		when "-p"
			pass = val
		when "-h"
			usage
		else
			usage
	end
}

if (not (ntlm and pass))
	usage
end

if(ntlm.length != 32)
	$stderr.puts "[*] NTLM should be exactly 32 bytes of hexadecimal"
	exit
end

if(pass.length > 14)
	$stderr.puts "[*] LANMAN password should be between 1 and 14 characters"
	exit
end

done = Rex::Proto::SMB::Crypt.lm2nt(pass, [ntlm].pack("H*"))

if(done)
	puts "[*] Cracked: LANMAN=#{pass} NTLM=#{done}"
else
	puts "[*] Failed to crack password (incorrect input)"
end
