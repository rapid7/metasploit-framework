#!/usr/bin/env ruby -w

##
#    Name: Rex::Proto::SMB::Crypt
# Purpose: Provide LANMAN DES, NTLM MD4, and HMAC MD5 routines for SMB
#  Author: H D Moore <hdm [at] metasploit.com>
# Version: $Revision$
##

require 'openssl'

module Rex
module Proto
module SMB
module Crypt

	def Crypt.lanman_des(pass, chal)
		e_p24( [ e_p16( [ pass.upcase()[0,14] ].pack('a14') ) ].pack('a21'), chal)
	end

	def Crypt.e_p16(pass)
		stat = "\x4b\x47\x53\x21\x40\x23\x24\x25"
		des_hash(stat, pass[0,7]) << des_hash(stat, pass[7,7])
	end

	def Crypt.e_p24(pass, chal)
		des_hash(chal, pass[0,7]) << des_hash(chal, pass[7,7]) << des_hash(chal, pass[14,7])
	end

	def Crypt.des_hash(data, ckey)
		cipher = OpenSSL::Cipher::Cipher.new('des-ecb')
		cipher.encrypt
		cipher.key = des_56_to_64(ckey)
		cipher.update(data)
	end

	def Crypt.des_56_to_64(ckey56)
		ckey64 = []
		ckey64[0] = ckey56[0]
		ckey64[1] = ((ckey56[0] << 7) & 0xFF) | (ckey56[1] >> 1)
		ckey64[2] = ((ckey56[1] << 6) & 0xFF) | (ckey56[2] >> 2)
		ckey64[3] = ((ckey56[2] << 5) & 0xFF) | (ckey56[3] >> 3)
		ckey64[4] = ((ckey56[3] << 4) & 0xFF) | (ckey56[4] >> 4)
		ckey64[5] = ((ckey56[4] << 3) & 0xFF) | (ckey56[5] >> 5)
		ckey64[6] = ((ckey56[5] << 2) & 0xFF) | (ckey56[6] >> 6)
		ckey64[7] =  (ckey56[6] << 1) & 0xFF
		ckey64.pack('C*')
	end

	def Crypt.unicode (str)
		str.unpack('C*').pack('v*')
	end
	
	def Crypt.ntlm_md4(pass, chal)
		e_p24( [ md4_hash(unicode(pass)) ].pack('a21'), chal)
	end
	
	def Crypt.md4_hash(data)
		digest = OpenSSL::Digest::Digest.digest('md4', data)
	end
end
end
end

if $0 == __FILE__

	test_nt = "8d041858f078ccfa1560a4617690e55184fd70ec7f23b7f9"
	test_lm = "c248cf6165fe55efaca0300966dc3796046b9c0bb4a52e27"
	test_pass = "XXXXXXX"
	test_chal = "Z" * 8

	res_lm = Rex::Proto::SMB::Crypt.lanman_des(test_pass, test_chal).unpack("H*")[0]
	res_nt = Rex::Proto::SMB::Crypt.ntlm_md4(test_pass, test_chal).unpack("H*")[0]

	if ! res_lm.eql?( test_lm )
		puts "[*] Hash generation test for lanman has failed"
		printf("Expected: %s and Received: %s\n", test_lm, res_lm)
		exit(0)
	end
	
	if res_nt != test_nt
		puts "[*] Hash generation test for ntlm has failed"
		printf("Expected: %s and Received: %s\n", test_nt, res_nt)		
		exit(0)
	end
	
	puts "[*] All hash generation tests have passed :-)"	
end
