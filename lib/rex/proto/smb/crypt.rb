require 'openssl'
require 'rex/text'

module Rex
module Proto
module SMB
class Crypt

begin

	def self.lanman_des(pass, chal)
		e_p24( [ e_p16( [ pass.upcase()[0,14] ].pack('a14') ) ].pack('a21'), chal)
	end

	def self.e_p16(pass)
		stat = "\x4b\x47\x53\x21\x40\x23\x24\x25"
		des_hash(stat, pass[0,7]) << des_hash(stat, pass[7,7])
	end

	def self.e_p24(pass, chal)
		des_hash(chal, pass[0,7]) << des_hash(chal, pass[7,7]) << des_hash(chal, pass[14,7])
	end

	def self.des_hash(data, ckey)
		cipher = OpenSSL::Cipher::Cipher.new('des-ecb')
		cipher.encrypt
		cipher.key = des_56_to_64(ckey)
		cipher.update(data)
	end

	def self.des_56_to_64(ckey56)
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

	def self.unicode (str)
		Rex::Text.to_unicode(str)
	end
	
	def self.ntlm_md4(pass, chal)
		e_p24( [ md4_hash(unicode(pass)) ].pack('a21'), chal)
	end
	
	def self.md4_hash(data)
		digest = OpenSSL::Digest::Digest.digest('md4', data)
	end
	
	def self.md5_hash(data)
		digest = OpenSSL::Digest::Digest.digest('md5', data)
	end	

rescue LoadError
end

end
end
end
end
