module Rex
module Proto
module SMB
class Utils

require 'rex/text'
require 'rex/proto/smb/constants'

CONST = Rex::Proto::SMB::Constants

	# Convert a standard ASCII string to 16-bit Unicode
	def self.unicode (str)
		str.unpack('C*').pack('v*')
	end

	# Creates an access mask for use with the CLIENT.open() call based on a string
	def self.open_mode_to_access(str)
		access = CONST::OPEN_ACCESS_READ | CONST::OPEN_SHARE_DENY_NONE
		str.each_byte { |c|
			case [c].pack('C').downcase
				when 'w'
					access |= CONST::OPEN_ACCESS_READWRITE
			end
		}
		return access
	end
	
	# Creates a mode mask for use with the CLIENT.open() call based on a string
	def self.open_mode_to_mode(str)
		mode = 0
		
		str.each_byte { |c|
			case [c].pack('C').downcase
				when 'x' # Fail if the file already exists
					mode |= CONST::OPEN_MODE_EXCL
				when 't' # Truncate the file if it already exists
					mode |= CONST::OPEN_MODE_TRUNC
				when 'c' # Create the file if it does not exist
					mode |= CONST::OPEN_MODE_CREAT	
				when 'o' # Just open the file, clashes with x
					mode |= CONST::OPEN_MODE_OPEN
			end
		}

		return mode
	end
	
	# Returns a disposition value for smb.create based on permission string
	def self.create_mode_to_disposition(str)
		str.each_byte { |c|
			case [c].pack('C').downcase
				when 'c' # Create the file if it does not exist
					return CONST::CREATE_ACCESS_OPENCREATE
				when 'o' # Just open the file and fail if it does not exist
					return CONST::CREATE_ACCESS_EXIST
			end
		}

		return CONST::CREATE_ACCESS_OPENCREATE
	end

	# Convert a 64-bit signed SMB time to a unix timestamp
	def self.servertime(time_high, time_low)
		(((time_high * 0x100000000) + time_low) / 10000000) - 11644473600
	end
	
	# Convert a name to its NetBIOS equivalent
	def self.nbname_encode (str)
		encoded = ''
		for x in (0..15)
			if (x >= str.length)
				encoded << 'CA'
			else
				c = str[x, 1].upcase[0]
				encoded << [ (c / 16) + 0x41, (c % 16) + 0x41 ].pack('CC')
			end
		end
		return encoded
	end
	
	# Convert a name from its NetBIOS equivalent
	def self.nbname_decode (str)
		decoded = ''
		str << 'A' if str.length % 2 != 0
		while (str.length > 0)
			two = str.slice!(0, 2)
			if (two.length == 2)
				decoded << [ ((two[0] - 0x41) * 16) + two[1] - 0x41 ].pack('C')
			end
		end
		return decoded
	end

	def self.asn1encode (str = '')
		res = ''
		case str.length
			when 0 .. 0x80
				res = [str.length].pack('C') + str
			when 0x81 .. 0x100
				res = [0x81, str.length].pack('CC') + str
			when 0x101 .. 0x100000
				res = [0x82, str.length].pack('Cn') + str
			when  0x100001 .. 0xffffffff
				res = [0x83, str.length].pack('CN') + str
		end
		return res
	end
	
	def self.make_ntlmv2_secblob_init (domain = 'WORKGROUP', name = 'WORKSTATION')
		blob = 
		"\x60" + self.asn1encode(		
			"\x06" + self.asn1encode(
				"\x2b\x06\x01\x05\x05\x02"
			) +	
			"\xa0" + self.asn1encode(
				"\x30" + self.asn1encode(
					"\xa0" + self.asn1encode(
						"\x30" + self.asn1encode(
							"\x06" + self.asn1encode(
								"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
							)
						)
					) +
					"\xa2" + self.asn1encode(
						"\x04" + self.asn1encode(
							"NTLMSSP\x00" +
							[1, 0x80201].pack('VV') +

							[
								domain.length,  #length
								domain.length,  #max length
								32
							].pack('vvV') +

							[
								name.length,	#length
								name.length, 	#max length
								domain.length + 32
							].pack('vvV') +	

							domain + name
						)
					)
				)
			)
		)

		return blob	
	end
		
	def self.make_ntlmv2_secblob_auth (domain = '', name = '', user = '', lmv2 = '', ntlm = '')
		
		domain_uni = self.unicode(domain)
		user_uni   = self.unicode(user)
		name_uni   = self.unicode(name)
		
		ptr  = 0 
		blob =
			"\xa1" + self.asn1encode(
			"\x30" + self.asn1encode(
			"\xa2" + self.asn1encode(
			"\x04" + self.asn1encode(
		
				"NTLMSSP\x00" +
				[ 3 ].pack('V') +
				
				[	# Lan Manager Response
					lmv2.length,
					lmv2.length,
					(ptr += 64)
				].pack('vvV') +
				
				[	# NTLM Manager Response
					ntlm.length,
					ntlm.length,
					(ptr += lmv2.length)
				].pack('vvV') +		
						
				[	# Domain Name
					domain_uni.length,
					domain_uni.length,
					(ptr += ntlm.length)
				].pack('vvV') +		

				[	# Username
					user_uni.length,
					user_uni.length,
					(ptr += domain_uni.length)
				].pack('vvV') +		

				[	# Hostname
					name_uni.length,
					name_uni.length,
					(ptr += user_uni.length)
				].pack('vvV') +		
				
				[	# Session Key (none)
					0, 0, 0
				].pack('vvV') +		

				[ 0x80201 ].pack('V') +
	
				lmv2 +
				ntlm +
				domain_uni +
				user_uni +
				name_uni 
		))))
		return blob
	end
	
end
end
end
end
