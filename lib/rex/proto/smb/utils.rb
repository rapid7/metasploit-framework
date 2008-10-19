require 'rex/text'
require 'rex/proto/smb/constants'

module Rex
module Proto
module SMB
class Utils

CONST = Rex::Proto::SMB::Constants

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
	def self.time_smb_to_unix(thi, tlo)
		(((thi << 32) + tlo) / 10000000) - 11644473600
	end

	# Convert a unix timestamp to a 64-bit signed server time
	def self.time_unix_to_smb(unix_time)
		t64 = (unix_time + 11644473600) * 10000000
		thi = (t64 & 0xffffffff00000000) >> 32
		tlo = (t64 & 0x00000000ffffffff)
		return [thi, tlo]
	end

	# Convert a name to its NetBIOS equivalent
	def self.nbname_encode(str)
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
	def self.nbname_decode(str)
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

	#
	# Prepends an ASN1 formatted length field to a piece of data
	#
	def self.asn1encode(str = '')
		res = ''

		# If the high bit of the first byte is 1, it contains the number of
		# length bytes that follow

		case str.length
			when 0 .. 0x7F
				res = [str.length].pack('C') + str
			when 0x80 .. 0xFF
				res = [0x81, str.length].pack('CC') + str
			when 0x100 .. 0xFFFF
				res = [0x82, str.length].pack('Cn') + str
			when  0x10000 .. 0xffffff
				res = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
			when  0x1000000 .. 0xffffffff
				res = [0x84, str.length].pack('CN') + str
			else
				raise "ASN1 str too long"
			end
		return res
	end
	
	def self.make_ntlmv2_secblob_init(domain = 'WORKGROUP', name = 'WORKSTATION', flags=0x80201)
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
							[1, flags].pack('VV') +

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

	def self.make_ntlmv2_secblob_auth(domain, name, user, lmv2, ntlm, flags = 0x080201)
		
		lmv2 ||= "\x00" * 24
		ntlm ||= "\x00" * 24		
	
		domain_uni = Rex::Text.to_unicode(domain)
		user_uni   = Rex::Text.to_unicode(user)
		name_uni   = Rex::Text.to_unicode(name)
		session    = ''
		
		ptr  = 64 
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
								(ptr)
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
								session.length,
								session.length,
								(ptr += name_uni.length)
							].pack('vvV') +		
			
							[ flags ].pack('V') +
				
							lmv2 +
							ntlm +
							domain_uni +
							user_uni +
							name_uni + 
							session + "\x00"
					)
				)
			)
		)
		return blob
	end


	def self.make_negotiate_secblob_resp(account, domain)
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
								"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"
							) +
							"\x06" + self.asn1encode(
								"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
							) +
							"\x06" + self.asn1encode(
								"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"
							) +	
							"\x06" + self.asn1encode(
								"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
							)																						
						)
					) +
					"\xa3" + self.asn1encode(
						"\x30" + self.asn1encode(
							"\xa0" + self.asn1encode(
								"\x1b" + self.asn1encode(
									account + '@' + domain
								)
							)
						)
					)
				)
			)
		)

		return blob	
	end	

	def self.make_ntlmv2_secblob_chall(win_domain, dns_domain, win_name, dns_name, chall, flags)
		
		win_domain = Rex::Text.to_unicode(win_domain)
		dns_domain = Rex::Text.to_unicode(dns_domain)
		win_name = Rex::Text.to_unicode(win_name)
		dns_name = Rex::Text.to_unicode(dns_name)
		
		addr_list  = ''
		addr_list  << [2, win_domain.length].pack('vv') + win_domain
		addr_list  << [1, win_name.length].pack('vv') + win_name
		addr_list  << [4, dns_domain.length].pack('vv') + dns_domain
		addr_list  << [3, dns_name.length].pack('vv') + dns_name
		addr_list  << [5, dns_domain.length].pack('vv') + dns_domain
		addr_list  << [0, 0].pack('vv')

		ptr  = 0 
		blob =
			"\xa1" + self.asn1encode(
				"\x30" + self.asn1encode(
					"\xa0" + self.asn1encode(
						"\x0a" + self.asn1encode(
							"\x01"
						)
					) +
					"\xa1" + self.asn1encode(
						"\x06" + self.asn1encode(
							"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
						)
					) +
					"\xa2" + self.asn1encode(
						"\x04" + self.asn1encode(
							"NTLMSSP\x00" +
							[2].pack('V') +
							[
								win_domain.length,  # length
								win_domain.length,  # max length
								(ptr += 48)
							].pack('vvV') +
							[ flags ].pack('V') +
							chall + 
							"\x00\x00\x00\x00\x00\x00\x00\x00" +
							[
								addr_list.length,  # length
								addr_list.length,  # max length
								(ptr += win_domain.length) 
							].pack('vvV') +
							win_domain + 
							addr_list
						)
					)
				)	
			)

		return blob
	end

	def self.make_ntlmv2_secblob_success
		blob =
			"\xa1" + self.asn1encode(
				"\x30" + self.asn1encode(
					"\xa0" + self.asn1encode(
						"\x0a" + self.asn1encode(
							"\x00"
						)
					)
				)	
			)
		return blob
	end
	
	#
	# Process Type 3 NTLM Message (in Base64)
	#
	def self.process_type3_message(message)
		decode = Rex::Text.decode_base64(message.strip)
		type = decode[8]
		if (type == 3)
			domoff = decode[32]	 # domain offset
			domlen = decode[28]	 # domain length
			useroff = decode[40] # username offset
			userlen = decode[36] # username length
			hostoff = decode[48] # hostname offset
			hostlen = decode[44] # hostname length
			lmoff = decode[16]	 # LM hash offset
			lmlen = decode[12]	 # LM hash length
			ntoff = decode[24]	 # NT hash offset
			ntlen = decode[20]	 # NT hash length

			domain = decode[domoff..domoff+domlen-1]
			user = decode[useroff..useroff+userlen-1]
			host = decode[hostoff..hostoff+hostlen-1]
			lm = decode[lmoff..lmoff+lmlen-1].unpack("H*")
			nt = decode[ntoff..ntoff+ntlen-1].unpack("H*")
		
			return domain, user, host, lm, nt
		else
			return "", "", "", "", ""
		end
	end
	
	#	 
	# Process Type 1 NTLM Messages, return a Base64 Type 2 Message
	#
	def self.process_type1_message(message, nonce = "\x11\x22\x33\x44\x55\x66\x77\x88", win_domain = 'DOMAIN', 
					win_name = 'SERVER', dns_name = 'server', dns_domain = 'example.com', downgrade = true)

		dns_name = Rex::Text.to_unicode(dns_name + "." + dns_domain)
		win_domain = Rex::Text.to_unicode(win_domain)
		dns_domain = Rex::Text.to_unicode(dns_domain)
		win_name = Rex::Text.to_unicode(win_name)
		decode = Rex::Text.decode_base64(message.strip)

		type = decode[8]

		if (type == 1)
			# A type 1 message has been received, lets build a type 2 message response

			reqflags = decode[12..15]
			reqflags = Integer("0x" + reqflags.unpack("h8").to_s.reverse)

			if (reqflags & CONST::REQUEST_TARGET) == CONST::REQUEST_TARGET

				if (downgrade)
					# At this time NTLMv2 and signing requirements are not supported
					if (reqflags & CONST::NEGOTIATE_NTLM2_KEY) == CONST::NEGOTIATE_NTLM2_KEY
						reqflags = reqflags - CONST::NEGOTIATE_NTLM2_KEY
					end
					if (reqflags & CONST::NEGOTIATE_ALWAYS_SIGN) == CONST::NEGOTIATE_ALWAYS_SIGN
						reqflags = reqflags - CONST::NEGOTIATE_ALWAYS_SIGN
					end				
				end

				flags = reqflags + CONST::TARGET_TYPE_DOMAIN + CONST::TARGET_TYPE_SERVER				
				tid = true

				tidoffset = 48 + win_domain.length
				tidbuff = 
					[2].pack('v') +				# tid type, win domain
					[win_domain.length].pack('v') +
					win_domain +
					[1].pack('v') +				# tid type, server name
					[win_name.length].pack('v') +
					win_name +
					[4].pack('v')	+			 # tid type, domain name
					[dns_domain.length].pack('v') +
					dns_domain +
					[3].pack('v')	+			# tid type, dns_name
					[dns_name.length].pack('v') +
					dns_name
			else
				flags = CONST::NEGOTIATE_UNICODE + CONST::NEGOTIATE_NTLM
				tid = false
			end

			type2msg = "NTLMSSP\0" + # protocol, 8 bytes
				   "\x02\x00\x00\x00"		# type, 4 bytes

			if (tid)
				type2msg +=	# Target security info, 8 bytes. Filled if REQUEST_TARGET
				[win_domain.length].pack('v') +	 # Length, 2 bytes
				[win_domain.length].pack('v')	 # Allocated space, 2 bytes
			end

			type2msg +="\x30\x00\x00\x00" + #		Offset, 4 bytes
				 [flags].pack('V') +	# flags, 4 bytes
				 nonce +		# the nonce, 8 bytes
			 	 "\x00" * 8		# Context (all 0s), 8 bytes

			if (tid)
				type2msg +=		# Target information security buffer. Filled if REQUEST_TARGET
					[tidbuff.length].pack('v') +	# Length, 2 bytes
					[tidbuff.length].pack('v') +	# Allocated space, 2 bytes
					[tidoffset].pack('V') +		# Offset, 4 bytes (usually \x48 + length of win_domain)
					win_domain +			# Target name data (domain in unicode if REQUEST_UNICODE)
									# Target information data
					tidbuff +			#	Type, 2 bytes
									#	Length, 2 bytes
									#	Data (in unicode if REQUEST_UNICODE)
					"\x00\x00\x00\x00"		# Terminator, 4 bytes, all \x00
			end

			type2msg = Rex::Text.encode_base64(type2msg).delete("\n") # base64 encode and remove the returns
		else
			# This is not a Type2 message
			type2msg = ""
		end

		return type2msg
	end
	
	#
	# Downgrading Type messages to LMv1/NTLMv1 and removing signing
	#
	def self.downgrade_type_message(message)
		decode = Rex::Text.decode_base64(message.strip)

		type = decode[8]

		if (type > 0 and type < 4)
			reqflags = decode[12..15] if (type == 1 or type == 3)
			reqflags = decode[20..23] if (type == 2)
			reqflags = Integer("0x" + reqflags.unpack("h8").to_s.reverse)

			# Remove NEGOTIATE_NTLMV2_KEY and NEGOTIATE_ALWAYS_SIGN, this lowers the negotiation
			# down to LMv1/NTLMv1.
			if (reqflags & CONST::NEGOTIATE_NTLM2_KEY) == CONST::NEGOTIATE_NTLM2_KEY
				reqflags = reqflags - CONST::NEGOTIATE_NTLM2_KEY
			end
			if (reqflags & CONST::NEGOTIATE_ALWAYS_SIGN) == CONST::NEGOTIATE_ALWAYS_SIGN
				reqflags = reqflags - CONST::NEGOTIATE_ALWAYS_SIGN
			end				
			
			# Return the flags back to the decode so we can base64 it again
			flags = reqflags.to_s(16)
			0.upto(8) do |idx|
			  if (idx > flags.length)
			    flags.insert(0, "0")
			  end
			end

			idx = 0
			0.upto(3) do |cnt|
				if (type == 2)
					decode[23-cnt] = Integer("0x" + flags[idx .. idx + 1])
				else
					decode[15-cnt] = Integer("0x" + flags[idx .. idx + 1])
				end
				idx += 2
			end
			
		end
		return Rex::Text.encode_base64(decode).delete("\n") # base64 encode and remove the returns 
	end
	
end
end
end
end