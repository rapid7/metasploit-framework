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

	# NOTE: the difference below came from: Time.utc("1970-1-1") - Time.utc("1601-1-1")

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
				c = str[x, 1].upcase[0,1].unpack('C*')[0]
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
			two = str.slice!(0, 2).unpack('C*')
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
	#This function will create a GSS Sec blob compatible for SMB_NEGOCIATE_RESPONSE packet of this kind : 
	#mechTypes: 2 items :
	#	-MechType: 1.3.6.1.4.1.311.2.2.30 (SNMPv2-SMI::enterprises.311.2.2.30)
	#	-MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
	#
	#this is the default on Win7
	def self.make_simple_negotiate_secblob_resp
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
					) 
				)
			)
		)

		return blob	
	end	

	#This function will create a GSS Sec blob compatible for SMB_NEGOCIATE_RESPONSE packet of this kind : 
	#mechTypes: 4 items :
	#	MechType: 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
	#	MechType: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
	#	MechType: 1.2.840.113554.1.2.2.3 (KRB5 - Kerberos 5 - User to User)
	#	MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
	#mechListMIC: 
	#	principal: account@domain
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

	def self.make_ntlmv2_secblob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)
		
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
							make_ntlm_type2_blob(win_domain, win_name, dns_domain, dns_name, chall, flags)
						)
					)
				)	
			)

		return blob
	end

	def self.make_ntlm_type2_blob(win_domain, win_name, dns_domain, dns_name, chall, flags)

		addr_list  = ''
		addr_list  << [2, win_domain.length].pack('vv') + win_domain
		addr_list  << [1, win_name.length].pack('vv') + win_name
		addr_list  << [4, dns_domain.length].pack('vv') + dns_domain
		addr_list  << [3, dns_name.length].pack('vv') + dns_name
		addr_list  << [0, 0].pack('vv')

		ptr  = 0 
		blob =	"NTLMSSP\x00" +
				[2].pack('V') +
				[
					win_domain.length,  # length
					win_domain.length,  # max length
					(ptr += 48) # offset
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
	# from http://www.innovation.ch/personal/ronald/ntlm.html
	#
	#	struct {
	#		byte  protocol[8];  // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	#		byte  type;         // 0x03
	#		byte  zero[3];
	#
	#		short lm_resp_len;  // LanManager response length (always 0x18)
	#		short lm_resp_len;  // LanManager response length (always 0x18)
	#		short lm_resp_off;  // LanManager response offset
	#		byte  zero[2];
	#
	#		short nt_resp_len;  // NT response length (always 0x18)
	#		short nt_resp_len;  // NT response length (always 0x18)
	#		short nt_resp_off;  // NT response offset
	#		byte  zero[2];
	#
	#		short dom_len;      // domain string length
	#		short dom_len;      // domain string length
	#		short dom_off;      // domain string offset (always 0x40)
	#		byte  zero[2];
	#
	#		short user_len;     // username string length
	#		short user_len;     // username string length
	#		short user_off;     // username string offset
	#		byte  zero[2];
	#
	#		short host_len;     // host string length
	#		short host_len;     // host string length
	#		short host_off;     // host string offset
	#		byte  zero[6];
	#
	#		short msg_len;      // message length
	#		byte  zero[2];
	#
	#		short flags;        // 0x8201
	#		byte  zero[2];
	#
	#		byte  dom[*];       // domain string (unicode UTF-16LE)
	#		byte  user[*];      // username string (unicode UTF-16LE)
	#		byte  host[*];      // host string (unicode UTF-16LE)
	#		byte  lm_resp[*];   // LanManager response
	#		byte  nt_resp[*];   // NT response
	#	} type_3_message
	#
	def self.process_type3_message(message)
		decode = Rex::Text.decode_base64(message.strip)
		type = decode[8,1].unpack("C").first
		if (type == 3)
			lm_len = decode[12,2].unpack("v").first
			lm_offset = decode[16,2].unpack("v").first
			lm = decode[lm_offset, lm_len].unpack("H*").first

			nt_len = decode[20,2].unpack("v").first
			nt_offset = decode[24,2].unpack("v").first
			nt = decode[nt_offset, nt_len].unpack("H*").first

			dom_len = decode[28,2].unpack("v").first
			dom_offset = decode[32,2].unpack("v").first
			domain = decode[dom_offset, dom_len]

			user_len = decode[36,2].unpack("v").first
			user_offset = decode[40,2].unpack("v").first
			user = decode[user_offset, user_len]

			host_len = decode[44,2].unpack("v").first
			host_offset = decode[48,2].unpack("v").first
			host = decode[host_offset, host_len]
		
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

		type = decode[8,1].unpack("C").first

		if (type == 1)
			# A type 1 message has been received, lets build a type 2 message response

			reqflags = decode[12,4]
			reqflags = reqflags.unpack("V").first

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

		type = decode[8,1].unpack("C").first

		if (type > 0 and type < 4)
			reqflags = decode[12..15] if (type == 1 or type == 3)
			reqflags = decode[20..23] if (type == 2)
			reqflags = reqflags.unpack("V")

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
					decode[23-cnt] = [flags[idx,1]].pack("C")
				else
					decode[15-cnt] = [flags[idx,1]].pack("C")
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
