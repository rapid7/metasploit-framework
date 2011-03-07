module Rex
module Proto
module NTLM
class Utils

  	#duplicate from lib/rex/proto/smb/utils cause we only need this fonction from Rex::Proto::SMB::Utils
	# Convert a unix timestamp to a 64-bit signed server time
	def self.time_unix_to_smb(unix_time)
		t64 = (unix_time + 11644473600) * 10000000
		thi = (t64 & 0xffffffff00000000) >> 32
		tlo = (t64 & 0x00000000ffffffff)
		return [thi, tlo]
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

	#GSS functions

	#GSS BLOB usefull for SMB_NEGOCIATE_RESPONSE message
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

	#GSS BLOB usefull for SMB_NEGOCIATE_RESPONSE message
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


	#GSS BLOB usefull for ntlmssp type 1 message
	def self.make_ntlmssp_secblob_init(domain = 'WORKGROUP', name = 'WORKSTATION', flags=0x80201)
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


	#GSS BLOB usefull for ntlmssp type 2 message
	def self.make_ntlmssp_secblob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)
		
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
							make_ntlmssp_blob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)
						)
					)
				)	
			)

		return blob
	end

	#BLOB without GSS usefull for ntlm type 2 message 
	def self.make_ntlmssp_blob_chall(win_domain, win_name, dns_domain, dns_name, chall, flags)

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


	#GSS BLOB Usefull for ntlmssp type 3 message
	def self.make_ntlmssp_secblob_auth(domain, name, user, lm, ntlm, enc_session_key, flags = 0x080201)

		lm ||= "\x00" * 24
		ntlm ||= "\x00" * 24		
	
		domain_uni = Rex::Text.to_unicode(domain)
		user_uni   = Rex::Text.to_unicode(user)
		name_uni   = Rex::Text.to_unicode(name)
		session    = enc_session_key

		ptr  = 64 
		blob =
			"\xa1" + self.asn1encode(
				"\x30" + self.asn1encode(
					"\xa2" + self.asn1encode(
						"\x04" + self.asn1encode(
					
							"NTLMSSP\x00" +
							[ 3 ].pack('V') +
							
							[	# Lan Manager Response
								lm.length,
								lm.length,
								(ptr)
							].pack('vvV') +
							
							[	# NTLM Manager Response
								ntlm.length,
								ntlm.length,
								(ptr += lm.length)
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
				
							lm +
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


	# GSS BLOB Usefull for SMB Success
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
	
	#others

	#this function return an ntlmv2 client challenge
	def self.make_ntlmv2_clientchallenge(win_domain, win_name, dns_domain, dns_name, client_challenge = nil, chall_MsvAvTimestamp = nil)
		
		client_challenge ||= Rex::Text.rand_text(8)
		#we have to set the timestamps here to the one in the challenge message from server if present
		#if we don't do that, recent server like seven will send a STATUS_INVALID_PARAMETER error packet
		timestamp = chall_MsvAvTimestamp != nil ? chall_MsvAvTimestamp : self.time_unix_to_smb(Time.now.to_i).reverse.pack("VV")
		#make those values unicode as requested
		win_domain = Rex::Text.to_unicode(win_domain)
		win_name = Rex::Text.to_unicode(win_name)
		dns_domain = Rex::Text.to_unicode(dns_domain)
		dns_name = Rex::Text.to_unicode(dns_name)
		#make the AV_PAIRs
		addr_list  = ''
		addr_list  << [2, win_domain.length].pack('vv') + win_domain
		addr_list  << [1, win_name.length].pack('vv') + win_name
		addr_list  << [4, dns_domain.length].pack('vv') + dns_domain
		addr_list  << [3, dns_name.length].pack('vv') + dns_name
		addr_list  << [7, 8].pack('vv') + timestamp

		#MAY BE USEFUL FOR FUTURE
		#seven (client) add at least one more av that is of type MsAvRestrictions (8)	
		#maybe this will be usefull with future windows OSs but has no use at all for the moment afaik		
		#restriction_encoding = 	[48,0,0,0].pack("VVV") + # Size, Z4, IntegrityLevel, SubjectIntegrityLevel
		#			Rex::Text.rand_text(32)	 # MachineId generated on startup on win7 and above
		#addr_list  << [8, restriction_encoding.length].pack('vv') + restriction_encoding
		#seven (client) and maybe others versions also add an av of type MsvChannelBindings (10) but the hash is "\x00" * 16
		#addr_list  << [10, 16].pack('vv') + "\x00" * 16
		#seven and maybe other versions also add an av of type MsvAvTargetName(9) with value cifs/target(_ip)
		#implementing it will necessary require knowing the target here, todo... :-/
		#spn= Rex::Text.to_unicode("cifs/RHOST")
		#addr_list  << [9, spn.length].pack('vv') + spn

		addr_list  << [0, 0].pack('vv')
		ntlm_clientchallenge = 	[1,1,0,0].pack("CCvV") + #RespType, HiRespType, Reserved1, Reserved2
					timestamp + #Timestamp
					client_challenge + 	#clientchallenge
					[0].pack("V")  +	#Reserved3 
					addr_list + "\x00" * 4

	end

end
end
end
end
