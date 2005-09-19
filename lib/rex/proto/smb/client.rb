module Rex
module Proto
module SMB
class Client

require 'rex/text'
require 'rex/struct2'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/crypt'
require 'rex/proto/smb/utils'


# Some short-hand class aliases
CONST = Rex::Proto::SMB::Constants
CRYPT = Rex::Proto::SMB::Crypt
UTILS = Rex::Proto::SMB::Utils

	def initialize (socket)
		self.socket = socket
		self.native_os = 'Windows 2000 2195'
		self.native_lm = 'Windows 2000 5.0'
		self.encrypt_passwords = 1
		self.extended_security = 0
		self.multiplex_id = rand(0xffff)
		self.process_id = rand(0xffff)
	end
	
	# Read a SMB packet from the socket
	def smb_recv
		head = self.socket.timed_read(4, 10)
		
		if (head == nil or head.length != 4)

			puts 'could not read header'
			return nil
		end

		recv_len = head[2,2].unpack('n')[0]
		if (recv_len == 0)
			return head
		end
		
		body = self.socket.timed_read(recv_len)
		if (body == nil or body.length != recv_len)
			# XXX exception?		
			puts 'incomplete packet read'
			p body
		end
		
		return head + body
	end
	
	# Send a SMB packet down the socket
	def smb_send (data)
		self.socket.put(data)
	end
	
	# Set the SMB parameters to some reasonable defaults
	def smb_defaults(packet)
		packet.v['MultiplexID'] = self.multiplex_id.to_i
		packet.v['TreeID'] = self.tree_id.to_i
		packet.v['UserID'] = self.auth_user_id.to_i
		packet.v['ProcessID'] = self.process_id.to_i
	end
	
	
	# The main dispatcher for all incoming SMB packets
	def smb_recv_parse
		data = self.smb_recv
		
		if (data == nil)
			puts "nil response!"
			return nil
		end
		
		pkt = CONST::SMB_BASE_PKT.make_struct
		pkt.from_s(data)
		
		case pkt['Payload']['SMB'].v['Command']
		
			when CONST::SMB_COM_NEGOTIATE
				return smb_parse_negotiate(pkt, data)
			
			when CONST::SMB_COM_SESSION_SETUP_ANDX
				return smb_parse_session_setup(pkt, data)
				
			else 
				puts "Unknown" + pkt['Payload']['SMB'].v['Command'].to_s 

			return pkt
		end
	end
	
	# Process incoming SMB_COM_NEGOTIATE packets
	def smb_parse_negotiate (pkt, data)
 		#Process NTLM negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 17)
			res = CONST::SMB_NEG_RES_NT_PKT.make_struct
			res.from_s(data)
			return res
		end

		# Process LANMAN negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 13)
			res = CONST::SMB_NEG_RES_LM_PKT.make_struct
			res.from_s(data)
			return res
		end		

		# Process ERROR negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 1)
			res = CONST::SMB_NEG_RES_ERR_PKT.make_struct
			res.from_s(data)
			return res
		end		

		puts "Unknown WordCount: " + pkt['Payload']['SMB'].v['WordCount'].to_s
		return pkt
	end
	
	# Process incoming SMB_COM_SESSION_SETUP_ANDX packets
	def smb_parse_session_setup(pkt, data)
 		# Process NTLM negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 4)
			res = CONST::SMB_SETUP_NTLMV2_RES_PKT.make_struct
			res.from_s(data)
			return res
		end

		puts "Unknown WordCount: " + pkt['Payload']['SMB'].v['WordCount'].to_s
		return pkt
	end	
	
	
	# Request a SMB session over NetBIOS
	def session_request (name = '*SMBSERVER')
		
		data = ''
		data << "\x20" + UTILS.nbname_encode(name) + "\x00"
		data << "\x20" + CONST::NETBIOS_REDIR      + "\x00"

		pkt = CONST::NBRAW_PKT.make_struct
		pkt.v['Type']       = 0x81
		pkt['Payload'].v['Payload']    = data

		self.smb_send(pkt.to_s)
		res = self.smb_recv
		
		ack = CONST::NBRAW_PKT.make_struct
		ack.from_s(res)

		if (ack.v['Type'] != 130)
			return nil
		end
		
		return ack
	end

	# Negotiate a SMB dialect
	def negotiate ()
		
		dialects = []
		dialects << 'LANMAN1.0'
		dialects << 'LM1.2X002'
		
		if (self.encrypt_passwords == 1)
			dialects << 'NT LANMAN 1.0'
			dialects << 'NT LM 0.12'
		end
		
		data = ''
		dialects.each { |dialect| data << "\x02" + dialect + "\x00" }

		pkt = CONST::SMB_NEG_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2801
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse

		
		if (ack['Payload']['SMB'].v['Command'] != CONST::SMB_COM_NEGOTIATE)
			return nil
		end
		
		idx = ack['Payload'].v['Dialect']
		
		# Check for failed dialect selection
		if (idx < 0 or idx >= dialects.length)
			return nil
		end
		
		# Set the selected dialect
		self.dialect = dialects[idx]
		
		# Does the server support extended security negotiation?
		if (ack['Payload'].v['Capabilities'] & 0x80000000)
			self.extended_security = 1
		end
		
		# Set the security mode
		self.security_mode = ack['Payload'].v['SecurityMode']
		
		# Set the challenge key
		if (ack['Payload'].v['EncryptionKey'] != nil)
			self.challenge_key = ack['Payload'].v['EncryptionKey']
		end
		
		# Set the session identifier
		if (ack['Payload'].v['SessionKey'] != nil)
			self.session_id = ack['Payload'].v['SessionKey']
		end
				
		# Set the server GUID
		if (ack['Payload'].v['GUID'] != nil)
			self.server_guid = ack['Payload'].v['GUID']
		end

		return ack
	end	


	# Authenticate and establish a session
	def session_setup (*args)
		if (self.dialect =~ /^(NT LANMAN 1.0|NT LM 0.12)$/)
			return self.extended_security == 1 ?
				self.session_setup_ntlmv2(*args) : self.session_setup_ntlmv1(*args)
		end
		
		if (self.dialect =~ /^(LANMAN1.0|LM1.2X002)$/)
			return self.session_setup_clear(*args)
		end

		return nil
	end
	
	
	# Authenticate using extended security negotiation
	def session_setup_ntlmv2(user = '', pass = '', domain = '', name = 'WORKSTATION1')
	
		data = ''
		blob = UTILS.make_ntlmv2_secblob_init(domain, name)
		
		native_data = ''
		native_data << self.native_os + "\x00"
		native_data << self.native_lm + "\x00"		

		pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2801
		pkt['Payload']['SMB'].v['WordCount'] = 12
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1		
		pkt['Payload'].v['SecurityBlobLen'] = blob.length
		pkt['Payload'].v['Capabilities'] = 0x8000d05c
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = blob + native_data 
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse
		
		# Make sure the response we received was the correct type
		if (ack['Payload']['SMB'].v['Command'] != CONST::SMB_COM_SESSION_SETUP_ANDX)
			return nil
		end
		
		# We want to see the MORE_PROCESSING error message
		if (ack['Payload']['SMB'].v['ErrorClass'] != 0xc0000016)
			return nil
		end
		
		# Extract the SecurityBlob from the response
		data = ack['Payload'].v['Payload']
		blob = data.slice!(0, ack['Payload'].v['SecurityBlobLen'])

		# Extract the native lanman and os strings
		info = data.split(/\x00/)
		self.peer_native_os = info[0]
		self.peer_native_lm = info[1]
		
		# Save the temporary UserID for use in the next request
		temp_user_id = ack['Payload']['SMB'].v['UserID']
		
		# Extract the NTLM challenge key the lazy way
		cidx = blob.index("NTLMSSP\x00\x02\x00\x00\x00")
		if (cidx == -1)
			puts "No challenge found"
			return nil
		end
		
		# Store the challenge key
		self.challenge_key = blob[cidx + 24, 8]
		
		# Generate a random client-side challenge
		client_challenge = Rex::Text.rand_text(8)
		
		# Generate the nonce
		nonce = CRYPT.md5_hash(self.challenge_key + client_challenge)

		# Generate the NTLM hash
		resp_ntlm = CRYPT.ntlm_md4(pass, nonce[0, 8])
		
		# Generate the fake LANMAN hash
		resp_lmv2 = client_challenge + ("\x00" * 16)

		# Create the ntlmv2 security blob data
		blob = UTILS.make_ntlmv2_secblob_auth(domain, name, user, resp_lmv2, resp_ntlm)
		
		pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2801
		pkt['Payload']['SMB'].v['WordCount'] = 12
		pkt['Payload']['SMB'].v['UserID'] = temp_user_id
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1		
		pkt['Payload'].v['SecurityBlobLen'] = blob.length
		pkt['Payload'].v['Capabilities'] = 0x8000d05c
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = blob + native_data 
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse
		
		# Make sure the response we received was the correct type
		if (ack['Payload']['SMB'].v['Command'] != CONST::SMB_COM_SESSION_SETUP_ANDX)
			return nil
		end
		
		# We want to see no error message
		if (ack['Payload']['SMB'].v['ErrorClass'] != 0)
			return nil
		end				
		return ack
	end	
	
# public methods
	attr_accessor	:native_os, :native_lm, :encrypt_passwords, :extended_security
	attr_reader		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_reader		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_reader		:multiplex_id, :tree_id, :last_tree_id, :last_file_id, :process_id
	attr_reader		:security_mode, :server_guid
	
# private methods
protected
	attr_writer		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_writer		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_writer		:multiplex_id, :tree_id, :last_tree_id, :last_file_id, :process_id
	attr_writer		:security_mode, :server_guid
		
	attr_accessor	:socket
	

end
end
end
end
