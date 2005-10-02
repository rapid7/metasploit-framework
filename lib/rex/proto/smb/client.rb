module Rex
module Proto
module SMB
class Client

require 'rex/text'
require 'rex/struct2'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'rex/proto/smb/evasions'
require 'rex/proto/smb/crypt'
require 'rex/proto/smb/utils'


# Some short-hand class aliases
CONST = Rex::Proto::SMB::Constants
CRYPT = Rex::Proto::SMB::Crypt
UTILS = Rex::Proto::SMB::Utils
XCEPT = Rex::Proto::SMB::Exceptions
EVADE = Rex::Proto::SMB::Evasions

	def initialize (socket)
		self.socket = socket
		self.native_os = 'Windows 2000 2195'
		self.native_lm = 'Windows 2000 5.0'
		self.encrypt_passwords = 1
		self.extended_security = 0
		self.multiplex_id = rand(0xffff)
		self.process_id = rand(0xffff)
		self.read_timeout = 10
		self.evasion_level = EVADE::EVASION_NONE
	end
	
	# Read a SMB packet from the socket
	def smb_recv
	
		head = nil
		
		begin
			head = self.socket.timed_read(4, self.read_timeout)
		rescue TimeoutError
		rescue
			raise XCEPT::ReadHeader
		end
		
		if (head == nil or head.length != 4)
			raise XCEPT::ReadHeader
		end

		recv_len = head[2,2].unpack('n')[0]
		if (recv_len == 0)
			return head
		end
		
		body = ''
		while (body.length != recv_len)
			buff = ''

			begin
				buff = self.socket.timed_read(recv_len, self.read_timeout)
			rescue TimeoutError
			rescue
				raise XCEPT::ReadPacket
			end
			
			# Failed to read one packet within the time limit
			if (buff == nil or buff.length == 0)
				raise XCEPT::ReadPacket
			end
			
			# Append this packet to the read buffer and continue
			body << buff
		end
		
		return head + body
	end
	
	# Send a SMB packet down the socket
	def smb_send (data, evasion = self.evasion_level)
		
		size = EVADE.send_block_size(evasion)
		wait = EVADE.send_wait_time(evasion)
		
		begin
			# Just send the packet and return
			if (size == 0 or size >= data.length)
				return self.socket.put(data)
			end
			
			# Break the packet up into chunks and wait between them
			ret = 0
			while ( (chunk = data.slice!(0, size)).length > 0 )
				ret = self.socket.put(chunk)
				if (wait > 0)
					select(nil, nil, nil, wait)
				end
			end
			return ret
			
		rescue
			raise XCEPT::WritePacket
		end
	end
	
	# Set the SMB parameters to some reasonable defaults
	def smb_defaults(packet)
		packet.v['MultiplexID'] = self.multiplex_id.to_i
		packet.v['TreeID'] = self.last_tree_id.to_i
		packet.v['UserID'] = self.auth_user_id.to_i
		packet.v['ProcessID'] = self.process_id.to_i
	end
	
	
	# The main dispatcher for all incoming SMB packets
	def smb_recv_parse(expected_type, ignore_errors = false)
	
		# This will throw an exception if it fails to read the whole packet
		data = self.smb_recv
		
		pkt = CONST::SMB_BASE_PKT.make_struct
		pkt.from_s(data)
		res  = pkt
		
		begin
			case pkt['Payload']['SMB'].v['Command']

				when CONST::SMB_COM_NEGOTIATE
					res =  smb_parse_negotiate(pkt, data)

				when CONST::SMB_COM_SESSION_SETUP_ANDX
					res =  smb_parse_session_setup(pkt, data)

				when CONST::SMB_COM_TREE_CONNECT_ANDX
					res =  smb_parse_tree_connect(pkt, data)

				when CONST::SMB_COM_TREE_DISCONNECT
					res =  smb_parse_tree_disconnect(pkt, data)

				when CONST::SMB_COM_CREATE_ANDX
					res =  smb_parse_create(pkt, data)

				when CONST::SMB_COM_TRANSACTION, CONST::SMB_COM_TRANSACTION2
					res =  smb_parse_trans(pkt, data)

				when CONST::SMB_COM_NT_TRANSACT
					res =  smb_parse_nttrans(pkt, data)

				when CONST::SMB_COM_OPEN_ANDX
					res =  smb_parse_open(pkt, data)

				when CONST::SMB_COM_WRITE_ANDX
					res =  smb_parse_write(pkt, data)
					
				when CONST::SMB_COM_READ_ANDX
					res =  smb_parse_read(pkt, data)
					
				when CONST::SMB_COM_CLOSE
					res =  smb_parse_close(pkt, data)

				when CONST::SMB_COM_DELETE
					res =  smb_parse_delete(pkt, data)

				else 
					raise XCEPT::InvalidCommand
				end
				
			if (pkt['Payload']['SMB'].v['Command'] != expected_type)
				raise XCEPT::InvalidType
			end
			
			if (ignore_errors == false and pkt['Payload']['SMB'].v['ErrorClass'] != 0)
				raise XCEPT::ErrorCode
			end
			
		rescue XCEPT::InvalidWordCount, XCEPT::InvalidCommand, XCEPT::InvalidType, XCEPT::ErrorCode
				$!.word_count = pkt['Payload']['SMB'].v['WordCount']
				$!.command = pkt['Payload']['SMB'].v['Command']
				$!.error_code = pkt['Payload']['SMB'].v['ErrorClass']
				raise $!
		end
		
		return res
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

		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		
		
		raise XCEPT::InvalidWordCount
	end
	
	# Process incoming SMB_COM_SESSION_SETUP_ANDX packets
	def smb_parse_session_setup(pkt, data)
 		# Process NTLMv2 negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 4)
			res = CONST::SMB_SETUP_NTLMV2_RES_PKT.make_struct
			res.from_s(data)
			return res
		end
		
		# Process NTLMv1 and LANMAN responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 3)
			res = CONST::SMB_SETUP_RES_PKT.make_struct
			res.from_s(data)
			return res
		end	
			
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end	
		
		raise XCEPT::InvalidWordCount
	end	
	
	# Process incoming SMB_COM_TREE_CONNECT_ANDX packets
	def smb_parse_tree_connect(pkt, data)
 		
		if (pkt['Payload']['SMB'].v['WordCount'] == 3)
			res = CONST::SMB_TREE_CONN_RES_PKT.make_struct
			res.from_s(data)
			return res
		end
		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	

	# Process incoming SMB_COM_TREE_DISCONNECT packets
	def smb_parse_tree_disconnect(pkt, data)
 		
		# Process SMB responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			res = CONST::SMB_TREE_DISCONN_RES_PKT.make_struct
			res.from_s(data)
			return res
		end		

		raise XCEPT::InvalidWordCount
	end	
		
	# Process incoming SMB_COM_CREATE_ANDX packets
	def smb_parse_create(pkt, data)
 		
		if (pkt['Payload']['SMB'].v['WordCount'] == 42)
			res = CONST::SMB_CREATE_RES_PKT.make_struct
			res.from_s(data)
			return res
		end
		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	

	# Process incoming SMB_COM_TRANSACTION packets
	def smb_parse_trans(pkt, data)
 		
		if (pkt['Payload']['SMB'].v['WordCount'] == 10)
			res = CONST::SMB_TRANS_RES_PKT.make_struct
			res.from_s(data)
			return res
		end
		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	

	# Process incoming SMB_COM_NT_TRANSACT packets
	def smb_parse_nttrans(pkt, data)
 		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end
	
	# Process incoming SMB_COM_OPEN_ANDX packets
	def smb_parse_open(pkt, data)
 		# Process open responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 15)
			res = CONST::SMB_OPEN_RES_PKT.make_struct
			res.from_s(data)
			return res
		end
			
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	

	# Process incoming SMB_COM_WRITE_ANDX packets
	def smb_parse_write(pkt, data)
	
  		# Process write responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 6)
			res = CONST::SMB_WRITE_RES_PKT.make_struct
			res.from_s(data)
			return res
		end	
			
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	
	
	# Process incoming SMB_COM_READ_ANDX packets
	def smb_parse_read(pkt, data)
	
  		# Process write responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 12)
			res = CONST::SMB_READ_RES_PKT.make_struct
			res.from_s(data)
			return res
		end	
			
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	
	
	# Process incoming SMB_COM_CLOSE packets
	def smb_parse_close(pkt, data)
 		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			return pkt
		end		

		raise XCEPT::InvalidWordCount
	end	
	
	# Process incoming SMB_COM_DELETE packets
	def smb_parse_delete(pkt, data)
 		
		# Process SMB error responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 0)
			res = CONST::SMB_DELETE_RES_PKT.make_struct
			res.from_s(data)
			return res
		end		

		raise XCEPT::InvalidWordCount
	end
						
	# Request a SMB session over NetBIOS
	def session_request (name = '*SMBSERVER')
		
		data = ''
		data << "\x20" + UTILS.nbname_encode(name) + "\x00"
		data << "\x20" + CONST::NETBIOS_REDIR      + "\x00"

		pkt = CONST::NBRAW_PKT.make_struct
		pkt.v['Type'] = 0x81
		pkt['Payload'].v['Payload'] = data

		# Most SMB implementations can't handle this being fragmented
		self.smb_send(pkt.to_s, EVADE::EVASION_NONE)
		res = self.smb_recv
		
		ack = CONST::NBRAW_PKT.make_struct
		ack.from_s(res)

		if (ack.v['Type'] != 130)
			raise XCEPT::NetbiosSessionFailed
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
		ack = self.smb_recv_parse(CONST::SMB_COM_NEGOTIATE)

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
		
		if (ack['Payload'].v['ServerDate'] > 0)
			stamp = UTILS.servertime(ack['Payload'].v['ServerDate'],ack['Payload'].v['ServerTime'])
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

		raise XCEPT::UnknownDialect
	end

	# Authenticate using clear-text passwords
	def session_setup_clear(user = '', pass = '', domain = '')

		data = ''
		data << pass + "\x00"
		data << user + "\x00"
		data << domain + "\x00"
		data << self.native_os + "\x00"
		data << self.native_lm + "\x00"		
		
		pkt = CONST::SMB_SETUP_LANMAN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 10
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1		
		pkt['Payload'].v['PasswordLen'] = pass.length + 1
		pkt['Payload'].v['Capabilities'] = 64
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX)
		
		if (ack['Payload'].v['Action'] != 1 and user.length > 0)
			self.auth_user = user
		end
		
		self.auth_user_id = ack['Payload']['SMB'].v['UserID']
		
		info = ack['Payload'].v['Payload'].split(/\x00/)
		self.peer_native_os = info[0]
		self.peer_native_lm = info[1]
		self.default_domain = info[2]
				
		return ack
	end	
	
	# Authenticate using NTLMv1
	def session_setup_ntlmv1(user = '', pass = '', domain = '')
	
		hash_lm = pass.length > 0 ? CRYPT.lanman_des(pass, self.challenge_key) : ''
		hash_nt = pass.length > 0 ? CRYPT.ntlm_md4(pass, self.challenge_key)   : ''

		data = ''
		data << hash_lm
		data << hash_nt
		data << user + "\x00"
		data << domain + "\x00"
		data << self.native_os + "\x00"
		data << self.native_lm + "\x00"		
		
		pkt = CONST::SMB_SETUP_NTLMV1_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 13
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1		
		pkt['Payload'].v['PasswordLenLM'] = hash_lm.length
		pkt['Payload'].v['PasswordLenNT'] = hash_nt.length
		pkt['Payload'].v['Capabilities'] = 64
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX)
			
		if (ack['Payload'].v['Action'] != 1 and user.length > 0)
			self.auth_user = user
		end
		
		self.auth_user_id = ack['Payload']['SMB'].v['UserID']

		info = ack['Payload'].v['Payload'].split(/\x00/)
		self.peer_native_os = info[0]
		self.peer_native_lm = info[1]
		self.default_domain = info[2]
				
		return ack
	end	
	
	# Authenticate using extended security negotiation (NTLMv2)
	def session_setup_ntlmv2(user = '', pass = '', domain = '', name = nil)
	
		if (name == nil)
			name = Rex::Text.rand_text_alphanumeric(16)
		end
		
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
		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)
		
		# Make sure the error code tells us to continue processing
		if (ack['Payload']['SMB'].v['ErrorClass'] != 0xc0000016)
			failure = XCEPT::ErrorCode.new
			failure.word_count = ack['Payload']['SMB'].v['WordCount']
			failure.command = ack['Payload']['SMB'].v['Command']
			failure.error_code = ack['Payload']['SMB'].v['ErrorClass']
			raise failure
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
		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)
		
		# Make sure that authentication succeeded
		if (ack['Payload']['SMB'].v['ErrorClass'] != 0)
			if (user.length == 0)
				return self.session_setup_ntlmv1(user, pass, domain)
			end
			
			failure = XCEPT::ErrorCode.new
			failure.word_count = ack['Payload']['SMB'].v['WordCount']
			failure.command = ack['Payload']['SMB'].v['Command']
			failure.error_code = ack['Payload']['SMB'].v['ErrorClass']
			raise failure
		end
				
		self.auth_user_id = ack['Payload']['SMB'].v['UserID']

		return ack
	end	


	# Connect to a specified share with an optional password
	def tree_connect(share = 'IPC$', pass = '')

		data = ''
		data << pass + "\x00"
		data << share + "\x00"
		data << '?????' + "\x00"
		
		pkt = CONST::SMB_TREE_CONN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TREE_CONNECT_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 4
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['PasswordLen'] = pass.length + 1
		pkt['Payload'].v['Capabilities'] = 64
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_TREE_CONNECT_ANDX)
		
		self.last_tree_id = ack['Payload']['SMB'].v['TreeID']
		info = ack['Payload'].v['Payload'].split(/\x00/)
		
		return ack		
	end	

	# Disconnect from the current tree
	def tree_disconnect(tree_id = self.last_tree_id)

		pkt = CONST::SMB_TREE_DISCONN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
				
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TREE_DISCONNECT
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 0
		pkt['Payload']['SMB'].v['TreeID'] = tree_id
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_TREE_DISCONNECT)
		
		if (tree_id == self.last_tree_id)
			self.last_tree_id = 0
		end
		
		return ack		
	end	
	
	# Returns a SMB_CREATE_RES response for a given named pipe
	def open_named_pipe(pipe_name)
		self.create(EVADE.make_named_pipe_path(self.evasion_level, pipe_name))
	end
	
	# Creates a file or opens an existing pipe
	# TODO: Allow the caller to specify the hardcoded options
	def create(filename, disposition = 1)
		
		pkt = CONST::SMB_CREATE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_CREATE_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 24
		
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['FileNameLen'] = filename.length
		pkt['Payload'].v['CreateFlags'] = 0x16
		pkt['Payload'].v['AccessMask'] = 0x02019f
		pkt['Payload'].v['ShareAccess'] = 7
		pkt['Payload'].v['CreateOptions'] = 0x40
		pkt['Payload'].v['Impersonation'] = 2		
		pkt['Payload'].v['Disposition'] = disposition
		pkt['Payload'].v['Payload'] = filename + "\x00"
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_CREATE_ANDX)

		# Save off the FileID
		if (ack['Payload'].v['FileID'] > 0)
			self.last_file_id = ack['Payload'].v['FileID']	
		end
		
		return ack
	end

	# Deletes a file from a share
	def delete(filename, tree_id = self.last_tree_id)
		
		pkt = CONST::SMB_DELETE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_DELETE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['TreeID'] = tree_id
		pkt['Payload']['SMB'].v['WordCount'] = 1
		
		pkt['Payload'].v['SearchAttributes'] = 0x06
		pkt['Payload'].v['BufferFormat'] = 4
		pkt['Payload'].v['Payload'] = filename + "\x00"
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_DELETE)

		return ack
	end

	# Opens an existing file or creates a new one
	def open(filename, mode = 0x12, access = 0x42)
		
		pkt = CONST::SMB_OPEN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_OPEN_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 15
		
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['Access'] = access
		pkt['Payload'].v['SearchAttributes'] = 0x06
		pkt['Payload'].v['OpenFunction'] = mode	
		pkt['Payload'].v['Payload'] = filename + "\x00"
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_OPEN_ANDX)
		
		# Save off the FileID
		if (ack['Payload'].v['FileID'] > 0)
			self.last_file_id = ack['Payload'].v['FileID']	
		end
		
		return ack
	end

	# Closes an open file handle
	def close(file_id = self.last_file_id, tree_id = self.last_tree_id)
		
		pkt = CONST::SMB_CLOSE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_CLOSE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['TreeID'] = tree_id
		pkt['Payload']['SMB'].v['WordCount'] = 3
		
		pkt['Payload'].v['FileID'] = file_id
		pkt['Payload'].v['LastWrite'] = -1
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_CLOSE)

		return ack
	end


	# Writes data to an open file handle
	def write(file_id = self.last_file_id, offset = 0, data = '')
		
		pkt = CONST::SMB_WRITE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		data_offset = pkt.to_s.length - 4
		
		filler = EVADE.make_offset_filler(self.evasion_level, 4096 - data.length - data_offset)
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_WRITE_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 14
		
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['FileID'] = file_id
		pkt['Payload'].v['Offset'] = offset
		pkt['Payload'].v['Reserved2'] = -1
		pkt['Payload'].v['WriteMode'] = 8
		pkt['Payload'].v['Remaining'] = data.length
		# pkt['Payload'].v['DataLenHigh'] = (data.length / 65536).to_i
		pkt['Payload'].v['DataLenLow'] = (data.length % 65536).to_i
		pkt['Payload'].v['DataOffset'] = data_offset + filler.length
		pkt['Payload'].v['Payload'] = filler + data
		
		self.smb_send(pkt.to_s)
		
		ack = self.smb_recv_parse(CONST::SMB_COM_WRITE_ANDX)

		return ack
	end


	# Reads data from an open file handle
	def read(file_id = self.last_file_id, offset = 0, data_length = 64000)
		
		pkt = CONST::SMB_READ_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_READ_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 10
		
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['FileID'] = file_id
		pkt['Payload'].v['Offset'] = offset
		# pkt['Payload'].v['MaxCountHigh'] = (data_length / 65536).to_i
		pkt['Payload'].v['MaxCountLow'] = (data_length % 65536).to_i
		pkt['Payload'].v['MinCount'] = data_length
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_READ_ANDX)

		return ack
	end
	
	
	# Perform a transaction against a named pipe
	def trans_named_pipe (file_id, data = '')
		pipe = EVADE.make_trans_named_pipe_name(self.evasion_level)
		self.trans(pipe, '', data, 2, [0x26, file_id].pack('vv') )
	end

	# Perform a transaction against a given pipe name
	def trans (pipe, param = '', body = '', setup_count = 0, setup_data = '')

		# Null-terminate the pipe parameter if needed
		if (pipe[-1] != 0)
			pipe << "\x00"
		end
		
		pkt = CONST::SMB_TRANS_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		# Packets larger than mlen will cause XP SP2 to disconnect us ;-(		
		mlen = 4200
		
		# Figure out how much space is taken up by our current arguments
		xlen =  pipe.length + param.length + body.length

		filler1 = ''
		filler2 = ''

		# Fill any available space depending on the evasion settings
		if (xlen < mlen)
			filler1 = EVADE.make_offset_filler(self.evasion_level, (mlen-xlen)/2)
			filler2 = EVADE.make_offset_filler(self.evasion_level, (mlen-xlen)/2)
		end

		# Squish the whole thing together
		data = pipe + filler1 + param + filler2 + body
		
		# Throw some form of a warning out?
		if (data.length > mlen)
			# This call will more than likely fail :-(
		end
		
		# Calculate all of the offsets
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length + filler1.length
		data_offset = param_offset + filler2.length + param.length
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count
		
		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 1024
		pkt['Payload'].v['DataCountMax'] = 65504
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data
					
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_TRANSACTION)
		
		return ack
	end		


	# Perform a transaction2 request using the specified subcommand, parameters, and data
	def trans2 (subcommand, param = '', body = '', setup_count = 0, setup_data = '')

		data = param + body

		pkt = CONST::SMB_TRANS2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length
		data_offset = param_offset + param.length
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 15 + setup_count
		
		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 1024
		pkt['Payload'].v['DataCountMax'] = 65504
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data
		pkt['Payload'].v['Subcommand'] = subcommand
				
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_TRANSACTION2)
		
		return ack
	end
	

	# Perform a nttransaction request using the specified subcommand, parameters, and data
	def nttrans (subcommand, param = '', body = '', setup_count = 0, setup_data = '')

		data = param + body

		pkt = CONST::SMB_NTTRANS_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])
		
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length
		data_offset = param_offset + param.length
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_TRANSACT
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 19 + setup_count
		
		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 1024
		pkt['Payload'].v['DataCountMax'] = 65504
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data
		pkt['Payload'].v['Subcommand'] = subcommand
				
		pkt['Payload'].v['Payload'] = data
		
		self.smb_send(pkt.to_s)
		ack = self.smb_recv_parse(CONST::SMB_COM_NT_TRANSACT)
		return ack
	end



# public methods
	attr_accessor	:native_os, :native_lm, :encrypt_passwords, :extended_security, :read_timeout, :evasion_level
	attr_reader		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_reader		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_reader		:multiplex_id, :last_tree_id, :last_file_id, :process_id
	attr_reader		:security_mode, :server_guid
	
# private methods
protected
	attr_writer		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_writer		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_writer		:multiplex_id, :last_tree_id, :last_file_id, :process_id
	attr_writer		:security_mode, :server_guid
		
	attr_accessor	:socket
	

end
end
end
end
