module Rex
module Proto
module SMB
class Client

require 'rex/text'
require 'rex/struct2'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'rex/proto/smb/evasions'
require 'rex/proto/smb/utils'
require 'rex/proto/smb/crypt'
require 'rex/proto/ntlm/crypt'
require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/utils'


# Some short-hand class aliases
CONST = Rex::Proto::SMB::Constants
CRYPT = Rex::Proto::SMB::Crypt
UTILS = Rex::Proto::SMB::Utils
XCEPT = Rex::Proto::SMB::Exceptions
EVADE = Rex::Proto::SMB::Evasions
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_UTILS = Rex::Proto::NTLM::Utils

	def initialize(socket)
		self.socket = socket
		self.native_os = 'Windows 2000 2195'
		self.native_lm = 'Windows 2000 5.0'
		self.encrypt_passwords = true
		self.extended_security = false
		self.multiplex_id = rand(0xffff)
		self.process_id = rand(0xffff)
		self.read_timeout = 10
		self.evasion_opts = {

		# Padding is performed between packet headers and data
		'pad_data' => EVADE::EVASION_NONE,

		# File path padding is performed on all open/create calls
		'pad_file' => EVADE::EVASION_NONE,

		# Modify the \PIPE\ string in trans_named_pipe calls
		'obscure_trans_pipe' => EVADE::EVASION_NONE,
		}
		self.verify_signature = false
		self.use_ntlmv2 = false
		self.usentlm2_session = true
		self.send_lm = true
		self.use_lanman_key = false
		self.send_ntlm  = true
		#signing
		self.sequence_counter  	= 0
		self.signing_key  	= ''
		self.require_signing	= false
		
	end

	# Read a SMB packet from the socket
	def smb_recv

		data = socket.timed_read(4, self.read_timeout)
		if (data.nil? or data.length < 4)
			raise XCEPT::NoReply
		end

		recv_len = data[2,2].unpack('n')[0]
		if (recv_len == 0)
			return data
		end

		recv_len += 4

		while (data.length != recv_len)
			buff = ''

			begin
				buff << self.socket.timed_read(recv_len - data.length, self.read_timeout)
			rescue Timeout::Error
			rescue
				raise XCEPT::ReadPacket
			end

			if (buff.nil? or buff.length == 0)
				raise XCEPT::ReadPacket
			end

			data << buff
		end

		#signing
		if self.require_signing && self.signing_key != ''
			if self.verify_signature		
				raise XCEPT::IncorrectSigningError if not CRYPT::is_signature_correct?(self.signing_key,self.sequence_counter,data)			
			end
			self.sequence_counter += 1
		end

		return data


	end

	# Send a SMB packet down the socket
	def smb_send(data, evasion_level=0)

		# evasion_level is ignored, since real evasion happens
		# in the actual socket layer

		size = 0
		wait = 0

		#signing
		if self.require_signing && self.signing_key != ''
			data = CRYPT::sign_smb_packet(self.signing_key, self.sequence_counter, data)
			self.sequence_counter += 1
		end

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
					::IO.select(nil, nil, nil, wait)
				end
			end
			return ret
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

				when CONST::SMB_COM_NT_CREATE_ANDX
					res =  smb_parse_create(pkt, data)

				when CONST::SMB_COM_TRANSACTION, CONST::SMB_COM_TRANSACTION2
					res =  smb_parse_trans(pkt, data)

				when CONST::SMB_COM_NT_TRANSACT
					res =  smb_parse_nttrans(pkt, data)

				when CONST::SMB_COM_NT_TRANSACT_SECONDARY
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
	def smb_parse_negotiate(pkt, data)
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
		# Process NTLMSSP negotiate responses
		if (pkt['Payload']['SMB'].v['WordCount'] == 4)
			res = CONST::SMB_SETUP_NTLMV2_RES_PKT.make_struct
			res.from_s(data)
			return res
		end

		# Process LANMAN responses
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

	# Process incoming SMB_COM_NT_CREATE_ANDX packets
	def smb_parse_create(pkt, data)

		# Windows says 42, but Samba says 34, same structure :-/
		if (pkt['Payload']['SMB'].v['WordCount'] == 42)
			res = CONST::SMB_CREATE_RES_PKT.make_struct
			res.from_s(data)
			return res
		end

		if (pkt['Payload']['SMB'].v['WordCount'] == 34)
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

		if (pkt['Payload']['SMB'].v['WordCount'] >= 18)
			res = CONST::SMB_NTTRANS_RES_PKT.make_struct
			res.from_s(data)
			return res
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

		# Process read responses
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
	def session_request(name = '*SMBSERVER', do_recv = true)

		name ||= '*SMBSERVER'

		data = ''
		data << "\x20" + UTILS.nbname_encode(name) + "\x00"
		data << "\x20" + CONST::NETBIOS_REDIR      + "\x00"

		pkt = CONST::NBRAW_PKT.make_struct
		pkt.v['Type'] = 0x81
		pkt['Payload'].v['Payload'] = data

		# Most SMB implementations can't handle this being fragmented
		ret = self.smb_send(pkt.to_s, EVADE::EVASION_NONE)
		return ret if not do_recv

		res = self.smb_recv

		ack = CONST::NBRAW_PKT.make_struct
		ack.from_s(res)

		if (ack.v['Type'] != 130)
			raise XCEPT::NetbiosSessionFailed
		end

		return ack
	end

	# Negotiate a SMB dialect
	def negotiate(smb_extended_security=true, do_recv = true)

		dialects = ['LANMAN1.0', 'LM1.2X002' ]

		if (self.encrypt_passwords)
			dialects.push('NT LANMAN 1.0', 'NT LM 0.12')
		end

		data = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

		pkt = CONST::SMB_NEG_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18

		if(smb_extended_security)
			pkt['Payload']['SMB'].v['Flags2'] = 0x2801
		else
			pkt['Payload']['SMB'].v['Flags2'] = 0xc001
		end

		pkt['Payload'].v['Payload'] = data

		ret = self.smb_send(pkt.to_s, EVADE::EVASION_NONE)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_NEGOTIATE)

		idx = ack['Payload'].v['Dialect']

		# Check for failed dialect selection
		if (idx < 0 or idx >= dialects.length)
			return nil
		end

		# Set the selected dialect
		self.dialect = dialects[idx]

		# Does the server support extended security negotiation?
		if (ack['Payload'].v['Capabilities'] & 0x80000000 != 0)
			self.extended_security = true
		end

		# Set the security mode
		self.security_mode = ack['Payload'].v['SecurityMode']

		#set require_signing
		if (ack['Payload'].v['SecurityMode'] & 0x08 != 0)
			self.require_signing	= true
		end

		# Set the challenge key
		if (ack['Payload'].v['EncryptionKey'] != nil)
			self.challenge_key = ack['Payload'].v['EncryptionKey']
		else
			# Handle Windows NT 4.0 responses
			if (ack['Payload'].v['KeyLength'] > 0)
				self.challenge_key = ack['Payload'].v['Payload'][0, ack['Payload'].v['KeyLength']]
			end
		end

		# Set the session identifier
		if (ack['Payload'].v['SessionKey'] != nil)
			self.session_id = ack['Payload'].v['SessionKey']
		end

		# Extract the payload (GUID/SecurityBlob)
		buf = ack['Payload'].v['Payload'] || ''

		# Set the server GUID
		if (self.extended_security and buf.length >= 16)
			self.server_guid = buf[0,16]
		end

		# Set the server SecurityBlob
		if (self.extended_security and buf.length > 16)
			# buf[16, buf.length - 16]
		end

		# The number of 100-nanosecond intervals that have elapsed since January 1, 1601, in
		# Coordinated Universal Time (UTC) format.
		# We convert it to a friendly Time object here
		self.system_time = UTILS.time_smb_to_unix(ack['Payload'].v['SystemTimeHigh'],ack['Payload'].v['SystemTimeLow'])
		self.system_time = ::Time.at( self.system_time )

		# A signed 16-bit signed integer that represents the server's time zone, in minutes, 
		# from UTC. The time zone of the server MUST be expressed in minutes, plus or minus, 
		# from UTC.
		# NOTE: althought the spec says +/- it doesn't say that it should be inverted :-/
		system_zone = ack['Payload'].v['ServerTimeZone']
		# Convert the ServerTimeZone to _seconds_ and back into a signed integer :-/
		if (system_zone & 0x8000) == 0x8000
			system_zone = (( (~system_zone)  & 0x0FFF ) + 1 )
		else
			system_zone *= -1
		end
		self.system_zone = system_zone * 60

		return ack
	end


	# Authenticate and establish a session
	def session_setup(*args)

		if (self.dialect =~ /^(NT LANMAN 1.0|NT LM 0.12)$/)
			
			if (self.challenge_key)
				return self.session_setup_no_ntlmssp(*args)
			end

			if ( self.extended_security )
				return self.session_setup_with_ntlmssp(*args)
			end

		end

		return self.session_setup_clear(*args)
	end

	# Authenticate using clear-text passwords
	def session_setup_clear(user = '', pass = '', domain = '', do_recv = true)

		data = [ pass, user, domain, self.native_os, self.native_lm ].collect{ |a| a + "\x00" }.join('');

		pkt = CONST::SMB_SETUP_LANMAN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 10
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1
		pkt['Payload'].v['PasswordLen'] = pass.length + 1
		pkt['Payload'].v['Capabilities'] = 64
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = data

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

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

	# Authenticate without NTLMSSP
	def session_setup_no_ntlmssp(user = '', pass = '', domain = '', do_recv = true)

		raise XCEPT::NTLM1MissingChallenge if not self.challenge_key
		#we can not yet handle signing in this situation
		raise XCEPT::NTLM2MissingChallenge if self.require_signing
		if (pass.length == 65)
			arglm = { 	:lm_hash => [ pass.upcase()[0,32] ].pack('H32'),
					:challenge =>  self.challenge_key }
			hash_lm = NTLM_CRYPT::lm_response(arglm)

			argntlm = { 	:ntlm_hash =>  [ pass.upcase()[33,65] ].pack('H32'), 
					:challenge =>  self.challenge_key }
			hash_nt = NTLM_CRYPT::ntlm_response(argntlm)
		else
			hash_lm = pass.length > 0 ? NTLM_CRYPT.lanman_des(pass, self.challenge_key) : ''
			hash_nt = pass.length > 0 ? NTLM_CRYPT.ntlm_md4(pass, self.challenge_key)   : ''
		end

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

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


	# Authenticate without ntlmssp with a precomputed hash pair
	def session_setup_no_ntlmssp_prehash(user, domain, hash_lm, hash_nt, do_recv = true)

		raise XCEPT::NTLM2MissingChallenge if self.require_signing

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

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

	# Authenticate using extended security negotiation 
	def session_setup_with_ntlmssp(user = '', pass = '', domain = '', name = nil, do_recv = true)

		if require_signing 
			ntlmssp_flags = 0xe2088215
		else

			ntlmssp_flags = 0xa2080205
		end

		if self.usentlm2_session
			if self.use_ntlmv2
				#set Negotiate Target Info
				ntlmssp_flags |= NTLM_CONST::NEGOTIATE_TARGET_INFO	
			end

		else
			#remove the ntlm2_session flag
			ntlmssp_flags &= 0xfff7ffff
			#set lanmanflag only when lm and ntlm are sent
			if self.send_lm
				ntlmssp_flags |= NTLM_CONST::NEGOTIATE_LMKEY if self.use_lanman_key
			end
		end
	
		#we can also downgrade ntlm2_session when we send only lmv1
		ntlmssp_flags &= 0xfff7ffff if self.usentlm2_session && (not self.use_ntlmv2) && (not self.send_ntlm)


		if (name == nil)
			name = Rex::Text.rand_text_alphanumeric(16)
		end

		blob = NTLM_UTILS.make_ntlmssp_secblob_init(domain, name, ntlmssp_flags)

		native_data = ''
		native_data << self.native_os + "\x00"
		native_data << self.native_lm + "\x00"

		pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end
		pkt['Payload']['SMB'].v['WordCount'] = 12
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1
		pkt['Payload'].v['SecurityBlobLen'] = blob.length
		pkt['Payload'].v['Capabilities'] = 0x800000d4
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = blob + native_data

		ret = self.smb_send(pkt.to_s)

		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)


		# The server doesn't know about NTLM_NEGOTIATE
		if (ack['Payload']['SMB'].v['ErrorClass'] == 0x00020002)
			return session_setup_no_ntlmssp(user, pass, domain)
		end

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
			raise XCEPT::NTLM2MissingChallenge
		end

		# Store the challenge key
		self.challenge_key = blob[cidx + 24, 8]

		# Extract the address list from the blob
		alist_len,alist_mlen,alist_off = blob[cidx + 40, 8].unpack("vvV")
		alist_buf = blob[cidx + alist_off, alist_len]
		chall_MsvAvTimestamp = nil
		while(alist_buf.length > 0)
			atype, alen = alist_buf.slice!(0,4).unpack('vv')
			break if atype == 0x00
			addr = alist_buf.slice!(0, alen)
			case atype
			when 1
				#netbios name
				self.default_name =  addr.gsub("\x00", '')
			when 2
				#netbios domain
				self.default_domain = addr.gsub("\x00", '')
			when 3
				#dns name
				self.dns_host_name =  addr.gsub("\x00", '')
			when 4
				#dns domain
				self.dns_domain_name =  addr.gsub("\x00", '')
			when 5
				#The FQDN of the forest.
			when 6
				#A 32-bit value indicating server or client configuration
			when 7
				# client time
				chall_MsvAvTimestamp = addr
			when 8
				#A Restriction_Encoding structure 
			when 9
				#The SPN of the target server. 
			when 10
				#A channel bindings hash.
			end
		end
	
		#calculate the lm/ntlm response
		resp_lm = "\x00" * 24
		resp_ntlm = "\x00" * 24

		client_challenge = Rex::Text.rand_text(8)
		ntlm_cli_challenge = ''
		if self.send_ntlm  #should be default
			if self.usentlm2_session

				if self.use_ntlmv2
				#This is only a partial implementation, in some situation recent servers may send STATUS_INVALID_PARAMETER 
				#answer must then be somewhere in [MS-NLMP].pdf around 3.1.5.2.1 :-/
					ntlm_cli_challenge = NTLM_UTILS::make_ntlmv2_clientchallenge(default_domain, default_name, dns_domain_name, 
												dns_host_name,client_challenge , chall_MsvAvTimestamp)
					if (pass.length == 65)
						argntlm = { 	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user, 
													[ pass.upcase()[33,65] ].pack('H32'), 
													domain,{:pass_is_hash => true}),
								:challenge => self.challenge_key }
					else
						argntlm = { 	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user, pass, domain),
								:challenge => self.challenge_key }
					end
						optntlm = { 	:nt_client_challenge => ntlm_cli_challenge}
					ntlmv2_response = NTLM_CRYPT::ntlmv2_response(argntlm,optntlm)
					resp_ntlm = ntlmv2_response 
					if self.send_lm
						if (pass.length == 65)
							arglm = {	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user, 
													[ pass.upcase()[33,65] ].pack('H32'), 
													domain,{:pass_is_hash => true}),
									:challenge => self.challenge_key }
						else
							arglm = {	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user,pass, domain),
									:challenge => self.challenge_key }
						end
						optlm = {	:client_challenge => client_challenge}
						resp_lm = NTLM_CRYPT::lmv2_response(arglm, optlm)
					else
						resp_lm = "\x00" * 24
					end

				else # ntlm2_session	
					if (pass.length == 65)
						argntlm = { 	:ntlm_hash =>  [ pass.upcase()[33,65] ].pack('H32'), 
								:challenge => self.challenge_key }
					else
						argntlm = { 	:ntlm_hash =>  NTLM_CRYPT::ntlm_hash(pass), 
								:challenge => self.challenge_key }
					end
					optntlm = {	:client_challenge => client_challenge}
					resp_ntlm = NTLM_CRYPT::ntlm2_session(argntlm,optntlm).join[24,24]
					# Generate the fake LANMAN hash
					resp_lm = client_challenge + ("\x00" * 16)
				end

			else #we use lmv1/ntlmv1
				if (pass.length == 65)
					argntlm = { 	:ntlm_hash =>  [ pass.upcase()[33,65] ].pack('H32'), 
							:challenge =>  self.challenge_key }
				else
					argntlm = { 	:ntlm_hash =>  NTLM_CRYPT::ntlm_hash(pass), 
							:challenge =>  self.challenge_key }
				end
				resp_ntlm = NTLM_CRYPT::ntlm_response(argntlm)
				if self.send_lm
					if (pass.length == 65)
						arglm = { 	:lm_hash => [ pass.upcase()[0,32] ].pack('H32'),
								:challenge =>  self.challenge_key }
					else
						arglm = { 	:lm_hash => NTLM_CRYPT::lm_hash(pass),
								:challenge =>  self.challenge_key }
					end
					resp_lm = NTLM_CRYPT::lm_response(arglm)
				else
					#when windows does not send lm in ntlmv1 type response,
					# it gives lm response the same value as ntlm response
					resp_lm  = resp_ntlm
				end
			end
		else #send_ntlm = false 
			#lmv2
			if self.usentlm2_session && self.use_ntlmv2
				if (pass.length == 65)
					arglm = {	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user, 
												[ pass.upcase()[33,65] ].pack('H32'), 
												domain,{:pass_is_hash => true}),
							:challenge => self.challenge_key }
				else
					arglm = {	:ntlmv2_hash =>  NTLM_CRYPT::ntlmv2_hash(user,pass, domain),
							:challenge => self.challenge_key }
				end
				optlm = {	:client_challenge => client_challenge}
				resp_lm = NTLM_CRYPT::lmv2_response(arglm, optlm)
			else
				if (pass.length == 65)
					arglm = { 	:lm_hash => [ pass.upcase()[0,32] ].pack('H32'),
							:challenge =>  self.challenge_key }
				else
					arglm = { 	:lm_hash => NTLM_CRYPT::lm_hash(pass),
							:challenge =>  self.challenge_key }
				end
				resp_lm = NTLM_CRYPT::lm_response(arglm)
			end
			resp_ntlm = ""
		end


		#create the sessionkey (aka signing key, aka mackey) and encrypted session key
		#server will decide for key_size and key_exchange
		enc_session_key = ''
		if self.require_signing
			if (pass.length == 65)
				raise ArgumentError, "pth not yet implemented when signing is required by server, coming soon"
			end
			server_ntlmssp_flags = blob[cidx + 20, 4].unpack("V")[0]
			#set default key size and key exchange values
			key_size = 40
			key_exchange = false
			#remove ntlmssp.negotiate56
			ntlmssp_flags &= 0x7fffffff
			#remove ntlmssp.negotiatekeyexch
			ntlmssp_flags &= 0xbfffffff
			#remove ntlmssp.negotiate128
			ntlmssp_flags &= 0xdfffffff
			#check the keyexchange
			if server_ntlmssp_flags & NTLM_CONST::NEGOTIATE_KEY_EXCH != 0 then
				key_exchange = true
				ntlmssp_flags |= NTLM_CONST::NEGOTIATE_KEY_EXCH
			end
			#check 128bits
			if server_ntlmssp_flags & NTLM_CONST::NEGOTIATE_128 != 0 then
				key_size = 128
				ntlmssp_flags |= NTLM_CONST::NEGOTIATE_128
				ntlmssp_flags |= NTLM_CONST::NEGOTIATE_56
			#check 56bits
			else
				if server_ntlmssp_flags & NTLM_CONST::NEGOTIATE_56 != 0 then
					key_size = 56
					ntlmssp_flags |= NTLM_CONST::NEGOTIATE_56
				end
			end

			#generate the user session key
			lanman_weak = false
			if self.send_ntlm  #should be default
				if self.usentlm2_session
					if self.use_ntlmv2
						user_session_key = NTLM_CRYPT::ntlmv2_user_session_key(user, pass, domain, 
												self.challenge_key, ntlm_cli_challenge)
					else
						user_session_key = NTLM_CRYPT::ntlm2_session_user_session_key(pass, self.challenge_key, client_challenge)
					end
				else #lmv1 / ntlmv1
					if self.send_lm
						if self.use_lanman_key
							user_session_key = NTLM_CRYPT::lanman_session_key(pass, self.challenge_key)
							lanman_weak = true
						else
							user_session_key = NTLM_CRYPT::ntlmv1_user_session_key(pass )
						end
					end
				end
			else
					if self.usentlm2_session && self.use_ntlmv2
						user_session_key = NTLM_CRYPT::lmv2_user_session_key(user, pass, domain, 
												self.challenge_key, client_challenge)
					else
						user_session_key = NTLM_CRYPT::lmv1_user_session_key(pass )
					end
			end

			user_session_key = NTLM_CRYPT::make_weak_sessionkey(user_session_key,key_size, lanman_weak)			
			self.sequence_counter = 0
			#sessionkey and encrypted session key
			if key_exchange
				self.signing_key = Rex::Text.rand_text(16)
				enc_session_key = NTLM_CRYPT::encrypt_sessionkey(self.signing_key, user_session_key)
			else
				self.signing_key = user_session_key
			end
	
		end
		# Create the security blob data
		blob = NTLM_UTILS.make_ntlmssp_secblob_auth(domain, name, user, resp_lm, resp_ntlm, enc_session_key, ntlmssp_flags)

		pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end
		pkt['Payload']['SMB'].v['WordCount'] = 12
		pkt['Payload']['SMB'].v['UserID'] = temp_user_id
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1
		pkt['Payload'].v['Capabilities'] = 0x8000d05c
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['SecurityBlobLen'] = blob.length
		pkt['Payload'].v['Payload'] = blob + native_data

		# NOTE: if do_recv is set to false, we cant reach here...
		self.smb_send(pkt.to_s)

		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)

		# Make sure that authentication succeeded
		if (ack['Payload']['SMB'].v['ErrorClass'] != 0)
			if (user.length == 0)
				return self.session_setup_no_ntlmssp(user, pass, domain)
			end

			failure = XCEPT::ErrorCode.new
			failure.word_count = ack['Payload']['SMB'].v['WordCount']
			failure.command = ack['Payload']['SMB'].v['Command']
			failure.error_code = ack['Payload']['SMB'].v['ErrorClass']
			raise failure
		end

		self.auth_user_id = ack['Payload']['SMB'].v['UserID']

		if (ack['Payload'].v['Action'] != 1 and user.length > 0)
			self.auth_user = user
		end

		return ack
	end


	# An exploit helper function for sending arbitrary SPNEGO blobs
	def session_setup_with_ntlmssp_blob(blob = '', do_recv = true)
		native_data = ''
		native_data << self.native_os + "\x00"
		native_data << self.native_lm + "\x00"

		pkt = CONST::SMB_SETUP_NTLMV2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2801
		pkt['Payload']['SMB'].v['WordCount'] = 12
		pkt['Payload']['SMB'].v['UserID'] = 0
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['MaxBuff'] = 0xffdf
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['VCNum'] = 1
		pkt['Payload'].v['SecurityBlobLen'] = blob.length
		pkt['Payload'].v['Capabilities'] = 0x8000d05c
		pkt['Payload'].v['SessionKey'] = self.session_id
		pkt['Payload'].v['Payload'] = blob + native_data

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, false)
	end


	# Authenticate using extended security negotiation (NTLMSSP), but stop half-way, using the temporary ID
	def session_setup_with_ntlmssp_temp(domain = '', name = nil, do_recv = true)

		if (name == nil)
			name = Rex::Text.rand_text_alphanumeric(16)
		end

		blob = NTLM_UTILS.make_ntlmssp_secblob_init(domain, name)

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)

		# The server doesn't know about NTLM_NEGOTIATE, try ntlmv1
		if (ack['Payload']['SMB'].v['ErrorClass'] == 0x00020002)
			return session_setup_no_ntlmssp(user, pass, domain)
		end

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
		self.auth_user_id = ack['Payload']['SMB'].v['UserID']

		# Extract the NTLM challenge key the lazy way
		cidx = blob.index("NTLMSSP\x00\x02\x00\x00\x00")

		if (cidx == -1)
			raise XCEPT::NTLM2MissingChallenge
		end

		# Store the challenge key
		self.challenge_key = blob[cidx + 24, 8]

		return ack
	end

	# Connect to a specified share with an optional password
	def tree_connect(share = 'IPC$', pass = '', do_recv = true)

		data = [ pass, share, '?????' ].collect{ |a| a + "\x00" }.join('');

		pkt = CONST::SMB_TREE_CONN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TREE_CONNECT_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 4
		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['PasswordLen'] = pass.length + 1
		pkt['Payload'].v['Capabilities'] = 64
		pkt['Payload'].v['Payload'] = data

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_TREE_CONNECT_ANDX)

		self.last_tree_id = ack['Payload']['SMB'].v['TreeID']
		# why bother?
		# info = ack['Payload'].v['Payload'].split(/\x00/)

		return ack
	end

	# Disconnect from the current tree
	def tree_disconnect(tree_id = self.last_tree_id, do_recv = true)

		pkt = CONST::SMB_TREE_DISCONN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TREE_DISCONNECT
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 0
		pkt['Payload']['SMB'].v['TreeID'] = tree_id

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_TREE_DISCONNECT)

		if (tree_id == self.last_tree_id)
			self.last_tree_id = 0
		end

		return ack
	end

	# Returns a SMB_CREATE_RES response for a given named pipe
	def create_pipe(filename, disposition = 1, impersonation = 2)
		self.create(filename)
	end

	# Creates a file or opens an existing pipe
	def create(filename, disposition = 1, impersonation = 2, do_recv = true)

		pkt = CONST::SMB_CREATE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 24

		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['FileNameLen'] = filename.length
		pkt['Payload'].v['CreateFlags'] = 0x16
		pkt['Payload'].v['AccessMask'] = 0x02000000 # Maximum Allowed
		pkt['Payload'].v['ShareAccess'] = 7
		pkt['Payload'].v['CreateOptions'] = 0
		pkt['Payload'].v['Impersonation'] = impersonation
		pkt['Payload'].v['Disposition'] = disposition
		pkt['Payload'].v['Payload'] = filename + "\x00"

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_NT_CREATE_ANDX)

		# Save off the FileID
		if (ack['Payload'].v['FileID'] > 0)
			self.last_file_id = ack['Payload'].v['FileID']
		end

		return ack
	end

	# Deletes a file from a share
	def delete(filename, tree_id = self.last_tree_id, do_recv = true)

		pkt = CONST::SMB_DELETE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_DELETE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['TreeID'] = tree_id
		pkt['Payload']['SMB'].v['WordCount'] = 1

		pkt['Payload'].v['SearchAttributes'] = 0x06
		pkt['Payload'].v['BufferFormat'] = 4
		pkt['Payload'].v['Payload'] = filename + "\x00"

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_DELETE)

		return ack
	end

	# Opens an existing file or creates a new one
	def open(filename, mode = 0x12, access = 0x42, do_recv = true)

		pkt = CONST::SMB_OPEN_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_OPEN_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 15

		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['Access'] = access
		pkt['Payload'].v['SearchAttributes'] = 0x06
		pkt['Payload'].v['OpenFunction'] = mode
		pkt['Payload'].v['Payload'] = filename + "\x00"

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_OPEN_ANDX)

		# Save off the FileID
		if (ack['Payload'].v['FileID'] > 0)
			self.last_file_id = ack['Payload'].v['FileID']
		end

		return ack
	end

	# Closes an open file handle
	def close(file_id = self.last_file_id, tree_id = self.last_tree_id, do_recv = true)

		pkt = CONST::SMB_CLOSE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_CLOSE
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['TreeID'] = tree_id
		pkt['Payload']['SMB'].v['WordCount'] = 3

		pkt['Payload'].v['FileID'] = file_id
		pkt['Payload'].v['LastWrite'] = -1

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_CLOSE)

		return ack
	end

	# Writes data to an open file handle
	def write(file_id = self.last_file_id, offset = 0, data = '', do_recv = true)
		pkt = CONST::SMB_WRITE_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		data_offset = pkt.to_s.length - 4

		filler = EVADE.make_offset_filler(evasion_opts['pad_data'], 4096 - data.length - data_offset)

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_WRITE_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2805
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_WRITE_ANDX)

		return ack
	end


	# Reads data from an open file handle
	def read(file_id = self.last_file_id, offset = 0, data_length = 64000, do_recv = true)

		pkt = CONST::SMB_READ_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_READ_ANDX
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 10

		pkt['Payload'].v['AndX'] = 255
		pkt['Payload'].v['FileID'] = file_id
		pkt['Payload'].v['Offset'] = offset
		# pkt['Payload'].v['MaxCountHigh'] = (data_length / 65536).to_i
		pkt['Payload'].v['MaxCountLow'] = (data_length % 65536).to_i
		pkt['Payload'].v['MinCount'] = data_length
		pkt['Payload'].v['Reserved2'] = -1

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_READ_ANDX, true)

		err = ack['Payload']['SMB'].v['ErrorClass']

		# Catch some non-fatal error codes
		if (err != 0 && err != CONST::SMB_ERROR_BUFFER_OVERFLOW)
			failure = XCEPT::ErrorCode.new
			failure.word_count = ack['Payload']['SMB'].v['WordCount']
			failure.command = ack['Payload']['SMB'].v['Command']
			failure.error_code = ack['Payload']['SMB'].v['ErrorClass']
			raise failure
		end

		return ack
	end


	# Perform a transaction against a named pipe
	def trans_named_pipe(file_id, data = '', no_response = nil)
		pipe = EVADE.make_trans_named_pipe_name(evasion_opts['pad_file'])
		self.trans(pipe, '', data, 2, [0x26, file_id].pack('vv'), no_response)
	end

	# Perform a mailslot write over SMB
	# Warning: This can kill srv.sys unless MS06-035 is applied
	def trans_mailslot (name, data = '')
		# Setup data must be:
		#  Operation: 1 (write)
		#   Priority: 0
		#      Class: Reliable
		self.trans_maxzero(name, '', data, 3, [1, 0, 1].pack('vvv'), true )
	end

	# Perform a transaction against a given pipe name
	def trans(pipe, param = '', body = '', setup_count = 0, setup_data = '', no_response = false, do_recv = true)

		# Null-terminate the pipe parameter if needed
		if (pipe[-1,1] != "\x00")
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
			filler1 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
			filler2 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
		end

		# Squish the whole thing together
		data = pipe + filler1 + param + filler2 + body

		# Throw some form of a warning out?
		if (data.length > mlen)
			# XXX This call will more than likely fail :-(
		end

		# Calculate all of the offsets
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length + filler1.length
		data_offset = param_offset + filler2.length + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

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

		if no_response
			pkt['Payload'].v['Flags'] = 2
		end

		ret = self.smb_send(pkt.to_s)
		return ret if no_response or not do_recv

		self.smb_recv_parse(CONST::SMB_COM_TRANSACTION)
	end



	# Perform a transaction against a given pipe name
	# Difference from trans: sets MaxParam/MaxData to zero
	# This is required to trigger mailslot bug :-(
	def trans_maxzero(pipe, param = '', body = '', setup_count = 0, setup_data = '', no_response = false, do_recv = true)

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
			filler1 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
			filler2 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
		end

		# Squish the whole thing together
		data = pipe + filler1 + param + filler2 + body

		# Throw some form of a warning out?
		if (data.length > mlen)
			# XXX This call will more than likely fail :-(
		end

		# Calculate all of the offsets
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length + filler1.length
		data_offset = param_offset + filler2.length + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count

		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 0
		pkt['Payload'].v['DataCountMax'] = 0
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data

		pkt['Payload'].v['Payload'] = data

		if no_response
			pkt['Payload'].v['Flags'] = 2
		end

		ret = self.smb_send(pkt.to_s)
		return ret if no_response or not do_recv

		self.smb_recv_parse(CONST::SMB_COM_TRANSACTION)
	end


	# Perform a transaction against a given pipe name (no null terminator)
	def trans_nonull(pipe, param = '', body = '', setup_count = 0, setup_data = '', no_response = false, do_recv = true)

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
			filler1 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
			filler2 = EVADE.make_offset_filler(evasion_opts['pad_data'], (mlen-xlen)/2)
		end

		# Squish the whole thing together
		data = pipe + filler1 + param + filler2 + body

		# Throw some form of a warning out?
		if (data.length > mlen)
			# XXX This call will more than likely fail :-(
		end

		# Calculate all of the offsets
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset + pipe.length + filler1.length
		data_offset = param_offset + filler2.length + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count

		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 0
		pkt['Payload'].v['DataCountMax'] = 0
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data

		pkt['Payload'].v['Payload'] = data

		if no_response
			pkt['Payload'].v['Flags'] = 2
		end

		ret = self.smb_send(pkt.to_s)
		return ret if no_response or not do_recv

		self.smb_recv_parse(CONST::SMB_COM_TRANSACTION)
	end

	# Perform a transaction2 request using the specified subcommand, parameters, and data
	def trans2(subcommand, param = '', body = '', do_recv = true)

		setup_count = 1
		setup_data = [subcommand].pack('v')

		data = param + body

		pkt = CONST::SMB_TRANS2_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset
		data_offset = param_offset + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_TRANSACTION2)

		return ack
	end


	# Perform a nttransaction request using the specified subcommand, parameters, and data
	def nttrans(subcommand, param = '', body = '', setup_count = 0, setup_data = '', do_recv = true)

		data = param + body

		pkt = CONST::SMB_NTTRANS_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset
		data_offset = param_offset + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_TRANSACT
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

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

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_NT_TRANSACT)
		return ack
	end

	# Perform a nttransaction request using the specified subcommand, parameters, and data
	def nttrans_secondary(param = '', body = '', do_recv = true)

		data = param + body

		pkt = CONST::SMB_NTTRANS_SECONDARY_PKT.make_struct
		self.smb_defaults(pkt['Payload']['SMB'])

		base_offset = pkt.to_s.length - 4
		param_offset = base_offset
		data_offset = param_offset + param.length

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_TRANSACT_SECONDARY
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		if self.require_signing
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] = 0x2807
		else
			#ascii
			pkt['Payload']['SMB'].v['Flags2'] =  0x2801
		end

		pkt['Payload']['SMB'].v['WordCount'] = 18

		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset

		pkt['Payload'].v['Payload'] = data

		ret = self.smb_send(pkt.to_s)
		return ret if not do_recv

		ack = self.smb_recv_parse(CONST::SMB_COM_NT_TRANSACT_SECONDARY)
		return ack
	end

	def queryfs(level)
		parm = [level].pack('v')

		begin
			resp = trans2(CONST::TRANS2_QUERY_FS_INFO, parm, '')

			pcnt = resp['Payload'].v['ParamCount']
			dcnt = resp['Payload'].v['DataCount']
			poff = resp['Payload'].v['ParamOffset']
			doff = resp['Payload'].v['DataOffset']

			# Get the raw packet bytes
			resp_rpkt = resp.to_s

			# Remove the NetBIOS header
			resp_rpkt.slice!(0, 4)

			resp_parm = resp_rpkt[poff, pcnt]
			resp_data = resp_rpkt[doff, dcnt]
			return resp_data

		rescue ::Exception
			raise $!
		end
	end

	def symlink(src,dst)
		parm = [513, 0x00000000].pack('vV') + src + "\x00"

		begin
			resp = trans2(CONST::TRANS2_SET_PATH_INFO, parm, dst + "\x00")

			pcnt = resp['Payload'].v['ParamCount']
			dcnt = resp['Payload'].v['DataCount']
			poff = resp['Payload'].v['ParamOffset']
			doff = resp['Payload'].v['DataOffset']

			# Get the raw packet bytes
			resp_rpkt = resp.to_s

			# Remove the NetBIOS header
			resp_rpkt.slice!(0, 4)

			resp_parm = resp_rpkt[poff, pcnt]
			resp_data = resp_rpkt[doff, dcnt]
			return resp_data

		rescue ::Exception
			raise $!
		end
	end

	# Obtains allocation information on the mounted tree
	def queryfs_info_allocation
		data = queryfs(CONST::SMB_INFO_ALLOCATION)
		head = %w{fs_id sectors_per_unit unit_total units_available bytes_per_sector}
		vals = data.unpack('VVVVv')
		info = { }
		head.each_index {|i| info[head[i]]=vals[i]}
		return info
	end

	# Obtains volume information on the mounted tree
	def queryfs_info_volume
		data = queryfs(CONST::SMB_INFO_VOLUME)
		vals = data.unpack('VCA*')
		return {
			'serial' => vals[0],
			'label'  => vals[2][0,vals[1]].gsub("\x00", '')
		}
	end

	# Obtains file system volume information on the mounted tree
	def queryfs_fs_volume
		data = queryfs(CONST::SMB_QUERY_FS_VOLUME_INFO)
		vals = data.unpack('VVVVCCA*')
		return {
			'create_time' => (vals[1] << 32) + vals[0],
			'serial'      => vals[2],
			'label'       => vals[6][0,vals[3]].gsub("\x00", '')
		}
	end

	# Obtains file system size information on the mounted tree
	def queryfs_fs_size
		data = queryfs(CONST::SMB_QUERY_FS_SIZE_INFO)
		vals = data.unpack('VVVVVV')
		return {
			'total_alloc_units' => (vals[1] << 32) + vals[0],
			'total_free_units'  => (vals[3] << 32) + vals[2],
			'sectors_per_unit'  => vals[4],
			'bytes_per_sector'  => vals[5]
		}
	end

	# Obtains file system device information on the mounted tree
	def queryfs_fs_device
		data = queryfs(CONST::SMB_QUERY_FS_DEVICE_INFO)
		vals = data.unpack('VV')
		return {
			'device_type'   => vals[0],
			'device_chars'  => vals[1],
		}
	end

	# Obtains file system attribute information on the mounted tree
	def queryfs_fs_attribute
		data = queryfs(CONST::SMB_QUERY_FS_ATTRIBUTE_INFO)
		vals = data.unpack('VVVA*')
		return {
			'fs_attributes' => vals[0],
			'max_file_name' => vals[1],
			'fs_name'       => vals[3][0, vals[2]].gsub("\x00", '')
		}
	end

	# Enumerates a specific path on the mounted tree
	def find_first(path)
		files = { }
		parm = [
			26,  # Search for ALL files
			512, # Maximum search count
			6,   # Resume and Close on End of Search
			260, # Level of interest
			0,   # Storage type is zero
		].pack('vvvvV') + path + "\x00"

		begin
			resp = trans2(CONST::TRANS2_FIND_FIRST2, parm, '')

			pcnt = resp['Payload'].v['ParamCount']
			dcnt = resp['Payload'].v['DataCount']
			poff = resp['Payload'].v['ParamOffset']
			doff = resp['Payload'].v['DataOffset']

			# Get the raw packet bytes
			resp_rpkt = resp.to_s

			# Remove the NetBIOS header
			resp_rpkt.slice!(0, 4)

			resp_parm = resp_rpkt[poff, pcnt]
			resp_data = resp_rpkt[doff, dcnt]

			# search id, search count, end of search, error offset, last name offset
			sid, scnt, eos, eoff, loff = resp_parm.unpack('v5')

			didx = 0
			while (didx < resp_data.length)
				info_buff = resp_data[didx, 70]
				break if info_buff.length != 70
				info = info_buff.unpack(
					'V'+	# Next Entry Offset
					'V'+	# File Index
					'VV'+	# Time Create
					'VV'+	# Time Last Access
					'VV'+	# Time Last Write
					'VV'+	# Time Change
					'VV'+	# End of File
					'VV'+	# Allocation Size
					'V'+	# File Attributes
					'V'+	# File Name Length
					'V'+	# Extended Attr List Length
					'C'+	# Short File Name Length
					'C' 	# Reserved
				)
				name = resp_data[didx + 70 + 24, info[15]].sub!(/\x00+$/, '')
				files[name] =
				{
					'type' => (info[14] & 0x10) ? 'D' : 'F',
					'attr' => info[14],
					'info' => info
				}

				break if info[0] == 0
				didx += info[0]
			end

			last_search_id = sid

		rescue ::Exception
			raise $!
		end

		return files
	end

	# TODO: Finish this method... requires search_id, resume_key, and filename from first
=begin
	def find_next(path, sid = last_search_id)

		parm = [
			sid, # Search ID
			512, # Maximum search count
			260, # Level of interest
			0,   # Resume key from previous
			1,   # Close search if end of search
		].pack('vvvVv') + path + "\x00"

		return files
	end
=end

	# Creates a new directory on the mounted tree
	def create_directory(name)
		files = { }
		parm = [0].pack('V') + name + "\x00"
		resp = trans2(CONST::TRANS2_CREATE_DIRECTORY, parm, '')
	end

# public read/write methods
	attr_accessor	:native_os, :native_lm, :encrypt_passwords, :extended_security, :read_timeout, :evasion_opts
	attr_accessor	:verify_signature, :use_ntlmv2, :usentlm2_session, :send_lm, :use_lanman_key, :send_ntlm 
	attr_accessor  	:system_time, :system_zone

# public read methods
	attr_reader		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_reader		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_reader		:multiplex_id, :last_tree_id, :last_file_id, :process_id, :last_search_id
	attr_reader		:dns_host_name, :dns_domain_name
	attr_reader		:security_mode, :server_guid
	#signing related 
	attr_reader		:sequence_counter,:signing_key, :require_signing

# private methods
	attr_writer		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_writer		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_writer		:dns_host_name, :dns_domain_name
	attr_writer		:multiplex_id, :last_tree_id, :last_file_id, :process_id, :last_search_id
	attr_writer		:security_mode, :server_guid
	#signing related 
	attr_writer		:sequence_counter,:signing_key, :require_signing

	attr_accessor	:socket


end
end
end
end
