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
	end
	
	def session_request (name = '*SMBSERVER')
		
		data = 
			"\x20" + UTILS.nbname_encode(name) + "\x00" +
			"\x20" + CONST::NETBIOS_REDIR + "\x00"
		
		pkt = CONST::NB_HDR.make_struct
		p pkt.methods
		
	end
	

# public methods
	attr_accessor	:native_os, :native_lm, :encrypt_passwords, :extended_security
	attr_reader		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_reader		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_reader		:multiplex_id, :tree_id, :last_tree_id, :last_file_id
	
# private methods
private
	attr_writer		:dialect, :session_id, :challenge_key, :peer_native_lm, :peer_native_os
	attr_writer		:default_domain, :default_name, :auth_user, :auth_user_id
	attr_writer		:multiplex_id, :tree_id, :last_tree_id, :last_file_id
	
	attr_accessor	:socket
	

end
end
end
end
