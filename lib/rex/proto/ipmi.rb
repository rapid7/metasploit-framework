# -*- coding: binary -*-

require 'rex/proto/ipmi/utils'

module Rex
module Proto
module IPMI
	require 'bit-struct'
	require 'rex/proto/ipmi/channel_auth_reply'
	require 'rex/proto/ipmi/open_session_reply'
	require 'rex/proto/ipmi/rakp2'

	#
	# Move these into an IPMI stack or mixin at some point
	#

	#
	# Payload types were identified from xCAT-server source code (IPMI.pm)
	#
	PAYLOAD_IPMI = 0
	PAYLOAD_SOL  = 1
	PAYLOAD_RMCPPLUSOPEN_REQ = 0x10
	PAYLOAD_RMCPPLUSOPEN_REP = 0x11
	PAYLOAD_RAKP1 = 0x12
	PAYLOAD_RAKP2 = 0x13
	PAYLOAD_RAKP3 = 0x14
	PAYLOAD_RAKP4 = 0x15


	#
	# Payload types were copied from xCAT-server source code (IPMI.pm)
	#
	RMCP_ERRORS = {
		1 => "Insufficient resources to create new session (wait for existing sessions to timeout)",
		2 => "Invalid Session ID", #this shouldn't occur...
		3 => "Invalid payload type",#shouldn't occur..
		4 => "Invalid authentication algorithm", #if this happens, we need to enhance our mechanism for detecting supported auth algorithms
		5 => "Invalid integrity algorithm", #same as above
		6 => "No matching authentication payload",
		7 => "No matching integrity payload",
		8 => "Inactive Session ID", #this suggests the session was timed out while trying to negotiate, shouldn't happen
		9 => "Invalid role",
		0xa => "Unauthorised role or privilege level requested",
		0xb => "Insufficient resources to create a session at the requested role",
		0xc => "Invalid username length",
		0xd => "Unauthorized name",
		0xe => "Unauthorized GUID",
		0xf => "Invalid integrity check value",
		0x10 => "Invalid confidentiality algorithm",
		0x11 => "No cipher suite match with proposed security algorithms",
		0x12 => "Illegal or unrecognized parameter", #have never observed this, would most likely mean a bug in xCAT or IPMI device
	}


end
end
end
