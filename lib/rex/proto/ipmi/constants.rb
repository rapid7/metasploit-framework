# -*- coding: binary -*-

require 'bit-struct'

module Rex
module Proto
module IPMI


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

	class Channel_Auth_Reply < BitStruct
	    unsigned	:rmcp_version,      8,     "RMCP Version"
	    unsigned	:rmcp_padding,      8,     "RMCP Padding"
	    unsigned	:rmcp_sequence,     8,     "RMCP Sequence"
	    unsigned	:rmcp_mtype,    1,     "RMCP Message Type"
	    unsigned	:rmcp_class,    7,     "RMCP Message Class"

	    unsigned	:session_auth_type,  8,     "Session Auth Type"
	    unsigned	:session_sequence,  32,     "Session Sequence Number"
	    unsigned	:session_id,  32,     "Session ID"
	    unsigned	:message_length,  8,     "Message Length"

	    unsigned	:ipmi_tgt_address,  8,     "IPMI Target Address"
	    unsigned	:ipmi_tgt_lun,  8,     "IPMI Target LUN"
		unsigned	:ipmi_header_checksum,  8,     "IPMI Header Checksum"
		unsigned	:ipmi_src_address,  8,     "IPMI Source Address"
	    unsigned	:ipmi_src_lun,  8,     "IPMI Source LUN"
		unsigned	:ipmi_command,  8,     "IPMI Command"
		unsigned	:ipmi_completion_code,  8,     "IPMI Completion Code"

	    unsigned	:ipmi_channel,  8,     "IPMI Channel"

	    unsigned	:ipmi_compat_20,  1,     "IPMI Version Compatibility: IPMI 2.0+"
		unsigned	:ipmi_compat_reserved1,  1,     "IPMI Version Compatibility: Reserved 1"
		unsigned	:ipmi_compat_oem_auth,  1,     "IPMI Version Compatibility: OEM Authentication"
		unsigned	:ipmi_compat_password,  1,     "IPMI Version Compatibility: Straight Password"
		unsigned	:ipmi_compat_reserved2,  1,     "IPMI Version Compatibility: Reserved 2"
		unsigned	:ipmi_compat_md5,  1,     "IPMI Version Compatibility: MD5"
		unsigned	:ipmi_compat_md2,  1,     "IPMI Version Compatibility: MD2"	
		unsigned	:ipmi_compat_none,  1,     "IPMI Version Compatibility: None"

		unsigned	:ipmi_user_reserved1,  2,     "IPMI User Compatibility: Reserved 1"
		unsigned	:ipmi_user_kg,  1,     "IPMI User Compatibility: KG Set to Default"
		unsigned	:ipmi_user_disable_message_auth,  1,     "IPMI User Compatibility: Disable Per-Message Authentication"
		unsigned	:ipmi_user_disable_user_auth,  1,     "IPMI User Compatibility: Disable User-Level Authentication"
		unsigned	:ipmi_user_non_null,  1,     "IPMI User Compatibility: Non-Null Usernames Enabled"
		unsigned	:ipmi_user_null,  1,     "IPMI User Compatibility: Null Usernames Enabled"
		unsigned	:ipmi_user_anonymous,  1,     "IPMI User Compatibility: Anonymous Login Enabled"
		
		unsigned	:ipmi_conn_reserved1,  6,     "IPMI Connection Compatibility: Reserved 1"
		unsigned	:ipmi_conn_20,  1,     "IPMI Connection Compatibility: 2.0"
		unsigned	:ipmi_conn_15,  1,     "IPMI Connection Compatibility: 1.5"

	    unsigned	:ipmi_oem_id,  24,     "IPMI OEM ID", :endian => 'little'

	    rest		:ipm_oem_data,         "IPMI OEM Data + Checksum Byte"


	    def to_banner
	    	info   = self
		    banner = "Addr:#{info.ipmi_src_address} LUN:#{info.ipmi_src_lun} CH:#{info.ipmi_command} #{(info.ipmi_compat_20  == 1) ? "IPMI-2.0" : "IPMI-1.5"} "

		    pass_info = []
		    pass_info << "oem_auth" if info.ipmi_compat_oem_auth == 1
			pass_info << "password" if info.ipmi_compat_password == 1
			pass_info << "md5" if info.ipmi_compat_md5 == 1
			pass_info << "md2" if info.ipmi_compat_md2 == 1
			pass_info << "null" if info.ipmi_compat_none == 1

		    user_info = []
		    user_info << "kg_default" if (info.ipmi_compat_20 == 1 and info.ipmi_user_kg == 1)
		    user_info << "auth_msg" unless info.ipmi_user_disable_message_auth == 1
			user_info << "auth_user" unless info.ipmi_user_disable_user_auth == 1
			user_info << "non_null_user" if info.ipmi_user_non_null == 1
			user_info << "null_user" if info.ipmi_user_null == 1
			user_info << "anonymous_user" if info.ipmi_user_anonymous == 1

			conn_info = []
			conn_info << "1.5" if info.ipmi_conn_15 == 1
			conn_info << "2.0" if info.ipmi_conn_20 == 1

			if info.ipmi_oem_id != 0
				banner << "OEMID:#{info.ipmi_oem_id} "
			end

			banner << "UserAuth(#{user_info.join(", ")}) PassAuth(#{pass_info.join(", ")}) Level(#{conn_info.join(", ")}) "
			banner
		end
	end

	class Open_Session_Reply < BitStruct
		unsigned	:rmcp_version,      8,     "RMCP Version"
		unsigned	:rmcp_padding,      8,     "RMCP Padding"
		unsigned	:rmcp_sequence,     8,     "RMCP Sequence"
		unsigned	:rmcp_mtype,    1,     "RMCP Message Type"
		unsigned	:rmcp_class,    7,     "RMCP Message Class"

		unsigned	:session_auth_type,  8,     "Authentication Type"

		unsigned	:session_payload_encrypted,  1,     "Session Payload Encrypted"
		unsigned	:session_payload_authenticated,  1,     "Session Payload Authenticated"	    
		unsigned	:session_payload_type,  6,     "Session Payload Type", :endian => 'little'

		unsigned	:session_id,  32,     "Session ID"
		unsigned	:session_sequence,  32,     "Session Sequence Number"
		unsigned	:message_length,  16,     "Message Length", :endian => "little"

		unsigned	:ignored1, 8, "Ignored"
		unsigned	:error_code, 8, "RMCP Error Code"
		unsigned	:ignored2, 16,	"Ignored"
		char		:console_session_id, 32, "Console Session ID"
		char		:bmc_session_id, 32, "BMC Session ID"
		rest		:stuff,         "The Rest of the Stuff"
	end

	class RAKP2 < BitStruct
		unsigned	:rmcp_version,      8,     "RMCP Version"
		unsigned	:rmcp_padding,      8,     "RMCP Padding"
		unsigned	:rmcp_sequence,     8,     "RMCP Sequence"
		unsigned	:rmcp_mtype,    1,     "RMCP Message Type"
		unsigned	:rmcp_class,    7,     "RMCP Message Class"

		unsigned	:session_auth_type,  8,     "Authentication Type"

		unsigned	:session_payload_encrypted,  1,     "Session Payload Encrypted"
		unsigned	:session_payload_authenticated,  1,     "Session Payload Authenticated"	    
		unsigned	:session_payload_type,  6,     "Session Payload Type", :endian => 'little'

		unsigned	:session_id,  32,     "Session ID"
		unsigned	:session_sequence,  32,     "Session Sequence Number"
		unsigned	:message_length,  16,     "Message Length", :endian => "little"

		unsigned	:ignored1, 8, "Ignored"
		unsigned	:error_code, 8, "RMCP Error Code"
		unsigned	:ignored2, 16,	"Ignored"
		char		:console_session_id, 32, "Console Session ID"
		char		:bmc_random_id,  128,     "BMC Random ID"
		char		:bmc_guid,  128,     "RAKP2 Hash 2 (nulls)"
		char		:hmac_sha1,  160,     "HMAC_SHA1 Output"
		rest		:stuff, "The rest of the stuff"
	end

end
end
end