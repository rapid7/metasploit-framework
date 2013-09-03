
module Rex
module Proto
module IPMI

class Open_Session_Reply < BitStruct
	unsigned :rmcp_version,  8,  "RMCP Version"
	unsigned :rmcp_padding,  8,  "RMCP Padding"
	unsigned :rmcp_sequence, 8,  "RMCP Sequence"
	unsigned :rmcp_mtype,    1,  "RMCP Message Type"
	unsigned :rmcp_class,    7,  "RMCP Message Class"

	unsigned :session_auth_type, 8,  "Authentication Type"

	unsigned :session_payload_encrypted,     1,  "Session Payload Encrypted"
	unsigned :session_payload_authenticated, 1,  "Session Payload Authenticated"
	unsigned :session_payload_type,          6,  "Session Payload Type", :endian => 'little'

	unsigned :session_id,       32,  "Session ID"
	unsigned :session_sequence, 32,  "Session Sequence Number"
	unsigned :message_length,   16,  "Message Length", :endian => "little"

	unsigned :ignored1,        8, "Ignored"
	unsigned :error_code,      8, "RMCP Error Code"
	unsigned :ignored2,       16, "Ignored"
	char :console_session_id, 32, "Console Session ID"
	char :bmc_session_id,     32, "BMC Session ID"

	rest :stuff, "The Rest of the Stuff"
end

end
end
end

