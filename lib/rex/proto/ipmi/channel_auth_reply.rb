
module Rex
module Proto
module IPMI

class Channel_Auth_Reply < BitStruct
	unsigned :rmcp_version,                    8,     "RMCP Version"
	unsigned :rmcp_padding,                    8,     "RMCP Padding"
	unsigned :rmcp_sequence,                   8,     "RMCP Sequence"
	unsigned :rmcp_mtype,                      1,     "RMCP Message Type"
	unsigned :rmcp_class,                      7,     "RMCP Message Class"

	unsigned :session_auth_type,               8,     "Session Auth Type"
	unsigned :session_sequence,               32,     "Session Sequence Number"
	unsigned :session_id,                     32,     "Session ID"
	unsigned :message_length,                  8,     "Message Length"

	unsigned :ipmi_tgt_address,                8,     "IPMI Target Address"
	unsigned :ipmi_tgt_lun,                    8,     "IPMI Target LUN"
	unsigned :ipmi_header_checksum,            8,     "IPMI Header Checksum"
	unsigned :ipmi_src_address,                8,     "IPMI Source Address"
	unsigned :ipmi_src_lun,                    8,     "IPMI Source LUN"
	unsigned :ipmi_command,                    8,     "IPMI Command"
	unsigned :ipmi_completion_code,            8,     "IPMI Completion Code"

	unsigned :ipmi_channel,                    8,     "IPMI Channel"

	unsigned :ipmi_compat_20,                  1,     "IPMI Version Compatibility: IPMI 2.0+"
	unsigned :ipmi_compat_reserved1,           1,     "IPMI Version Compatibility: Reserved 1"
	unsigned :ipmi_compat_oem_auth,            1,     "IPMI Version Compatibility: OEM Authentication"
	unsigned :ipmi_compat_password,            1,     "IPMI Version Compatibility: Straight Password"
	unsigned :ipmi_compat_reserved2,           1,     "IPMI Version Compatibility: Reserved 2"
	unsigned :ipmi_compat_md5,                 1,     "IPMI Version Compatibility: MD5"
	unsigned :ipmi_compat_md2,                 1,     "IPMI Version Compatibility: MD2"
	unsigned :ipmi_compat_none,                1,     "IPMI Version Compatibility: None"

	unsigned :ipmi_user_reserved1,             2,     "IPMI User Compatibility: Reserved 1"
	unsigned :ipmi_user_kg,                    1,     "IPMI User Compatibility: KG Set to Default"
	unsigned :ipmi_user_disable_message_auth,  1,     "IPMI User Compatibility: Disable Per-Message Authentication"
	unsigned :ipmi_user_disable_user_auth,     1,     "IPMI User Compatibility: Disable User-Level Authentication"
	unsigned :ipmi_user_non_null,              1,     "IPMI User Compatibility: Non-Null Usernames Enabled"
	unsigned :ipmi_user_null,                  1,     "IPMI User Compatibility: Null Usernames Enabled"
	unsigned :ipmi_user_anonymous,             1,     "IPMI User Compatibility: Anonymous Login Enabled"

	unsigned :ipmi_conn_reserved1,             6,     "IPMI Connection Compatibility: Reserved 1"
	unsigned :ipmi_conn_20,                    1,     "IPMI Connection Compatibility: 2.0"
	unsigned :ipmi_conn_15,                    1,     "IPMI Connection Compatibility: 1.5"

	unsigned :ipmi_oem_id,                    24,     "IPMI OEM ID", :endian => 'little'

	rest :ipm_oem_data, "IPMI OEM Data + Checksum Byte"


	def to_banner
		info   = self
		banner = "Addr:#{info.ipmi_src_address} LUN:#{info.ipmi_src_lun} CH:#{info.ipmi_command} #{(info.ipmi_compat_20 == 1) ? "IPMI-2.0" : "IPMI-1.5"} "

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

end
end
end
