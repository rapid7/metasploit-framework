# -*- coding: binary -*-

require 'bindata'

module Rex
module Proto
module IPMI

class Channel_Auth_Reply < BinData::Record
  endian :little
  uint8  :rmcp_version            ,label: "RMCP Version"
  uint8  :rmcp_padding            ,label: "RMCP Padding"
  uint8  :rmcp_sequence           ,label: "RMCP Sequence"
  bit1   :rmcp_mtype              ,label: "RMCP Message Type"
  bit7   :rmcp_class              ,label: "RMCP Message Class"

  uint8  :session_auth_type       ,label: "Session Auth Type"
  uint32 :session_sequence        ,label: "Session Sequence Number"
  uint32 :session_id              ,label: "Session ID"
  uint8  :message_length          ,label: "Message Length"

  uint8  :ipmi_tgt_address        ,label: "IPMI Target Address"
  uint8  :ipmi_tgt_lun            ,label: "IPMI Target LUN"
  uint8  :ipmi_header_checksum    ,label: "IPMI Header Checksum"
  uint8  :ipmi_src_address        ,label: "IPMI Source Address"
  uint8  :ipmi_src_luna           ,label: "IPMI Source LUN"
  uint8  :ipmi_command            ,label: "IPMI Command"
  uint8  :ipmi_completion_code    ,label: "IPMI Completion Code"

  uint8  :ipmi_channel            ,label: "IPMI Channel"

  bit1   :ipmi_compat_20          ,label: "IPMI Version Compatibility: IPMI 2.0+"
  bit1   :ipmi_compat_reserved1   ,label: "IPMI Version Compatibility: Reserved 1"
  bit1   :ipmi_compat_oem_auth    ,label: "IPMI Version Compatibility: OEM Authentication"
  bit1   :ipmi_compat_password    ,label: "IPMI Version Compatibility: Straight Password"
  bit1   :ipmi_compat_reserved2   ,label: "IPMI Version Compatibility: Reserved 2"
  bit1   :ipmi_compat_md5         ,label: "IPMI Version Compatibility: MD5"
  bit1   :ipmi_compat_md2         ,label: "IPMI Version Compatibility: MD2"
  bit1   :ipmi_compat_none        ,label: "IPMI Version Compatibility: None"

  bit2   :ipmi_user_reserved1     ,label: "IPMI User Compatibility: Reserved 1"
  bit1   :ipmi_user_kg            ,label: "IPMI User Compatibility: KG Set to Default"
  bit1   :ipmi_user_disable_message_auth ,label: "IPMI User Compatibility: Disable Per-Message Authentication"
  bit1   :ipmi_user_disable_user_auth ,label: "IPMI User Compatibility: Disable User-Level Authentication"
  bit1   :ipmi_user_non_null      ,label: "IPMI User Compatibility: Non-Null Usernames Enabled"
  bit1   :ipmi_user_null          ,label: "IPMI User Compatibility: Null Usernames Enabled"
  bit1   :ipmi_user_anonymous     ,label: "IPMI User Compatibility: Anonymous Login Enabled"

  bit6   :ipmi_conn_reserved1     ,label: "IPMI Connection Compatibility: Reserved 1"
  bit1   :ipmi_conn_20            ,label: "IPMI Connection Compatibility: 2.0"
  bit1   :ipmi_conn_15            ,label: "IPMI Connection Compatibility: 1.5"
  bit24  :ipmi_oem_id             ,label: "IPMI OEM ID"

  rest :ipm_oem_data              ,label: "IPMI OEM Data + Checksum Byte"

  def to_banner
    info   = self
    banner = "#{(info.ipmi_compat_20 == 1) ? "IPMI-2.0" : "IPMI-1.5"} "

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
