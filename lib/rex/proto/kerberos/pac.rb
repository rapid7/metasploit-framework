# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        VERSION = 0
        NETLOGON_FLAG = 0x20000
        SE_GROUP_MANDATORY = 1
        SE_GROUP_ENABLED_BY_DEFAULT = 2
        SE_GROUP_ENABLED = 4
        SE_GROUP_ALL = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        USER_NORMAL_ACCOUNT = 0x00000010
        USER_DONT_EXPIRE_PASSWORD = 0x00000200
        PAC_LOGON_INFO = 1
        PAC_SERVER_CHECKSUM = 6
        PAC_PRIVSVR_CHECKSUM = 7
        PAC_CLIENT_INFO = 10
        AD_WIN2K_PAC = 128
        SEC_TO_UNIX_EPOCH = 11644473600
        WINDOWS_TICK = 10000000
        NEVER_EXPIRE = 0x7fffffffffffffff
        DOMAIN_USERS = 513
        DEFAULT_USER_SID = 1000
        NT_AUTHORITY_SID = 'S-1-5'
      end
    end
  end
end

require 'rex/proto/kerberos/pac/element'
require 'rex/proto/kerberos/pac/priv_svr_checksum'
require 'rex/proto/kerberos/pac/server_checksum'
require 'rex/proto/kerberos/pac/client_info'
require 'rex/proto/kerberos/pac/logon_info'
require 'rex/proto/kerberos/pac/type'
