# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
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
