# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        VERSION = 0
        NETLOGON_FLAG = 0x20000

        # Kerberos:
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
        # Reference with details on flags:
        # https://learn.microsoft.com/en-gb/windows/win32/api/winnt/ns-winnt-token_groups?redirectedfrom=MSDN#members
        SE_GROUP_MANDATORY = 0x00000001
        SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
        SE_GROUP_ENABLED = 0x00000004
        SE_GROUP_OWNER = 0x00000008
        SE_GROUP_RESOURCE = 0x20000000

        # XXX: Does not include some of the newer SE_GROUP_* flags
        SE_GROUP_ALL = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

        USER_NORMAL_ACCOUNT = 0x00000010
        USER_DONT_EXPIRE_PASSWORD = 0x00000200
        PAC_LOGON_INFO = 1
        PAC_CREDENTIALS_INFO = 2
        PAC_SERVER_CHECKSUM = 6
        PAC_PRIVSVR_CHECKSUM = 7
        PAC_CLIENT_INFO = 10
        AD_WIN2K_PAC = 128
        SEC_TO_UNIX_EPOCH = 11644473600
        WINDOWS_TICK = 10000000
        NEVER_EXPIRE = 0x7fffffffffffffff
        DOMAIN_ADMINS = 512
        DOMAIN_USERS = 513
        SCHEMA_ADMINISTRATORS = 518
        ENTERPRISE_ADMINS = 519
        GROUP_POLICY_CREATOR_OWNERS = 520
        DEFAULT_ADMIN_RID = 500
        DEFAULT_USER_RID = 1000
        NT_AUTHORITY_SID = 'S-1-5'
      end
    end
  end
end
