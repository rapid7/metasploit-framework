# frozen_string_literal: true

module Rex::Proto::Kerberos::Pac

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
  module Krb5PacElementType
    LOGON_INFORMATION = 0x00000001
    CREDENTIAL_INFORMATION = 0x00000002
    SERVER_CHECKSUM = 0x00000006
    PRIVILEGE_SERVER_CHECKSUM = 0x00000007
    CLIENT_INFORMATION = 0x0000000A
  end
end
