# frozen_string_literal: true

module Rex::Proto::Kerberos::Pac

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
  module Krb5PacElementType
    LOGON_INFORMATION                             = 0x00000001
    CREDENTIAL_INFORMATION                        = 0x00000002
    SERVER_CHECKSUM                               = 0x00000006
    PRIVILEGE_SERVER_CHECKSUM                     = 0x00000007
    CLIENT_INFORMATION                            = 0x0000000A
    CONSTRAINED_DELEGATION_INFORMATION            = 0x0000000B
    USER_PRINCIPAL_NAME_AND_DNS_INFORMATION       = 0x0000000C
    CLIENT_CLAIMS_INFORMATION                     = 0x0000000D
    DEVICE_INFORMATION                            = 0x0000000E
    DEVICE_CLAIMS_INFORMATION                     = 0x0000000F
    TICKET_CHECKSUM                               = 0x00000010
    PAC_ATTRIBUTES                                = 0x00000011
    PAC_REQUESTOR                                 = 0x00000012

    #
    # Return a string representation of the constant for a number
    #
    # @param [Integer] code
    def self.const_name(code)
      self.constants.each do |c|
        return c.to_s if self.const_get(c) == code
      end
      return nil
    end
  end
end
