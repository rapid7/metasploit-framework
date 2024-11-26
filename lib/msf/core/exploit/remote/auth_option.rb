# -*- coding: binary -*-

module Msf::Exploit::Remote::AuthOption
  # The module / specific protocol will automatically negotiate the best authentication method to use
  AUTO = 'auto'

  # NTLM authentication is used
  NTLM = 'ntlm'

  # Kerberos authentication is used
  KERBEROS = 'kerberos'

  KERBEROS_DEFAULT_OFFERED_ENC_TYPES = Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes.map do |id|
    Rex::Proto::Kerberos::Crypto::Encryption.const_name(id).gsub('_', '-')
  end

  # plaintext authentication is used
  PLAINTEXT = 'plaintext'

  # SCHANNEL authentication is used.
  SCHANNEL = 'schannel'

  # Do not authenticate with the service
  NONE = 'none'

  # The auth methods supported by the SMB protocol
  SMB_OPTIONS = [
    AUTO,
    NTLM,
    KERBEROS
  ]

  # The auth methods supported by the HTTP protocol
  HTTP_OPTIONS = [
    AUTO,
    NTLM,
    KERBEROS,
    PLAINTEXT,
    NONE
  ]

  # The auth methods supported by the LDAP protocol
  LDAP_OPTIONS = [
    AUTO,
    NTLM,
    KERBEROS,
    SCHANNEL,
    PLAINTEXT,
    NONE
  ]

  # The auth methods supported by the MSSQL/TDS protocol
  MSSQL_OPTIONS = [
    AUTO,
    NTLM,
    KERBEROS,
    PLAINTEXT
  ]

  # The auth methods supported by the WINRM protocol
  WINRM_OPTIONS = [
    AUTO,
    NTLM,
    KERBEROS,
    PLAINTEXT
  ]

  # @param [String] value String value with the user defined etypes, i.e. AES128,AES256,RC4_HMAC,etc
  # @return [Array[Integer] The encryption types
  # @see Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes
  def self.as_default_offered_etypes(value)
    return Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes if value.blank?

    value.split(',').map(&:strip).reject(&:blank?).map do |type|
      Rex::Proto::Kerberos::Crypto::Encryption.value_for(type.upcase.gsub('-', '_'))
    end.uniq
  end
end
