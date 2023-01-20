# -*- coding: binary -*-

module Msf

# Mini-mixin for making SMBUser/SMBPass/SMBDomain regular options vs advanced
# Included when the module needs credentials to function
module Exploit::Remote::SMB::Client::Authenticated

  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::Kerberos::Ticket::Storage
  include Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Options

  def initialize(info = {})
    super
    register_options(
      [
        OptString.new('SMBUser', [ false, 'The username to authenticate as', ''], fallbacks: ['USERNAME']),
        OptString.new('SMBPass', [ false, 'The password for the specified username', ''], fallbacks: ['PASSWORD']),
        OptString.new('SMBDomain',  [ false, 'The Windows domain to use for authentication', '.'], fallbacks: ['DOMAIN']),
      ], Msf::Exploit::Remote::SMB::Client::Authenticated)

    register_advanced_options(
      [
        *kerberos_storage_options(protocol: 'SMB'),
        *kerberos_auth_options(protocol: 'SMB', auth_methods: Msf::Exploit::Remote::AuthOption::SMB_OPTIONS),
      ],
      Msf::Exploit::Remote::SMB::Client::Authenticated
    )
  end
end

end
