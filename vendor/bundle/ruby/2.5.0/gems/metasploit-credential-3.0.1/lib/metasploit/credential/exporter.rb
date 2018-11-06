# Namespace for classes which export {Metasploit::Credential::Core Metasploit::Credential::Cores} or
# {Metasploit::Credential::Login Metasploit::Credential::Logins}.
module Metasploit::Credential::Exporter
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :Core
  autoload :Pwdump
end