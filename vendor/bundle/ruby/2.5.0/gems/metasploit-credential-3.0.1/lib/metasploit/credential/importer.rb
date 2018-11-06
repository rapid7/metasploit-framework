# Namespace for all importers of {Metasploit::Credential::Core Metasploit::Credential::Cores} and
# {Metasploit::Credential::Login Metasploit::Credential::Logins}.
module Metasploit::Credential::Importer
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :Core
  autoload :MsfPwdump
  autoload :Multi
  autoload :Pwdump
  autoload :Zip
end