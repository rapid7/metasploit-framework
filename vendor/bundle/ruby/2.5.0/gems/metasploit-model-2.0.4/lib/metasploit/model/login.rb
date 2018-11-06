# Namespace for constants used in `Metasploit::Credential::Login` that need to be accessible without
# `metasploit-credential`
module Metasploit::Model::Login
  extend ActiveSupport::Autoload

  autoload :Status
end