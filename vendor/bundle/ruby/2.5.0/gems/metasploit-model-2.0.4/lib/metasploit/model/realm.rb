# Namespace for constants used in `Metasploit::Credential::Realm` that need to be accessible without
# `metasploit-credential`
module Metasploit::Model::Realm
  extend ActiveSupport::Autoload

  autoload :Key
end