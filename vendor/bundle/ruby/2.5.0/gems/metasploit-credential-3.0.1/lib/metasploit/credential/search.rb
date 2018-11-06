# Namespace for {Metasploit::Credential} custom {Metasploit::Credential::Search::Operation operations} and
# {Metasploit::Credential::Search::Operator operators}.
module Metasploit::Credential::Search
  extend ActiveSupport::Autoload

  autoload :Operation
  autoload :Operator
end