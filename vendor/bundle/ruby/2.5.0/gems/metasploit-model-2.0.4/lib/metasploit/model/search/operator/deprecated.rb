# Namespace for search operators that mimic behavior of the msfconsole search operators prior to the search operator
# generalization introduced by {Metasploit::Model::Search}.
module Metasploit::Model::Search::Operator::Deprecated
  extend ActiveSupport::Autoload

  autoload :App
  autoload :Author
  autoload :Authority
  autoload :Platform
  autoload :Ref
  autoload :Text
end
