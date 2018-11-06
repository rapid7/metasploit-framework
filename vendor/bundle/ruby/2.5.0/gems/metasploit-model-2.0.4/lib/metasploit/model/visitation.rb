# Namespace for `metasploit-model`'s implementation of the {http://en.wikipedia.org/wiki/Visitor_pattern visitor
# pattern}.
module Metasploit::Model::Visitation
  extend ActiveSupport::Autoload

  autoload :Visit
  autoload :Visitor
end
