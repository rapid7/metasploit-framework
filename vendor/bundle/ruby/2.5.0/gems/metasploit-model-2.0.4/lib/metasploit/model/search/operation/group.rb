# Namespace for operations that form groups directly from single operator.
module Metasploit::Model::Search::Operation::Group
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :Intersection
  autoload :Union
end