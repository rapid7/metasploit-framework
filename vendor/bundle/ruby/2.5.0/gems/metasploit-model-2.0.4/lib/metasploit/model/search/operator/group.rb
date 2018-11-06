# Namespace for operators that produce group operations.
module Metasploit::Model::Search::Operator::Group
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :Intersection
  autoload :Union
end
