# Namespace for search groups, such as {Metasploit::Model::Search::Group::Intersection intersections} or
# {Metasploit::Model::Search::Group::Union unions}.
module Metasploit::Model::Search::Group
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :Intersection
  autoload :Union
end