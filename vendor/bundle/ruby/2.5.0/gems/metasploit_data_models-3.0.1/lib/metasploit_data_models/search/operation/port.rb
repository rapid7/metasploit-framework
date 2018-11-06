# Search operation on IP port formats: either
# {MetasploitDataModels::Search::Operation::Port::Number an individual port number} or
# {MetasploitDataModels::Search::Operation::Port::Range a hyphenated range of port numbers}.
module MetasploitDataModels::Search::Operation::Port
  extend ActiveSupport::Autoload

  autoload :Number
  autoload :Range
end