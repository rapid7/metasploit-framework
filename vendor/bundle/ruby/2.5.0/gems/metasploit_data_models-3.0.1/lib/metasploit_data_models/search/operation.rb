# Search operations ({MetasploitDataModels::Search::Operator operator}:operand) on {Mdm} and {MetasploitDataModels}
# models.
module MetasploitDataModels::Search::Operation
  extend ActiveSupport::Autoload

  autoload :IPAddress
  autoload :Port
  autoload :Range
end