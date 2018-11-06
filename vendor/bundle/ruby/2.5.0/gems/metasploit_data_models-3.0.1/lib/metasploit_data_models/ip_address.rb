# Namespace for models for validating various IPv4 formats beyond those supported by the Ruby standard library's
# `IPAddr`.
module MetasploitDataModels::IPAddress
  extend ActiveSupport::Autoload

  autoload :CIDR
  autoload :Range
  autoload :V4
end