# Namespace for IPv4 Address format models.
module MetasploitDataModels::IPAddress::V4
  extend ActiveSupport::Autoload

  autoload :CIDR
  autoload :Nmap
  autoload :Range
  autoload :Segment
  autoload :Segmented
  autoload :Single
end