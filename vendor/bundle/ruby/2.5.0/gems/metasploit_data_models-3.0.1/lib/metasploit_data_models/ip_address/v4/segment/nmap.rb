# A segment in Nmap's IPv4 address format: either a {List comma separated list} or a {Range hyphenated range}.
module MetasploitDataModels::IPAddress::V4::Segment::Nmap
  extend ActiveSupport::Autoload

  autoload :List
  autoload :Range
end