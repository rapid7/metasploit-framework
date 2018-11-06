# A range of complete IPv4 addresses, separated by a `-`.
class MetasploitDataModels::IPAddress::V4::Range < Metasploit::Model::Base
  extend MetasploitDataModels::Match::Child

  include MetasploitDataModels::IPAddress::Range

  #
  # Range Extremes
  #

  extremes class_name: 'MetasploitDataModels::IPAddress::V4::Single'
end
