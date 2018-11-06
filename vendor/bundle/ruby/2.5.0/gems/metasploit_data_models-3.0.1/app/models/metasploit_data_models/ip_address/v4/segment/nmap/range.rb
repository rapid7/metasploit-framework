# A range of segment number composed of a {#begin} and {#end} segment number, separated by a `-`.
class MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range < Metasploit::Model::Base
  extend MetasploitDataModels::Match::Child

  include MetasploitDataModels::IPAddress::Range

  #
  # Range Extremes
  #

  extremes class_name: 'MetasploitDataModels::IPAddress::V4::Segment::Single'
end