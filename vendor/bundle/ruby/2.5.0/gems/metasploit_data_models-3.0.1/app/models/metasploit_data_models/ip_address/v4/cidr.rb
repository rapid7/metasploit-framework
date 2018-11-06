# An IPv4 CIDR (Classless InterDomain Routing) block composed of a
# {MetasploitDataModels::IPAddress::V4::Single IPv4} {MetasploitDataModels::IPAddress::CIDR#address address} and
# {MetasploitDataModels::IPAddress::CIDR#prefix_length prefix_length} written in the form `'a.b.c.d/prefix_length'`.
#
# @see https://en.wikipedia.org/wiki/Cidr#IPv6_CIDR_blocks
class MetasploitDataModels::IPAddress::V4::CIDR < Metasploit::Model::Base
  include MetasploitDataModels::IPAddress::CIDR

  #
  # CIDR
  #

  cidr address_class: MetasploitDataModels::IPAddress::V4::Single
end
