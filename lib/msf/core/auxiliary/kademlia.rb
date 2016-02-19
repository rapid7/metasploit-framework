# -*- coding: binary -*-

require 'rex/proto/kademlia'

module Msf

###
#
# This module provides methods for working with Kademlia
#
###
module Auxiliary::Kademlia
  include Rex::Proto::Kademlia
end
end
