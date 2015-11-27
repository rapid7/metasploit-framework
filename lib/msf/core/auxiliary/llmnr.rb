# -*- coding: binary -*-
require 'msf/core/auxiliary/mdns'

module Msf
  # This module provides methods for working with LLMNR
  module Auxiliary::LLMNR
    include Auxiliary::MDNS

    # Initializes an instance of an auxiliary module that uses LLMNR
    def initialize(info = {})
      super
      register_options(
        [
          OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '224.0.0.252']),
          Opt::RPORT(5355),
          # TODO: allow more than one
          OptString.new('NAME', [true, 'The name to query', 'localhost']),
          OptString.new('TYPE', [true, 'The query type (name, # or TYPE#)', 'A'])
        ],
        self.class
      )
    end
  end
end
