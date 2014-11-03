# -*- coding: binary -*-
require 'net/dns'
require 'rex/proto/llmnr'

module Msf
  # This module provides methods for working with LLMNR
  module Auxiliary::LLMNR
    include Auxiliary::UDPScanner

    # Initializes an instance of an auxiliary module that uses LLMNR
    def initialize(info = {})
      super
      register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '224.0.0.252']),
        Opt::RPORT(5355),
        OptString.new('NAME', [true, 'The name to query', 'localhost']),
        OptString.new('TYPE', [true, 'The query type (name, # or TYPE#)', 'A']),
        OptString.new('CLASS', [true, 'The query class (name, # or CLASS#)', 'IN'])
      ], self.class)
    end

    def setup
      query_class_name
      query_type_name
    end

    def query_class
      if datastore['CLASS'] =~ /^\d+$/
        datastore['CLASS'].to_i
      else
        datastore['CLASS'].upcase
      end
    end

    def query_class_name
      Net::DNS::RR::Classes.new(query_class).to_s
    end

    def query_class_num
      Net::DNS::RR::Classes.new(query_class).to_i
    end

    def query_type
      if datastore['TYPE'] =~ /^\d+$/
        datastore['TYPE'].to_i
      else
        datastore['TYPE'].upcase
      end
    end

    def query_type_name
      Net::DNS::RR::Types.new(query_type).to_s
    end

    def query_type_num
      Net::DNS::RR::Types.new(query_type).to_i
    end
  end
end
