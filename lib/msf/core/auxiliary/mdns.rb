# -*- coding: binary -*-
require 'net/dns'
require 'rex/proto/mdns'

module Msf
  # This module provides methods for working with mDNS
  module Auxiliary::MDNS
    include Auxiliary::UDPScanner

    # Initializes an instance of an auxiliary module that uses mDNS
    def initialize(info = {})
      super
      register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '224.0.0.251']),
        Opt::RPORT(5353),
        OptString.new('NAME', [true, 'The name to query', '_services._dns-sd._udp.local']),
        OptString.new('TYPE', [true, 'The query type (name, # or TYPE#)', 'PTR']),
        OptString.new('CLASS', [true, 'The query class (name, # or CLASS#)', 'IN'])
      ], self.class)
    end

    def setup
      query_class_name
      query_type_name
    end

    def build_probe
      @probe ||= query
    end

    # Returns the raw query message
    def query
      # Note that we don't use ::Net::DNS::Packet or similar here because of
      # the current restrictions it places on RRs, specifically the values that
      # it allows for RR names (it only allows valid RR names, we often need to
      # query invalid ones for various purposes)
      [
        rand(65535), # id
        0, # all-0 qr, opcode, conflict, truncation, tentative, reserved an rcode
        1, # number of questions
        0, # number of answer RRs
        0, # number of authority RRs
        0, # number of additional RRs
        query_name.length,
        query_name,
        query_type_num,
        query_class_num
      ].pack("nnnnnnCa#{query_name.length + 1}nn")
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

    def query_name
      datastore['NAME']
    end

    def query_type_name
      Net::DNS::RR::Types.new(query_type).to_s
    end

    def query_type_num
      Net::DNS::RR::Types.new(query_type).to_i
    end
  end
end
