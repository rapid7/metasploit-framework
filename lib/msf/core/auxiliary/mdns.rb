# -*- coding: binary -*-
require 'net/dns'

module Msf
  # This module provides methods for working with mDNS
  module Auxiliary::MDNS
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
        ],
        self.class
      )
    end

    def setup
      query_class_name
      query_type_name
    end

    def build_probe
      @probe ||= ::Net::DNS::Packet.new(query_name, query_type_num, query_class_num).data
      # TODO: support QU vs QM probes
      #+ @probe[@probe.size-2] = [0x80].pack('C')
      #+ @probe
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

    def describe_response(response)
      decoded = Resolv::DNS::Message.decode(response)
      answers = decoded.answer

      if answers.empty? # not sure this will ever happen...
        "no answers"
      else
        # there are often many answers for the same RR, so group them
        grouped_answers = answers.group_by { |name, _, _| name }
        # now summarize each group by noting the resource type and the notable
        # part(s) of that RR
        summarized_answers = grouped_answers.map do |name, these_answers|
          summarized_group = these_answers.map do |_, _, data|
            case data
            when Resolv::DNS::Resource::IN::A
              "A #{data.address}"
            when Resolv::DNS::Resource::IN::AAAA
              "AAAA #{data.address}"
            when Resolv::DNS::Resource::IN::PTR
              "PTR #{data.name}"
            when Resolv::DNS::Resource::IN::SRV
              "SRV #{data.target}"
            when Resolv::DNS::Resource::IN::TXT
              "TXT #{data.strings.join(',')}"
            else
              data.inspect
            end
          end
          "#{name}: (#{summarized_group.join(", ")})"
        end
        summarized_answers.join(', ')
      end
    end

    def request_info
      "#{query_name} #{query_class}/#{query_type}"
    end
  end
end
