# -*- coding: binary -*-
require 'rex/proto/llmnr'
require 'msf/core/exploit'
module Msf

###
#
# This module provides methods for working with LLMNR
#
###
module Auxiliary::LLMNR

  include Auxiliary::UDPScanner

  #
  # Initializes an instance of an auxiliary module that uses LLMNR
  #

  def initialize(info = {})
    super
    register_options(
    [
      OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '224.0.0.252']),
      Opt::RPORT(5355),
      OptString.new('NAME', [true, 'The name to query', 'localhost']),
      OptString.new('TYPE', [true, 'The query type (name or #)', 'A']),
      OptString.new('CLASS', [true, 'The query class (name or #)', 'IN'])
    ], self.class)
  end

  def setup
    query_class_name
    query_type_name
  end

  def query_class
    datastore['CLASS'].upcase
  end

  def query_class_name
    return @query_class_name if @query_class_name
    if /^(?<class_num>\d+)$/ =~ query_class
      class_num = class_num.to_i
      raise ClassArgumentError, "LLMNR RR class #{query_class} out of range" if class_num > 0x7FFF
      begin
        @query_class_name = Net::DNS::RR::Classes.to_str(class_num)
      rescue ClassArgumentError
        @query_class_name = "CLASS#{class_num}"
      end
    else
      unless Net::DNS::RR::Classes.valid?(query_class)
        raise ClassArgumentError, "LLMNR RR class #{query_class} invalid"
      end
      @query_class_name = query_class
    end

    @query_class_name
  end

  def query_class_num
    return @query_class_num if @query_class_num
    if /^(?<class_num>\d+)$/ =~ query_class
      class_num = class_num.to_i
      raise ClassArgumentError, "LLMNR RR class #{query_class} out of range" if class_num > 0x7FFF
      @query_class_num = class_num
    else
      unless Net::DNS::RR::Classes.valid?(query_class)
        raise ClassArgumentError, "LLMNR RR class #{query_class} invalid"
      end
      @query_class_num = Net::DNS::RR::Classes::Classes[query_class]
    end

    @query_class_num
  end

  def query_type
    datastore['TYPE'].upcase
  end

  def query_type_name
    return @query_type_name if @query_type_name
    if /^(?<type_num>\d+)$/ =~ query_type
      type_num = type_num.to_i
      raise TypeArgumentError, "LLMNR RR type #{query_type} out of range" if type_num > 0xFFFF
      begin
        @query_type_name = Net::DNS::RR::Types.to_str(type_num)
      rescue TypeArgumentError
        @query_type_name = "TYPE#{type_num}"
      end
    else
      unless Net::DNS::RR::Types.valid?(query_type)
        raise TypeArgumentError, "LLMNR RR type #{query_type} invalid"
      end
      @query_type_name = query_type
    end

    @query_type_name
  end

  def query_type_num
    return @query_type_num if @query_type_num
    if /^(?<type_num>\d+)$/ =~ query_type
      type_num = type_num.to_i
      raise TypeArgumentError, "LLMNR RR type #{query_type} out of range" if type_num > 0xFFFF
      @query_type_num = type_num
    else
      unless Net::DNS::RR::Types.valid?(query_type)
        raise TypeArgumentError, "LLMNR RR type #{query_type} invalid"
      end
      @query_type_num = Net::DNS::RR::Types::Types[query_type]
    end

    @query_type_num
  end
end
end
