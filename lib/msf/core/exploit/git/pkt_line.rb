# -*- coding: binary -*-

module Msf::Exploit::Git

###
#
# This module implements the pkt-line format used
# by Git.
#
###
module PktLine

  FLUSH_PKT         = "0000"
  DELIM_PKT         = "0001"
  RESPONSE_END_PKT  = "0002"

  ###
  #
  # pkt-line format
  # pkt-line     =  data-pkt / flush-pkt
  # data-pkt     =  pkt-len pkt-payload
  # pkt-len      =  4*(HEXDIG)
  # pkt-payload  =  (pkt-len - 4)*(OCTET)
  # source: https://git-scm.com/docs/protocol-common
  #
  ###
  def self.generate_pkt_line(data, type: 'data-pkt')
    case type
    when 'data-pkt'
      generate_data_pkt(data)
    when 'flush-pkt'
      FLUSH_PKT 
    end
  end

  def self.generate_data_pkt(data)
    return nil unless data

    return nil if data.empty?

    # The length should include the length
    # of pkt-payload plus four characters for
    # pkt-len plus another for the terminating LF
    pkt_line_len = data.length + 4 + 1
    pkt_line_len = pkt_line_len.to_s(16).rjust(4, '0')

    "#{pkt_line_len}#{data}\n"
  end

  def self.request_ends
    [ "#{FLUSH_PKT}0009done", "#{FLUSH_PKT}0009#{FLUSH_PKT}" ]
  end

  # Reads a single pkt-line and returns the data
  #
  # @param [String] a single pkt-line
  #
  # @return [String] the pkt-line data
  def self.get_pkt_line_data(pkt_line)
    return '' unless pkt_line.kind_of?(String)

    line_len = pkt_line.length - 4
    pkt_line[4, line_len - 1]
  end

  # Retrieves pkt-lines from argument supplied
  #
  # @param [String] data that possibly contains pkt-lines
  #
  # @return [Array] pkt-lines
  def self.get_pkt_lines(data)
    return [] if data.empty?

    pkt_lines = data.split("\n")
    pkt_lines.each { |line| line.gsub!(FLUSH_PKT, '') }
    pkt_lines.delete('')

    pkt_lines
  end

  # Determine if data contains any pkt-lines
  #
  # @param [String] the data to check for pkt-lines
  #
  # @return [Boolean]
  def self.has_pkt_line_data?(data)
    return false unless data.kind_of?(String)

    return false if data.empty?

    get_pkt_lines(data).empty? ? false : true
  end
end
end
