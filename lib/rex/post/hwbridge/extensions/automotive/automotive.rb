#
# -*- coding: binary -*-
require 'rex/post/hwbridge/extensions/automotive/uds_errors'
require 'rex/post/hwbridge/client'

module Rex
module Post
module HWBridge
module Extensions
module Automotive

###
# Automotive extension - set of commands to be executed on automotive hw bridges
###

class Automotive < Extension

  include Rex::Post::HWBridge::Extensions::Automotive::UDSErrors

  def initialize(client)
    super(client, 'automotive')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'automotive',
          'ext'  => self
        }
      ])
  end

  #
  # Checks to see if the specified bus is valid
  #
  # @param bus [String] bus name
  #
  # @return [Boolean] return true if bus is valid
  def is_valid_bus?(bus)
    valid = false
    get_supported_buses if buses.nil?
    unless bus.blank?
      self.buses.each do |b|
        valid = true if b["bus_name"] == bus
      end
    end
    valid
  end

  # Checks for Errors in ISO-TP responses.  If an error is present
  # Document the error with an additional "error" => { "ACRONYMN" => "Definition" }
  #
  # @param data [Hash] client.send_request response
  #
  # @return [Hash] client.send_request response with "Error" if any exist
  def check_for_errors(data)
    if data && (data.key? "Packets")
      if data["Packets"].size == 1
        if data["Packets"][0]["DATA"].size > 3 && data["Packets"][0]["DATA"][1].hex == 0x7F
          if ERR_MNEMONIC.key? data["Packets"][0]["DATA"][3].hex
            err = data["Packets"][0]["DATA"][3].hex
            data["error"] = { ERR_MNEMONIC[err] => ERR_DESC[ERR_MNEMONIC[err]] }
          else
            data["error"] = { "UNK" => "An Unknown error detected" }
          end
        end
      end
    end
    data
  end

  #
  # Pass an array of bytes and return an array of ASCII byte representation
  #
  # @param arr [Array] Array of integers (bytes)
  #
  # @return [Array] Array of Hex string equivalents
  def array2hex(arr)
    # We give the flexibility of sending Integers or string hexes in the array
    arr.map { |b| "%02x" % (b.respond_to?("hex") ? b.hex : b ) }
  end

  def set_active_bus(bus)
    self.active_bus = bus
  end

  def get_supported_buses
    self.buses = client.send_request("/automotive/supported_buses")
    self.buses
  end

  def get_bus_config(bus)
    status = client.send_request("/automotive/#{bus}/config")
    status
  end

  def get_supported_methods(bus)
    client.send_request("/automotive/#{bus}/supported_methods")
  end

  def cansend(bus, id, data)
    client.send_request("/automotive/#{bus}/cansend?id=#{id}&data=#{data}")
  end

  def send_isotp_and_wait_for_response(bus, src_id, dst_id, data, opt = {})
    # TODO: Implement sending ISO-TP > 8 bytes
    data = [ data ] if data.is_a? Integer
    if data.size < 8
      data = array2hex(data).join
      request_str = "/automotive/#{bus}/isotpsend_and_wait?srcid=#{src_id}&dstid=#{dst_id}&data=#{data}"
      request_str += "&timeout=#{opt['TIMEOUT']}" if opt.key? "TIMEOUT"
      request_str += "&maxpkts=#{opt['MAXPKTS']}" if opt.key? "MAXPKTS"
      return check_for_errors(client.send_request(request_str))
    end
    nil
  end

  attr_reader :buses, :active_bus

  private

  attr_writer :buses, :active_bus

end

end
end
end
end
end
