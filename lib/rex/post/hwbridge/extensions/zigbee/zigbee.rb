#
# -*- coding: binary -*-
require 'rex/post/hwbridge/client'

module Rex
module Post
module HWBridge
module Extensions
module Zigbee

###
# Zigbee extension - set of commands to be executed on zigbee compatible hw bridges
###

class Zigbee < Extension

  def initialize(client)
    super(client, 'zigbee')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'zigbee',
          'ext'  => self
        }
      ])
  end

  # Sets the default target device
  # @param device [String] Target Zigbee device ID
  def set_target_device(device)
    self.target_device = device
  end

  # Retrieves the default zigbee device ID
  # @return [String] Zigbee device ID
  def get_target_device
    self.target_device
  end

  # Gets supported Zigbee Devices
  # @return [Array] Devices
  def supported_devices
    client.send_request("/zigbee/supported_devices")
  end

  # Sets the channel
  # @param dev [String] Device to affect
  # @param channel [Integer] Channel number
  def set_channel(dev, channel)
    client.send_request("/zigbee/#{dev}/set_channel?chan=#{channel}")
  end

  # Injects a raw packet
  # @param dev [String] Zigbee Device ID
  # @param data [String] Raw hex data that will be Base64 encoded
  def inject(dev, data)
    data = Base64.urlsafe_encode64(data)
    client.send_request("/zigbee/#{dev}/inject?data=#{data}")
  end

  # Receives data from transceiver
  # @param dev [String] Zigbee Device ID
  # @return [Hash] { data: HexString, valid_crc: X, rssi: X }
  def recv(dev)
    data = client.send_request("/zigbee/#{dev}/recv")
    if data.size > 0
      data["data"] = Base64.urlsafe_decode64(data["data"]) if data.has_key? "data"
    end
    data
  end

  # Disables sniffer and puts the device in a state that can be changed (like adujsting channel)
  # @param dev [String] Zigbee Device ID
  def sniffer_off(dev)
    client.send_request("/zigbee/#{dev}/sniffer_off")
  end

  # Enables sniffer receive mode.  Not necessary to call before calling recv
  # @param dev [String] Zigbee Device ID
  def sniffer_on(dev)
    client.send_request("/zigbee/#{dev}/sniffer_on")
  end

  attr_accessor :target_device

end

end
end
end
end
end
