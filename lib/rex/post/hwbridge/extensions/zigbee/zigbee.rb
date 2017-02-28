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

  # Gets supported Zigbee Devices
  # @return [Array] Devices
  def supported_devices
    client.send_request("/zigbee/supported_devices")
  end
end

end
end
end
end
end
