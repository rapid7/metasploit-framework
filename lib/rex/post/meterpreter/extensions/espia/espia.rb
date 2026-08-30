# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/espia/tlv'
require 'rex/post/meterpreter/extensions/espia/command_ids'

module Rex
module Post
module Meterpreter
module Extensions
module Espia

###
#
# This meterpreter extensions interface that is capable
# grab webcam frame and recor mic audio
#
###
class Espia < Extension

  def self.extension_id
    EXTENSION_ID_ESPIA
  end

  def initialize(client)
    super(client, 'espia')

    client.register_extension_aliases(
      [
        {
          'name' => 'espia',
          'ext'  => self
        },
      ])
  end

  def espia_image_get_dev_screen
    request = Packet.create_request(COMMAND_ID_ESPIA_IMAGE_GET_DEV_SCREEN)
    response = client.send_request( request )
    if response.result == 0
      response.get_tlv_value(TLV_TYPE_DEV_SCREEN)
    else
      nil
    end
  end

end

end; end; end; end; end
