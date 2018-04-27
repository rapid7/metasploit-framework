# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/lua/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Lua

###
#
# This meterpreter extension can be used to capture execute lua code in memory 
#
###
class Lua < Extension


  def initialize(client)
    super(client, 'lua')

    client.register_extension_aliases(
      [
        {
          'name' => 'lua',
          'ext'  => self
        },
      ])
  end

  # Execute provided lua code
  def execute(code='print("Hello mettle")')
    request = Packet.create_request('lua_dostring')
    response = client.send_request(request)
  end

end

end; end; end; end; end
