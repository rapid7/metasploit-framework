#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/extapi/tlv'
require 'rex/post/meterpreter/extensions/extapi/window/window'
require 'rex/post/meterpreter/extensions/extapi/service/service'

module Rex
module Post
module Meterpreter
module Extensions
module Extapi

###
#
# This meterpreter extension contains an extended API which will allow for more
#  advanced enumeration of the victim.
#
###
class Extapi < Extension

  def initialize(client)
    super(client, 'extapi')

    client.register_extension_aliases(
      [
        {
          'name' => 'extapi',
          'ext'  => ObjectAliases.new(
            {
              'window'  => Rex::Post::Meterpreter::Extensions::Extapi::Window::Window.new(client),
              'service' => Rex::Post::Meterpreter::Extensions::Extapi::Service::Service.new(client)
            })
        },
      ])
  end

end

end; end; end; end; end
