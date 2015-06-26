# -*- coding: binary -*-

require 'rex/post/meeterpeter/extensions/extapi/tlv'
require 'rex/post/meeterpeter/extensions/extapi/window/window'
require 'rex/post/meeterpeter/extensions/extapi/service/service'
require 'rex/post/meeterpeter/extensions/extapi/clipboard/clipboard'
require 'rex/post/meeterpeter/extensions/extapi/adsi/adsi'
require 'rex/post/meeterpeter/extensions/extapi/ntds/ntds'
require 'rex/post/meeterpeter/extensions/extapi/wmi/wmi'

module Rex
module Post
module meeterpeter
module Extensions
module Extapi

###
#
# This meeterpeter extension contains an extended API which will allow for more
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
              'window'    => Rex::Post::meeterpeter::Extensions::Extapi::Window::Window.new(client),
              'service'   => Rex::Post::meeterpeter::Extensions::Extapi::Service::Service.new(client),
              'clipboard' => Rex::Post::meeterpeter::Extensions::Extapi::Clipboard::Clipboard.new(client),
              'adsi'      => Rex::Post::meeterpeter::Extensions::Extapi::Adsi::Adsi.new(client),
              'ntds'      => Rex::Post::meeterpeter::Extensions::Extapi::Ntds::Ntds.new(client),
              'wmi'       => Rex::Post::meeterpeter::Extensions::Extapi::Wmi::Wmi.new(client)
            })
        },
      ])
  end

end

end; end; end; end; end
