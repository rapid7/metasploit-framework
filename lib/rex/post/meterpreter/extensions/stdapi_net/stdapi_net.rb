# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/net/resolve'
require 'rex/post/meterpreter/extensions/stdapi/net/config'
require 'rex/post/meterpreter/extensions/stdapi/net/socket'
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi_Net
  module Net
    include Rex::Post::Meterpreter::Extensions::Stdapi::Net
  end
  include Rex::Post::Meterpreter::Extensions::Stdapi

###
#
# Standard ruby interface to remote entities for meterpreter.  It provides
# basic access to files, network, system, and other properties of the remote
# machine that are fairly universal.
#
###
class Stdapi_Net < Extension

  def self.extension_id
    Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
  end

  #
  # Initializes an instance of the standard API extension.
  #
  def initialize(client)
    super(client, 'stdapi_net')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'net',
          'ext'  => ObjectAliases.new(
            {
              'config'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config.new(client),
              'socket'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket.new(client),
              'resolve'  => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Resolve.new(client)
            })
        }
      ])
  end

  #
  # Sets the client instance on a duplicated copy of the supplied class.
  #
  def brand(klass)
    klass = klass.dup
    klass.client = self.client
    return klass
  end
end

end; end; end; end; end
