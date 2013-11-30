# -*- coding: binary -*-

require 'rex/post/meterpreter/channels/pool'
require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Channels
module Pools

###
#
# File
# ----
#
# This class represents a channel that is associated with a file
# on the remote half of the meterpreter connection.
#
###
class File < Rex::Post::Meterpreter::Channels::Pool

  ##
  #
  # Factory
  #
  ##

  #
  # This method returns an instance of a file pool channel that can be read
  # from, written to, seeked on, and other interacted with.
  #
  def File.open(client, name, mode = "r", perm = 0)
    return Channel.create(client, 'stdapi_fs_file',
        self, CHANNEL_FLAG_SYNCHRONOUS,
        [
          {
            'type'  => Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_FILE_PATH,
            'value' => client.unicode_filter_decode( name )
          },
          {
            'type'  => Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_FILE_MODE,
            'value' => mode + "b"
          },
        ])
  end

  ##
  #
  # Constructor
  #
  ##

  # Initializes the file channel instance
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)
  end

end

end; end; end; end; end

