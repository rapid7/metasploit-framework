# -*- coding: binary -*-

require 'rex/io/stream_abstraction'
require 'rex/post/meterpreter/channels/socket_abstraction'

module Rex
module Post
module Meterpreter

###
#
# Stream
# ------
#
# This class represents a channel that is streaming.  This means
# that sequential data is flowing in either one or both directions.
#
###
class Stream < Rex::Post::Meterpreter::Channel

  include Rex::Post::Meterpreter::SocketAbstraction
  include Rex::IO::StreamAbstraction

  class << self
    def cls
      return CHANNEL_CLASS_STREAM
    end
  end

  module SocketInterface
    include Rex::Post::Meterpreter::SocketAbstraction::SocketInterface
    def type?
      'tcp'
    end
  end

end

end; end; end

