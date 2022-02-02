# -*- coding: binary -*-

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/stream_pool'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module AudioOutput

###
#
# Play an audio file
#
###
class AudioOutput
  def initialize(client)
    @client = client
  end

  def session
    @client
  end

  # Upload file and play it
  def play_file(path)
    channel = Channel.create(client, 'audio_output', Rex::Post::Meterpreter::Channels::Pools::StreamPool, CHANNEL_FLAG_SYNCHRONOUS)

    # Read file buffers after buffers and upload
    buf_size = 8 * 1024 * 1024
    src_fd = nil

    begin
      src_fd = ::File.open(path, 'rb')
      src_size = src_fd.stat.size
      while (buf = src_fd.read(buf_size))
        channel.write(buf)
        percent = src_size / src_fd.pos.to_f * 100.0
      end
    ensure src_fd.close unless src_fd.nil?
    end

    channel.close()
  end

  attr_accessor :client
end

end
end
end
end
end
end
