# -*- coding: binary -*-
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# HTTP response class.
#
###
class Response < Packet

  ##
  #
  # Builtin response class wrappers.
  #
  ##

  #
  # HTTP 200/OK response class wrapper.
  #
  class OK < Response
    def initialize(message = 'OK', proto = DefaultProtocol)
      super(200, message, proto)
    end
  end

  #
  # HTTP 404/File not found response class wrapper.
  #
  class E404 < Response
    def initialize(message = 'File not found', proto = DefaultProtocol)
      super(404, message, proto)
    end
  end

  #
  # Constructage of the HTTP response with the supplied code, message, and
  # protocol.
  #
  def initialize(code = 200, message = 'OK', proto = DefaultProtocol)
    super()

    self.code    = code.to_i
    self.message = message
    self.proto   = proto

    # Default responses to auto content length on
    self.auto_cl = true

    # default chunk sizes (if chunked is used)
    self.chunk_min_size = 1
    self.chunk_max_size = 10

    # 100 continue counter
    self.count_100 = 0
  end

  #
  # Gets cookies from the Set-Cookie header in a format to be used
  # in the 'cookie' send_request field
  #
  def get_cookies
    cookies = ""
    if (self.headers.include?('Set-Cookie'))
      set_cookies = self.headers['Set-Cookie']
      key_vals = set_cookies.scan(/\s?([^, ;]+?)=([^, ;]+?);/)
      key_vals.each do |k, v|
        # Dont downcase actual cookie name as may be case sensitive
        name = k.downcase
        next if name == 'path'
        next if name == 'expires'
        next if name == 'domain'
        next if name == 'max-age'
        cookies << "#{k}=#{v}; "
      end
    end

    return cookies.strip
  end

  #
  # Updates the various parts of the HTTP response command string.
  #
  def update_cmd_parts(str)
    if (md = str.match(/HTTP\/(.+?)\s+(\d+)\s?(.+?)\r?\n?$/))
      self.message = md[3].gsub(/\r/, '')
      self.code    = md[2].to_i
      self.proto   = md[1]
    else
      raise RuntimeError, "Invalid response command string", caller
    end

    check_100()
  end

  #
  # Allow 100 Continues to be ignored by the caller
  #
  def check_100
    # If this was a 100 continue with no data, reset
    if self.code == 100 and (self.body_bytes_left == -1 or self.body_bytes_left == 0) and self.count_100 < 5
      self.reset_except_queue
      self.count_100 += 1
    end
  end

  #
  # Returns the response based command string.
  #
  def cmd_string
    "HTTP\/#{proto} #{code}#{(message and message.length > 0) ? ' ' + message : ''}\r\n"
  end

  #
  # Used to store a copy of the original request
  #
  attr_accessor :request


  attr_accessor :code
  attr_accessor :message
  attr_accessor :proto
  attr_accessor :count_100
end

end
end
end
