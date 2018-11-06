# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.


    #
    # Base64 encoder
    #
    def self.encode_base64(str, delim=nil)
      if delim
        [str.to_s].pack("m").gsub(/\s+/, delim)
      else
        [str.to_s].pack("m0")
      end
    end

    #
    # Base64 decoder
    #
    def self.decode_base64(str)
      str.to_s.unpack("m")[0]
    end

    #
    # Base64 encoder (URL-safe RFC6920)
    #
    def self.encode_base64url(str, delim=nil)
      encode_base64(str, delim).
        tr('+/', '-_').
        gsub('=', '')
    end

    #
    # Base64 decoder (URL-safe RFC6920, ignores invalid characters)
    #
    def self.decode_base64url(str)
      decode_base64(
        str.gsub(/[^a-zA-Z0-9_\-]/, '').
          tr('-_', '+/'))
    end
  end
end
