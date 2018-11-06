# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.



    #
    # Encode a string in a manor useful for HTTP URIs and URI Parameters.
    #
    def self.uri_encode(str, mode = 'hex-normal')
      return "" if str == nil

      return str if mode == 'none' # fast track no encoding

      all = /./
      noslashes = /[^\/\\]+/
      # http://tools.ietf.org/html/rfc3986#section-2.3
      normal = /[^a-zA-Z0-9\/\\\.\-_~]+/

      case mode
        when 'hex-all'
          return str.gsub(all) { |s| Rex::Text.to_hex(s, '%') }
        when 'hex-normal'
          return str.gsub(normal) { |s| Rex::Text.to_hex(s, '%') }
        when 'hex-noslashes'
          return str.gsub(noslashes) { |s| Rex::Text.to_hex(s, '%') }
        when 'hex-random'
          res = ''
          str.each_byte do |c|
            b = c.chr
            res << ((rand(2) == 0) ?
              b.gsub(all)   { |s| Rex::Text.to_hex(s, '%') } :
              b.gsub(normal){ |s| Rex::Text.to_hex(s, '%') } )
          end
          return res
        when 'u-all'
          return str.gsub(all) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
        when 'u-normal'
          return str.gsub(normal) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
        when 'u-noslashes'
          return str.gsub(noslashes) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
        when 'u-random'
          res = ''
          str.each_byte do |c|
            b = c.chr
            res << ((rand(2) == 0) ?
              b.gsub(all)   { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) } :
              b.gsub(normal){ |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) } )
          end
          return res
        when 'u-half'
          return str.gsub(all) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms-half'), '%u', 2) }
        else
          raise TypeError, "invalid mode #{mode.inspect}"
      end
    end

    #
    # Encode a string in a manner useful for HTTP URIs and URI Parameters.
    #
    # @param str [String] The string to be encoded
    # @param mode ["hex","int","int-wide"]
    # @return [String]
    # @raise [TypeError] if +mode+ is not one of the three available modes
    def self.html_encode(str, mode = 'hex')
      case mode
        when 'hex'
          return str.unpack('C*').collect{ |i| "&#x" + ("%.2x" % i) + ";"}.join
        when 'int'
          return str.unpack('C*').collect{ |i| "&#" + i.to_s + ";"}.join
        when 'int-wide'
          return str.unpack('C*').collect{ |i| "&#" + ("0" * (7 - i.to_s.length)) + i.to_s + ";" }.join
        else
          raise TypeError, 'invalid mode'
      end
    end

    #
    # Decode a string that's html encoded
    #
    def self.html_decode(str)
      decoded_str = CGI.unescapeHTML(str)
      return decoded_str
    end

    #
    # Encode an ASCII string so it's safe for XML. It's a wrapper for to_hex_ascii.
    #
    def self.xml_char_encode(str)
      self.to_hex_ascii(str, "&#x", 1, ";")
    end

    #
    # Decode a URI encoded string
    #
    def self.uri_decode(str)
      str.gsub(/(%[a-z0-9]{2})/i){ |c| [c[1,2]].pack("H*") }
    end
  end
end
