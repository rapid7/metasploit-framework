# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Compresses a string, eliminating all superfluous whitespace before and
    # after lines and eliminating all lines.
    #
    # @param str [String] The string in which to crunch whitespace
    # @return [String] Just like +str+, but with repeated whitespace characters
    #   trimmed down to a single space
    def self.compress(str)
      str.gsub(/\n/m, ' ').gsub(/\s+/, ' ').gsub(/^\s+/, '').gsub(/\s+$/, '')
    end



    # Returns true if zlib can be used.
    def self.zlib_present?
      begin
        temp = Zlib
        return true
      rescue
        return false
      end
    end

    # backwards compat for just a bit...
    def self.gzip_present?
      self.zlib_present?
    end

    #
    # Compresses a string using zlib
    #
    # @param str [String] The string to be compressed
    # @param level [Integer] One of the Zlib compression level constants
    # @return [String] The compressed version of +str+
    def self.zlib_deflate(str, level = Zlib::BEST_COMPRESSION)
      if self.zlib_present?
        z = Zlib::Deflate.new(level)
        dst = z.deflate(str, Zlib::FINISH)
        z.close
        return dst
      else
        raise RuntimeError, "Gzip support is not present."
      end
    end

    #
    # Uncompresses a string using zlib
    #
    # @param str [String] Compressed string to inflate
    # @return [String] The uncompressed version of +str+
    def self.zlib_inflate(str)
      if(self.zlib_present?)
        zstream = Zlib::Inflate.new
        buf = zstream.inflate(str)
        zstream.finish
        zstream.close
        return buf
      else
        raise RuntimeError, "Gzip support is not present."
      end
    end

    #
    # Compresses a string using gzip
    #
    # @param str (see zlib_deflate)
    # @param level [Integer] Compression level, 1 (fast) to 9 (best)
    # @return (see zlib_deflate)
    def self.gzip(str, level = 9)
      raise RuntimeError, "Gzip support is not present." if (!zlib_present?)
      raise RuntimeError, "Invalid gzip compression level" if (level < 1 or level > 9)

      s = ""
      s.force_encoding('ASCII-8BIT') if s.respond_to?(:encoding)
      gz = Zlib::GzipWriter.new(StringIO.new(s, 'wb'), level)
      gz << str
      gz.close
      return s
    end

    #
    # Uncompresses a string using gzip
    #
    # @param str (see zlib_inflate)
    # @return (see zlib_inflate)
    def self.ungzip(str)
      raise RuntimeError, "Gzip support is not present." if (!zlib_present?)

      s = ""
      s.force_encoding('ASCII-8BIT') if s.respond_to?(:encoding)
      gz = Zlib::GzipReader.new(StringIO.new(str, 'rb'))
      s << gz.read
      gz.close
      return s
    end
  end
end
