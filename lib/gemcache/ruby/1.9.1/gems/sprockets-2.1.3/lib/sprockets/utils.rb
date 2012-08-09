module Sprockets
  # `Utils`, we didn't know where else to put it!
  module Utils
    # If theres encoding support (aka Ruby 1.9)
    if "".respond_to?(:valid_encoding?)
      # Define UTF-8 BOM pattern matcher.
      # Avoid using a Regexp literal because it inheirts the files
      # encoding and we want to avoid syntax errors in other interpreters.
      UTF8_BOM_PATTERN = Regexp.new("\\A\uFEFF".encode('utf-8'))

      def self.read_unicode(pathname)
        pathname.read.tap do |data|
          # Eager validate the file's encoding. In most cases we
          # expect it to be UTF-8 unless `default_external` is set to
          # something else. An error is usually raised if the file is
          # saved as UTF-16 when we expected UTF-8.
          if !data.valid_encoding?
            raise EncodingError, "#{pathname} has a invalid " +
              "#{data.encoding} byte sequence"

          # If the file is UTF-8 and theres a BOM, strip it for safe concatenation.
          elsif data.encoding.name == "UTF-8" && data =~ UTF8_BOM_PATTERN
            data.sub!(UTF8_BOM_PATTERN, "")
          end
        end
      end

    else
      # Define UTF-8 and UTF-16 BOM pattern matchers.
      # Avoid using a Regexp literal to prevent syntax errors in other interpreters.
      UTF8_BOM_PATTERN  = Regexp.new("\\A\\xEF\\xBB\\xBF")
      UTF16_BOM_PATTERN = Regexp.new("\\A(\\xFE\\xFF|\\xFF\\xFE)")

      def self.read_unicode(pathname)
        pathname.read.tap do |data|
          # If the file is UTF-8 and theres a BOM, strip it for safe concatenation.
          if data =~ UTF8_BOM_PATTERN
            data.sub!(UTF8_BOM_PATTERN, "")

          # If we find a UTF-16 BOM, theres nothing we can do on
          # 1.8. Only UTF-8 is supported.
          elsif data =~ UTF16_BOM_PATTERN
            raise EncodingError, "#{pathname} has a UTF-16 BOM. " +
              "Resave the file as UTF-8 or upgrade to Ruby 1.9."
          end
        end
      end
    end

    # Prepends a leading "." to an extension if its missing.
    #
    #     normalize_extension("js")
    #     # => ".js"
    #
    #     normalize_extension(".css")
    #     # => ".css"
    #
    def self.normalize_extension(extension)
      extension = extension.to_s
      if extension[/^\./]
        extension
      else
        ".#{extension}"
      end
    end
  end
end
