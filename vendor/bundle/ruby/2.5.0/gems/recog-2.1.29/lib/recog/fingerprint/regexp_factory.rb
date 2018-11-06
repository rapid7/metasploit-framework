
module Recog
  class Fingerprint

    #
    # @example
    #   r = RegexpFactory.build("^Apache[ -]Coyote/(\d\.\d)$", "REG_ICASE")
    #   r.match("Apache-Coyote/1.1")
    #
    module RegexpFactory

      # Currently, only options relating to case insensitivity and
      # multiline/newline are supported.  Because Recog's data is used by tools
      # written in different languages like Ruby and Java, we currently support
      # specifying them in a variety of ways.  This map controls how they can
      # be specified.
      #
      # TODO: consider supporting only a simpler variant and require that tools
      # that use Recog data translate accordingly
      FLAG_MAP = {
        # multiline variations
        'REG_DOT_NEWLINE'   => Regexp::MULTILINE,
        'REG_LINE_ANY_CRLF' => Regexp::MULTILINE,
        'REG_MULTILINE'     => Regexp::MULTILINE,
        # case variations
        'REG_ICASE'         => Regexp::IGNORECASE,
        'IGNORECASE'        => Regexp::IGNORECASE
      }

      DEFAULT_FLAGS = 0

      # @return [Regexp]
      def self.build(pattern, flags)
        options = build_options(flags)
        Regexp.new(pattern, options)
      end

      # Convert string flag names as used in Recog XML into a Fixnum suitable for
      # passing as the `options` parameter to `Regexp.new`
      #
      # @see FLAG_MAP
      # @param flags [Array<String>]
      # @return [Fixnum] Flags for creating a regular expression object
      def self.build_options(flags)
        unsupported_flags = flags.select { |flag| !FLAG_MAP.key?(flag) }
        unless unsupported_flags.empty?
          fail "Unsupported regular expression flags found: #{unsupported_flags.join(',')}. Must be one of: #{FLAG_MAP.keys.join(',')}"
        end
        flags.reduce(DEFAULT_FLAGS) do |sum, flag|
          sum |= (FLAG_MAP[flag] || 0)
        end
      end
    end
  end
end

