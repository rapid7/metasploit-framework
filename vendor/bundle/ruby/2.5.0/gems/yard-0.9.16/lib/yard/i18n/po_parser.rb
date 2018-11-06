# frozen_string_literal: true
module YARD
  module I18n
    # +Locale+ is a wrapper for gettext's PO parsing feature. It hides
    # gettext API difference from YARD.
    #
    # @since 0.8.8
    class POParser
      if RUBY_VERSION < "1.9"
        begin
          require "gettext/tools/poparser"
          require "gettext/runtime/mofile"
          @@gettext_version = 2
        rescue LoadError
          log.warn "Need gettext gem 2.x for i18n feature:\n" \
                   "\tgem install gettext -v 2.3.9"
        end
      else
        begin
          require "gettext/po_parser"
          require "gettext/mo"
          @@gettext_version = 3
        rescue LoadError
          begin
            require "gettext/tools/poparser"
            require "gettext/runtime/mofile"
            @@gettext_version = 2
          rescue LoadError
            log.warn "Need gettext gem for i18n feature:\n" \
                     "\tgem install gettext"
          end
        end
      end

      class << self
        # @return [Boolean] true if gettext is available, false otherwise.
        def available?
          !@@gettext_version.nil?
        end
      end

      # Parses PO file.
      #
      # @param [String] file path of PO file to be parsed.
      # @return [Hash<String, String>] parsed messages.
      def parse(file)
        case @@gettext_version
        when 2
          parser = GetText::PoParser.new
          data = GetText::MoFile.new
        when 3
          parser = GetText::POParser.new
          data = GetText::MO.new
        end
        parser.report_warning = false
        parser.parse_file(file, data)
        data
      end
    end
  end
end
