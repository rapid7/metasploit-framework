# frozen_string_literal: true
module YARD
  module I18n
    # Provides some convenient features for translating a text.
    class Text
      # Creates a text object that has translation related features for
      # the input text.
      #
      # @param [#each_line] input a text to be translated.
      # @option options [Boolean] :have_header (false) whether the
      #   input text has header or not.
      def initialize(input, options = {})
        @input = input
        @options = options
      end

      # Extracts translation target messages from +@input+.
      #
      # @yield [:attribute, name, value, line_no] the block that
      #   receives extracted an attribute in header. It may called many
      #   times.
      # @yieldparam [String] name the name of extracted attribute.
      # @yieldparam [String] value the value of extracted attribute.
      # @yieldparam [Integer] line_no the defined line number of extracted
      #   attribute.
      # @yield [:paragraph, text, start_line_no] the block that
      #   receives extracted a paragraph in body. Paragraph is a text
      #   block separated by one or more empty lines. Empty line is a
      #   line that contains only zero or more whitespaces. It may
      #   called many times.
      # @yieldparam [String] text the text of extracted paragraph.
      # @yieldparam [Integer] start_line_no the start line number of
      #   extracted paragraph.
      # @return [void]
      def extract_messages
        parse do |part|
          case part[:type]
          when :markup, :empty_line
            # ignore
          when :attribute
            yield(:attribute, part[:name], part[:value], part[:line_no])
          when :paragraph
            yield(:paragraph, part[:paragraph], part[:line_no])
          end
        end
      end

      # Translates into +locale+.
      #
      # @param [Locale] locale the translation target locale.
      # @return [String] translated text.
      def translate(locale)
        translated_text = String.new("")
        parse do |part|
          case part[:type]
          when :markup
            translated_text << part[:line]
          when :attribute
            prefix = "#{part[:prefix]}#{part[:name]}#{part[:infix]}"
            value = locale.translate(part[:value])
            suffix = part[:suffix]
            translated_text << "#{prefix}#{value}#{suffix}"
          when :paragraph
            translated_text << locale.translate(part[:paragraph])
          when :empty_line
            translated_text << part[:line]
          else
            raise "should not reach here: unexpected type: #{type}"
          end
        end
        translated_text
      end

      private

      def parse(&block)
        paragraph = String.new("")
        paragraph_start_line = 0
        line_no = 0
        in_header = @options[:have_header]

        @input.each_line do |line|
          line_no += 1
          if in_header
            case line
            when /^#!\S+\s*$/
              if line_no == 1
                emit_markup_event(line, line_no, &block)
              else
                in_header = false
              end
            when /^(\s*#\s*@)(\S+)(\s*)(.+?)(\s*)$/
              emit_attribute_event(Regexp.last_match, line_no, &block)
            else
              in_header = false
              if line.strip.empty?
                emit_empty_line_event(line, line_no, &block)
                next
              end
            end
            next if in_header
          end

          case line
          when /^\s*$/
            if paragraph.empty?
              emit_empty_line_event(line, line_no, &block)
            else
              paragraph << line
              emit_paragraph_event(paragraph, paragraph_start_line, line_no,
                                   &block)
              paragraph = String.new("")
            end
          else
            paragraph_start_line = line_no if paragraph.empty?
            paragraph << line
          end
        end

        unless paragraph.empty?
          emit_paragraph_event(paragraph, paragraph_start_line, line_no, &block)
        end
      end

      def emit_markup_event(line, line_no)
        part = {
          :type => :markup,
          :line => line,
          :line_no => line_no
        }
        yield(part)
      end

      def emit_attribute_event(match_data, line_no)
        part = {
          :type => :attribute,
          :prefix => match_data[1],
          :name => match_data[2],
          :infix => match_data[3],
          :value => match_data[4],
          :suffix => match_data[5],
          :line_no => line_no
        }
        yield(part)
      end

      def emit_empty_line_event(line, line_no)
        part = {
          :type => :empty_line,
          :line => line,
          :line_no => line_no
        }
        yield(part)
      end

      def emit_paragraph_event(paragraph, paragraph_start_line, line_no, &block)
        paragraph_part = {
          :type => :paragraph,
          :line_no => paragraph_start_line
        }
        match_data = /(\s*)\z/.match(paragraph)
        if match_data
          paragraph_part[:paragraph] = match_data.pre_match
          yield(paragraph_part)
          emit_empty_line_event(match_data[1], line_no, &block)
        else
          paragraph_part[:paragraph] = paragraph
          yield(paragraph_part)
        end
      end
    end
  end
end
