RSpec::Support.require_rspec_support 'encoded_string'
RSpec::Support.require_rspec_support 'hunk_generator'
RSpec::Support.require_rspec_support "object_formatter"

require 'pp'

module RSpec
  module Support
    # rubocop:disable ClassLength
    class Differ
      def diff(actual, expected)
        diff = ""

        if actual && expected
          if all_strings?(actual, expected)
            if any_multiline_strings?(actual, expected)
              diff = diff_as_string(coerce_to_string(actual), coerce_to_string(expected))
            end
          elsif no_procs?(actual, expected) && no_numbers?(actual, expected)
            diff = diff_as_object(actual, expected)
          end
        end

        diff.to_s
      end

      # rubocop:disable MethodLength
      def diff_as_string(actual, expected)
        encoding = EncodedString.pick_encoding(actual, expected)

        actual   = EncodedString.new(actual, encoding)
        expected = EncodedString.new(expected, encoding)

        output = EncodedString.new("\n", encoding)
        hunks = build_hunks(actual, expected)

        hunks.each_cons(2) do |prev_hunk, current_hunk|
          begin
            if current_hunk.overlaps?(prev_hunk)
              add_old_hunk_to_hunk(current_hunk, prev_hunk)
            else
              add_to_output(output, prev_hunk.diff(format_type).to_s)
            end
          ensure
            add_to_output(output, "\n")
          end
        end

        finalize_output(output, hunks.last.diff(format_type).to_s) if hunks.last

        color_diff output
      rescue Encoding::CompatibilityError
        handle_encoding_errors(actual, expected)
      end
      # rubocop:enable MethodLength

      def diff_as_object(actual, expected)
        actual_as_string = object_to_string(actual)
        expected_as_string = object_to_string(expected)
        diff_as_string(actual_as_string, expected_as_string)
      end

      def color?
        @color
      end

      def initialize(opts={})
        @color = opts.fetch(:color, false)
        @object_preparer = opts.fetch(:object_preparer, lambda { |string| string })
      end

    private

      def no_procs?(*args)
        safely_flatten(args).none? { |a| Proc === a }
      end

      def all_strings?(*args)
        safely_flatten(args).all? { |a| String === a }
      end

      def any_multiline_strings?(*args)
        all_strings?(*args) && safely_flatten(args).any? { |a| multiline?(a) }
      end

      def no_numbers?(*args)
        safely_flatten(args).none? { |a| Numeric === a }
      end

      def coerce_to_string(string_or_array)
        return string_or_array unless Array === string_or_array
        diffably_stringify(string_or_array).join("\n")
      end

      def diffably_stringify(array)
        array.map do |entry|
          if Array === entry
            entry.inspect
          else
            entry.to_s.gsub("\n", "\\n")
          end
        end
      end

      if String.method_defined?(:encoding)
        def multiline?(string)
          string.include?("\n".encode(string.encoding))
        end
      else
        def multiline?(string)
          string.include?("\n")
        end
      end

      def build_hunks(actual, expected)
        HunkGenerator.new(actual, expected).hunks
      end

      def finalize_output(output, final_line)
        add_to_output(output, final_line)
        add_to_output(output, "\n")
      end

      def add_to_output(output, string)
        output << string
      end

      def add_old_hunk_to_hunk(hunk, oldhunk)
        hunk.merge(oldhunk)
      end

      def safely_flatten(array)
        array = array.flatten(1) until (array == array.flatten(1))
        array
      end

      def format_type
        :unified
      end

      def color(text, color_code)
        "\e[#{color_code}m#{text}\e[0m"
      end

      def red(text)
        color(text, 31)
      end

      def green(text)
        color(text, 32)
      end

      def blue(text)
        color(text, 34)
      end

      def normal(text)
        color(text, 0)
      end

      def color_diff(diff)
        return diff unless color?

        diff.lines.map do |line|
          case line[0].chr
          when "+"
            green line
          when "-"
            red line
          when "@"
            line[1].chr == "@" ? blue(line) : normal(line)
          else
            normal(line)
          end
        end.join
      end

      def object_to_string(object)
        object = @object_preparer.call(object)
        case object
        when Hash
          hash_to_string(object)
        when Array
          PP.pp(ObjectFormatter.prepare_for_inspection(object), "".dup)
        when String
          object =~ /\n/ ? object : object.inspect
        else
          PP.pp(object, "".dup)
        end
      end

      def hash_to_string(hash)
        formatted_hash = ObjectFormatter.prepare_for_inspection(hash)
        formatted_hash.keys.sort_by { |k| k.to_s }.map do |key|
          pp_key   = PP.singleline_pp(key, "".dup)
          pp_value = PP.singleline_pp(formatted_hash[key], "".dup)

          "#{pp_key} => #{pp_value},"
        end.join("\n")
      end

      def handle_encoding_errors(actual, expected)
        if actual.source_encoding != expected.source_encoding
          "Could not produce a diff because the encoding of the actual string " \
          "(#{actual.source_encoding}) differs from the encoding of the expected " \
          "string (#{expected.source_encoding})"
        else
          "Could not produce a diff because of the encoding of the string " \
          "(#{expected.source_encoding})"
        end
      end
    end
    # rubocop:enable ClassLength
  end
end
