# -*- coding: binary -*-
# frozen_string_literal: true
require 'shellwords'

module Rex
  module Parser
    ###
    #
    # This class parses arguments in a getopt style format, kind of.
    # Unfortunately, the default ruby getopt implementation will only
    # work on ARGV, so we can't use it.
    #
    ###
    class Arguments
      # e.g. '-x' or '-xyz'
      SHORT_FLAG = /^-[a-zA-Z]+$/.freeze
      private_constant :SHORT_FLAG
      # e.g. '--verbose', '--very-verbose' or '--very-very-verbose'
      LONG_FLAG = /^--([a-zA-Z]+)(-[a-zA-Z]+)*$/.freeze
      private_constant :LONG_FLAG

      #
      # Initializes the format list with an array of formats like:
      #
      # Arguments.new(
      #    '-z'                => [ has_argument, "some text", "<argument_description>" ],
      #    '-b'                => [ false, "some text"                 ],
      #    ['-b']              => [ false, "some text"                 ],
      #    ['-x', '--execute'] => [ true, "mixing long and short args" ],
      #    ['-t', '--test']    => [ true, "testing custom <opt> value", "<arg_to_test>" ],
      #    ['--long-flag']     => [ false, "sample long flag" ]
      # )
      #
      def initialize(fmt)
        normalised_fmt = fmt.map { |key, metadata| [Array(key), metadata] }.to_h
        self.fmt = normalised_fmt
        self.longest = normalised_fmt.each_pair.map { |key, value| key.flatten.join(', ') + (value[0] ? ' ' + value[2].to_s : '') }.max_by(&:length)
      end

      #
      # Takes a string and converts it into an array of arguments.
      #
      def self.from_s(str)
        Shellwords.shellwords(str)
      end

      #
      # Parses the supplied arguments into a set of options.
      #
      def parse(args, &_block)
        skip_next = 0

        args.each_with_index do |arg, idx|
          if skip_next > 0
            skip_next -= 1
            next
          end

          param = nil
          if arg =~ SHORT_FLAG
            # parsing needs to take into account a couple requirements
            #  1. longest `short` flag found in 'arg' should be extracted first
            #    * consider passing the short flag to a tokenizer that returns a list of tokens in order with any invalid tokens
            #  2. any short flag arguments that need an option will consume the next option from the list
            short_args_from_token(arg).each do |letter|
              next unless include?("-#{letter}")

              if arg_required?("-#{letter}")
                skip_next += 1
                param = args[idx + skip_next]
              end

              yield "-#{letter}", idx, param
            end
          elsif arg =~ LONG_FLAG && include?(arg)
            if arg_required?(arg)
              skip_next = 1
              param = args[idx + skip_next]
            end

            # Try to yield the short hand version of our argument if possible
            # This will result in less areas of code that would need to be changed
            to_return = short_arg_from_long_arg(arg)
            if to_return.nil?
              yield arg, idx, param
            else
              yield to_return, idx, param
            end
          else
            # else treat the passed in flag as argument
            yield nil, idx, arg
          end
        end
      end

      #
      # Returns usage information for this parsing context.
      #
      def usage
        txt = ["\nOPTIONS:\n"]

        fmt.sort_by { |key, _metadata| key.to_s.downcase }.each do |key, val|
          # if the arg takes in a parameter, get parameter string
          opt = val[0] ? " #{val[2]}" : ''

          # Get all arguments for a command
          output = key.join(', ')
          output += opt

          # Left align the fmt options and <opt> string
          aligned_option = "    #{output.ljust(longest.length)}"
          txt << "#{aligned_option}  #{val[1]}"
        end

        txt << ""
        txt.join("\n")
      end

      def include?(search)
        fmt.keys.flatten.include?(search)
      end

      def arg_required?(opt)
        value = select_value_from_fmt_option(opt)
        return false if value.nil?

        value.first
      end

      def option_keys
        fmt.keys.flatten
      end

      # Return new Parser object featuring options from the base object and including the options hash that was passed in
      def merge(to_merge)
        return fmt unless to_merge.is_a?(Hash)

        Rex::Parser::Arguments.new(fmt.clone.merge(to_merge))
      end

      private

      attr_accessor :fmt     # :nodoc:
      attr_accessor :longest # :nodoc:

      def select_value_from_fmt_option(option)
        fmt_option = fmt.find { |key, value| value if key.include?(option) }
        return if fmt_option.nil?

        fmt_option[1]
      end

      # Returns the short-flag equivalent of any option passed in, if one exists
      # Returns nil if one does not exist
      def short_arg_from_long_arg(long_arg)
        fmt_option = fmt.find { |key, value| value if key.include?(long_arg) }.first
        # if fmt_option == [long_arg] that means that a short flag option for it does not exist
        return if fmt_option.nil? || fmt_option == [long_arg]

        fmt_option.each { |opt| return opt if opt =~ SHORT_FLAG }
      end

      # Parsing takes into account longest `short` flag found in 'arg' should as extracted first
      #
      # Returns Array of short arguments found in `arg`
      def short_args_from_token(arg)
        compare_arg = arg.dup[1..-1]
        short_args = []
        found_args = {}
        fmt.keys.each do |keys|
          if keys.first =~ SHORT_FLAG
            short_args << keys.first[1..-1]
          end
        end
        short_args.sort_by! { |value| value.downcase }.reverse!
        short_args.each do |short_arg|
          break if compare_arg.empty?
          if compare_arg.include? short_arg
            found_args[arg.index(short_arg)] = short_arg
            compare_arg.gsub!(short_arg, '')
          end
        end
        found_args.sort_by { |key, _value| key }.to_h.values
      end
    end
  end
end
