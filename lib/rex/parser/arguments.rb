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
      #
      # Initializes the format list with an array of formats like:
      #
      # Arguments.new(
      #    '-b'                => [ false, "some text"                 ],
      #    ['-b']              => [ false, "some text"                 ],
      #    '--sample'          => [ false, "sample long arg"           ],
      #    '--also-a-sample'   => [ false, "sample longer arg"         ],
      #    ['-x', '--execute'] => [ true, "mixing long and short args" ]
      # )
      #
      def initialize(fmt)
        normalised_fmt = fmt.map { |key, metadata| [Array(key), metadata] }.to_h
        self.fmt = normalised_fmt
        self.longest = normalised_fmt.keys.map { |key| key.flatten.join(', ') }.max_by(&:length)
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
        # e.g. '-x' or '-xyz'
        short_flag = /^-[a-zA-Z]+$/
        # e.g. '--verbose', '--very-verbose' or '--very-very-verbose'
        long_flag = /^--([a-zA-Z]+)((-[a-zA-Z]+)*)$/

        skip_next = false

        args.each_with_index do |arg, idx|
          if skip_next
            skip_next = false
            next
          end

          param = nil
          if arg =~ short_flag
            arg.split('')[1..-1].each do |letter|
              next unless include?("-#{letter}")

              if arg_required?("-#{letter}")
                param = args[idx + 1]
                skip_next = true
              end

              yield "-#{letter}", idx, param
            end
          elsif arg =~ long_flag && include?(arg)
            if arg_required?(arg)
              param = args[idx + 1]
              skip_next = true
            end

            yield arg, idx, param
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
          opt = val[0] ? " <opt>  " : "        "

          # Get all arguments for a command
          output = key.join(', ')
          output += opt

          # Left align the fmt options and <opt> string
          txt << "    #{(output).ljust((longest + opt).length)}#{val[1]}"
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
    end
  end
end
