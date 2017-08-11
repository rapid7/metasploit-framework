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
      #    '-b' => [ false, "some text" ]
      # )
      #
      def initialize(fmt)
        self.fmt = fmt
        self.longest = fmt.keys.max_by(&:length)
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
        skip_next = false

        args.each_with_index do |arg, idx|
          if skip_next
            skip_next = false
            next
          end

          if arg.length > 1 && arg[0] == '-' && arg[1] != '-'
            arg.split('').each do |flag|
              fmt.each_pair do |fmtspec, val|
                next if fmtspec != "-#{flag}"

                param = nil

                if val[0]
                  param = args[idx + 1]
                  skip_next = true
                end

                yield fmtspec, idx, param
              end
            end
          else
            yield nil, idx, arg
          end
        end
      end

      #
      # Returns usage information for this parsing context.
      #
      def usage
        txt = ["\nOPTIONS:\n"]

        fmt.sort.each do |entry|
          fmtspec, val = entry
          opt = val[0] ? " <opt>  " : "        "
          txt << "    #{fmtspec.ljust(longest.length)}#{opt}#{val[1]}"
        end

        txt << ""
        txt.join("\n")
      end

      def include?(search)
        fmt.include?(search)
      end

      def arg_required?(opt)
        fmt[opt][0] if fmt[opt]
      end

      attr_accessor :fmt     # :nodoc:
      attr_accessor :longest # :nodoc:
    end
  end
end
