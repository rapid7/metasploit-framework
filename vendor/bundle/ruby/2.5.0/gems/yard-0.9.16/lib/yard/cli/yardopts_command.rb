# frozen_string_literal: true
require 'optparse'

module YARD
  module CLI
    # Abstract base class for command that reads .yardopts file
    #
    # @abstract
    # @since 0.8.3
    class YardoptsCommand < Command
      # The configuration filename to load extra options from
      DEFAULT_YARDOPTS_FILE = ".yardopts"

      # @return [Boolean] whether to parse options from .yardopts
      attr_accessor :use_yardopts_file

      # @return [Boolean] whether to parse options from .document
      attr_accessor :use_document_file

      # The options file name (defaults to {DEFAULT_YARDOPTS_FILE})
      # @return [String] the filename to load extra options from
      attr_accessor :options_file

      # Creates a new command that reads .yardopts
      def initialize
        super
        @options_file = DEFAULT_YARDOPTS_FILE
        @use_yardopts_file = true
        @use_document_file = true
      end

      # Parses commandline arguments
      # @param [Array<String>] args the list of arguments
      # @return [Boolean] whether or not arguments are valid
      # @since 0.5.6
      def parse_arguments(*args)
        parse_yardopts_options(*args)

        # Parse files and then command line arguments
        parse_rdoc_document_file
        parse_yardopts
        optparse(*args)
      end

      protected

      # Adds --[no-]yardopts / --[no-]document
      def yardopts_options(opts)
        opts.on('--[no-]yardopts [FILE]',
                "If arguments should be read from FILE",
                "  (defaults to yes, FILE defaults to .yardopts)") do |use_yardopts|
          if use_yardopts.is_a?(String)
            self.options_file = use_yardopts
            self.use_yardopts_file = true
          else
            self.use_yardopts_file = (use_yardopts != false)
          end
        end

        opts.on('--[no-]document', "If arguments should be read from .document file. ",
                                   "  (defaults to yes)") do |use_document|
          self.use_document_file = use_document
        end
      end

      private

      # Parses the .yardopts file for default yard options
      # @return [Array<String>] an array of options parsed from .yardopts
      def yardopts(file = options_file)
        return [] unless use_yardopts_file
        File.read_binary(file).shell_split
      rescue Errno::ENOENT
        []
      end

      # Parses out the yardopts/document options
      def parse_yardopts_options(*args)
        opts = OptionParser.new
        opts.base.long.clear # HACK: why are --help and --version defined?
        yardopts_options(opts)
        begin
          opts.parse(args)
        rescue OptionParser::ParseError => err
          idx = args.index(err.args.first)
          args = args[(idx + 1)..-1]
          args.shift while args.first && args.first[0, 1] != '-'
          retry
        end
      end

      def parse_rdoc_document_file(file = '.document')
        optparse(*support_rdoc_document_file!(file)) if use_document_file
      end

      def parse_yardopts(file = options_file)
        optparse(*yardopts(file)) if use_yardopts_file
      end

      # Reads a .document file in the directory to get source file globs
      # @return [Array<String>] an array of files parsed from .document
      def support_rdoc_document_file!(file = '.document')
        return [] unless use_document_file
        File.read(file).gsub(/^[ \t]*#.+/m, '').split(/\s+/)
      rescue Errno::ENOENT
        []
      end
    end
  end
end
