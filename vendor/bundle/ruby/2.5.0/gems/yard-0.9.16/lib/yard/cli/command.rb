# frozen_string_literal: true
require 'optparse'

module YARD
  module CLI
    # Abstract base class for CLI utilities. Provides some helper methods for
    # the option parser
    #
    # @abstract
    # @since 0.6.0
    class Command
      # Helper method to run the utility on an instance.
      # @see #run
      def self.run(*args) new.run(*args) end

      def description; '' end

      protected

      # Adds a set of common options to the tail of the OptionParser
      #
      # @param [OptionParser] opts the option parser object
      # @return [void]
      def common_options(opts)
        opts.separator ""
        opts.separator "Other options:"
        opts.on('-e', '--load FILE', 'A Ruby script to load before running command.') do |file|
          load_script(file)
        end
        opts.on('--plugin PLUGIN', 'Load a YARD plugin (gem with `yard-\' prefix)') do |name|
          # Not actually necessary to load here, this is done at boot in YARD::Config.load_plugins
          # YARD::Config.load_plugin(name)
        end
        opts.on('--legacy', 'Use old style Ruby parser and handlers. ',
                            '  Always on in 1.8.x.') do
          YARD::Parser::SourceParser.parser_type = :ruby18
        end
        opts.on('--safe', 'Enable safe mode for this instance') do
          # Parsed in YARD::Config.load
        end
        opts.on_tail('-q', '--quiet', 'Show no warnings.') { log.level = Logger::ERROR }
        opts.on_tail('--verbose', 'Show more information.') { log.level = Logger::INFO }
        opts.on_tail('--debug', 'Show debugging information.') { log.level = Logger::DEBUG }
        opts.on_tail('--backtrace', 'Show stack traces') { log.show_backtraces = true }
        opts.on_tail('-v', '--version', 'Show version.') { log.puts "yard #{YARD::VERSION}"; exit }
        opts.on_tail('-h', '--help', 'Show this help.')  { log.puts opts; exit }
      end

      # Parses the option and gracefully handles invalid switches
      #
      # @param [OptionParser] opts the option parser object
      # @param [Array<String>] args the arguments passed from input. This
      #   array will be modified.
      # @return [void]
      def parse_options(opts, args)
        opts.parse!(args)
      rescue OptionParser::ParseError => err
        unrecognized_option(err)
        args.shift if args.first && args.first[0, 1] != '-'
        retry
      end

      # Loads a Ruby script. If <tt>Config.options[:safe_mode]</tt> is enabled,
      # this method will do nothing.
      #
      # @param [String] file the path to the script to load
      # @since 0.6.2
      def load_script(file)
        return if YARD::Config.options[:safe_mode]
        load(file)
      rescue LoadError => load_exception
        log.error "The file `#{file}' could not be loaded:\n#{load_exception}"
        exit
      end

      # Callback when an unrecognize option is parsed
      #
      # @param [OptionParser::ParseError] err the exception raised by the
      #   option parser
      def unrecognized_option(err)
        log.warn "Unrecognized/#{err.message}"
      end
    end
  end
end
