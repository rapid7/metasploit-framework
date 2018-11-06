# frozen_string_literal: true
module YARD
  module CLI
    # This class parses a command name out of the +yard+ CLI command and calls
    # that command in the form:
    #
    #   $ yard command_name [options]
    #
    # If no command or arguments are specified, or if the arguments immediately
    # begin with a +--opt+ (not +--help+), the {default_command} will be used
    # (which itself defaults to +:doc+).
    #
    # == Adding a Command
    #
    # To add a custom command via plugin, create a mapping in {commands} from
    # the Symbolic command name to the {Command} class that implements the
    # command. To implement a command, see the documentation for the {Command}
    # class.
    #
    # @see Command
    # @see commands
    # @see default_command
    class CommandParser
      class << self
        # @return [Hash{Symbol => Command}] the mapping of command names to
        #   command classes to parse the user command.
        attr_accessor :commands

        # @return [Symbol] the default command name to use when no options
        #   are specified or
        attr_accessor :default_command
      end

      self.commands = SymbolHash[
        :config  => Config,
        :diff    => Diff,
        :display => Display,
        :doc     => Yardoc,
        :gems    => Gems,
        :graph   => Graph,
        :help    => Help,
        :list    => List,
        :markups => MarkupTypes,
        :ri      => YRI,
        :server  => Server,
        :stats   => Stats,
        :i18n    => I18n
      ]

      self.default_command = :doc

      # Convenience method to create a new CommandParser and call {#run}
      # @return (see #run)
      def self.run(*args) new.run(*args) end

      def initialize
        log.show_backtraces = false
      end

      # Runs the {Command} object matching the command name of the first
      # argument.
      # @return [void]
      def run(*args)
        unless args == ['--help']
          if args.empty? || args.first =~ /^-/
            command_name = self.class.default_command
          else
            command_name = args.first.to_sym
            args.shift
          end
          if commands.key?(command_name)
            return commands[command_name].run(*args)
          end
        end
        list_commands
      end

      private

      def commands; self.class.commands end

      def list_commands
        log.puts "Usage: yard <command> [options]"
        log.puts
        log.puts "Commands:"
        commands.keys.sort_by(&:to_s).each do |command_name|
          command = commands[command_name].new
          log.puts "%-8s %s" % [command_name, command.description]
        end
      end
    end
  end
end
