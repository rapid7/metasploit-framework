# frozen_string_literal: true
module YARD
  module CLI
    # Handles help for commands
    # @since 0.6.0
    class Help < Command
      def description; "Retrieves help for a command" end

      def run(*args)
        cmd = args.first && CommandParser.commands[args.first.to_sym]
        if cmd
          cmd.run('--help')
        else
          log.puts "Command #{args.first} not found." if args.first
          CommandParser.run('--help')
        end
      end
    end
  end
end
