require 'metasploit/framework/parsed_options/base'

class Metasploit::Framework::ParsedOptions::RemoteDB < Metasploit::Framework::ParsedOptions::Base

  def options
    unless @options
      super.tap { |options|
        options.console = ActiveSupport::OrderedOptions.new

        options.console.commands = []
        options.console.confirm_exit = false
        options.console.histfile = nil
        options.console.local_output = nil
        options.console.plugins = []
        options.console.quiet = false
        options.console.real_readline = false
        options.console.resources = []
        options.console.subcommand = :run
      }
    end

    @options
  end

  #######
  private
  #######

  def option_parser
    unless @option_parser
      super.tap { |option_parser|
        option_parser.banner = "Usage: #{option_parser.program_name} [options]"

        option_parser.separator ''
        option_parser.separator 'Remote DB options:'

        option_parser.on('-ns', "Remove signal processing") do
          options.database.no_signal = true
        end

      }
    end

    @option_parser
  end
end