# Parsed options for {Metasploit::Framework::Command::Console}
class Metasploit::Framework::ParsedOptions::Console < Metasploit::Framework::ParsedOptions::Base
  # Options parsed from msfconsole command-line.
  #
  # @return [ActiveSupport::OrderedOptions]
  def options
    unless @options
      super.tap { |options|
        options.console = ActiveSupport::OrderedOptions.new

        options.console.commands = []
        options.console.confirm_exit = false
        options.console.defanged = false
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

  private

  # Parses msfconsole arguments into {#options}.
  #
  # @return [OptionParser]
  def option_parser
    unless @option_parser
      super.tap { |option_parser|
        option_parser.banner = "Usage: #{option_parser.program_name} [options]"

        option_parser.separator ''
        option_parser.separator 'Console options:'

        option_parser.on('-a', '--ask', "Ask before exiting Metasploit or accept 'exit -y'") do
          options.console.confirm_exit = true
        end

        option_parser.on('-d', '--defanged', 'Execute the console as defanged') do
          options.console.defanged = true
        end

        option_parser.on('-L', '--real-readline', 'Use the system Readline library instead of RbReadline') do
          options.console.real_readline = true
        end

        option_parser.on('-o', '--output FILE', 'Output to the specified file') do |file|
          options.console.local_output = file
        end

        option_parser.on('-p', '--plugin PLUGIN', 'Load a plugin on startup') do |plugin|
          options.console.plugins << plugin
        end

        option_parser.on('-q', '--quiet', 'Do not print the banner on start up') do
          options.console.quiet = true
        end

        option_parser.on('-r', '--resource FILE', 'Execute the specified resource file') do |file|
          options.console.resources << file
        end

        option_parser.on(
            '-x',
            '--execute-command COMMAND',
            'Execute the specified string as console commands (use ; for multiples)'
        ) do |commands|
          options.console.commands += commands.split(/\s*;\s*/)
        end
      }
    end

    @option_parser
  end
end
