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
        options.console.histfile = nil
        options.console.logger = nil
        options.console.local_output = nil
        options.console.plugins = []
        options.console.quiet = false
        options.console.readline = true
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

        option_parser.separator 'Console options:'

        option_parser.on('-a', '--ask', "Ask before exiting Metasploit or accept 'exit -y'") do
          options.console.confirm_exit = true
        end

        option_parser.on('-H', '--history-file FILE', 'Save command history to the specified file') do |file|
          options.console.histfile = file
        end

        option_parser.on('-l', '--logger STRING', "Specify a logger to use (#{Rex::Logging::LogSinkFactory.available_sinks.join(', ')})") do |logger|
          options.console.logger = logger
        end

        option_parser.on('--[no-]readline') do |readline|
          options.console.readline = readline
        end

        option_parser.on('-L', '--real-readline', 'Use the system Readline library instead of RbReadline') do
          message = "The RealReadline option has been marked as deprecated, and is currently a noop.\n"
          message << "If you require this functionality, please use the following link to tell us:\n"
          message << '  https://github.com/rapid7/metasploit-framework/issues/19399'
          warn message
        end

        option_parser.on('-o', '--output FILE', 'Output to the specified file') do |file|
          options.console.local_output = file
        end

        option_parser.on('-p', '--plugin PLUGIN', 'Load a plugin on startup') do |plugin|
          options.console.plugins << plugin
        end

        option_parser.on('-q', '--quiet', 'Do not print the banner on startup') do
          options.console.quiet = true
        end

        option_parser.on('-r', '--resource FILE', 'Execute the specified resource file (- for stdin)') do |file|
          options.console.resources << file
        end

        option_parser.on(
            '-x',
            '--execute-command COMMAND',
            'Execute the specified console commands (use ; for multiples)'
        ) do |commands|
          options.console.commands += commands.split(/\s*;\s*/)
        end
      }
    end

    @option_parser
  end
end
