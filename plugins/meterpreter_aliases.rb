require 'rex/post/meterpreter/ui/console/meterpreter_alias_configuration'
require 'rex/post/meterpreter/ui/console/meterpreter_alias_dispatcher'

module Msf
  # Loads declarative YAML aliases into Meterpreter consoles.
  class Plugin::MeterpreterAliases < Msf::Plugin
    include Msf::SessionEvent

    # Manages Meterpreter aliases from the framework console.
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      class << self
        attr_accessor :plugin
      end

      def initialize(driver)
        super
        @plugin = self.class.plugin
      end

      def name
        'Meterpreter Aliases'
      end

      def commands
        {
          'meterpreter_aliases' => 'List configured Meterpreter YAML aliases',
          'meterpreter_aliases_reload' => 'Reload Meterpreter YAML aliases'
        }
      end

      def cmd_meterpreter_aliases(*args)
        return cmd_meterpreter_aliases_help if args == ['-h']

        if args.any?
          print_error('Usage: meterpreter_aliases')
          return false
        end

        @plugin.print_configuration
        true
      end

      def cmd_meterpreter_aliases_help
        print_line('Usage: meterpreter_aliases')
        print_line
        print_line('Lists the active Meterpreter alias YAML file and configured aliases.')
        true
      end

      def cmd_meterpreter_aliases_reload(*args)
        return cmd_meterpreter_aliases_reload_help if args == ['-h']

        if args.any?
          print_error('Usage: meterpreter_aliases_reload')
          return false
        end

        @plugin.reload_configuration
      end

      def cmd_meterpreter_aliases_reload_help
        print_line('Usage: meterpreter_aliases_reload')
        print_line
        print_line('Reloads and validates the active Meterpreter alias YAML file.')
        true
      end
    end

    def initialize(framework, opts)
      super
      @configuration_path = opts['Config'] || ::File.join(Msf::Config.data_directory, 'meterpreter_aliases.yml')
      @dispatchers = {}.compare_by_identity
      @configuration = load_configuration
      meterpreter_sessions.each { |session| validate_session_commands!(@configuration, session) }

      ConsoleCommandDispatcher.plugin = self
      add_console_dispatcher(ConsoleCommandDispatcher)
      framework.events.add_session_subscriber(self)
      meterpreter_sessions.each { |session| attach_session(session) }
      print_status("Loaded #{@configuration['aliases'].length} Meterpreter aliases from #{@configuration['path']}")
    end

    def cleanup
      framework.events.remove_session_subscriber(self)
      @dispatchers.each_key { |session_key| detach_session(session_key) }
      remove_console_dispatcher('Meterpreter Aliases')
      ConsoleCommandDispatcher.plugin = nil if ConsoleCommandDispatcher.plugin == self
    end

    def name
      'meterpreter_aliases'
    end

    def desc
      'Loads Meterpreter commands from a YAML alias file'
    end

    def on_session_open(session)
      return unless meterpreter_session?(session)

      validate_session_commands!(@configuration, session)
      attach_session(session)
    rescue Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration::Error => e
      print_error(e.message)
    end

    def on_session_close(session, _reason = '')
      detach_session(session)
    end

    def on_session_fail(_reason = ''); end
    def on_plugin_load; end
    def on_plugin_unload; end

    def reload_configuration
      replacement = load_configuration
      meterpreter_sessions.each { |session| validate_session_commands!(replacement, session) }

      @configuration = replacement
      @dispatchers.each_key { |session_key| detach_session(session_key) }
      meterpreter_sessions.each { |session| attach_session(session) }
      print_status("Reloaded #{@configuration['aliases'].length} Meterpreter aliases from #{@configuration['path']}")
      true
    rescue Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration::Error => e
      print_error("Meterpreter aliases were not reloaded: #{e.message}")
      false
    end

    def print_configuration
      print_status("Meterpreter alias configuration: #{@configuration['path']}")
      @configuration['aliases'].sort.each do |alias_name, definition|
        print_line("#{alias_name} - #{definition['description']}")
      end
    end

    private

    def load_configuration
      validator = lambda do |module_name|
        mod = framework.modules.create(module_name)
        mod && (mod.type == 'post' || (mod.type == 'exploit' && mod.exploit_type == 'local'))
      end
      Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration.load(
        path: @configuration_path,
        module_validator: validator
      )
    end

    def meterpreter_sessions
      framework.sessions.each_pair.filter_map do |_session_id, session|
        session if meterpreter_session?(session)
      end
    end

    def meterpreter_session?(session)
      session.type == 'meterpreter' && session.respond_to?(:console) && session.console
    end

    def validate_session_commands!(configuration, session)
      configured = configuration['aliases'].keys
      dispatchers = session.console.dispatcher_stack.reject do |dispatcher|
        dispatcher.is_a?(Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasDispatcher)
      end
      existing = dispatchers.flat_map { |dispatcher| dispatcher.commands&.keys || [] }
      collision = (configured & existing).first
      return unless collision

      raise Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration::Error,
            "Alias '#{collision}' conflicts with an existing command in session #{session.sid}"
    end

    def attach_session(session)
      return if @dispatchers.key?(session)

      dispatcher = Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasDispatcher.new(
        session.console,
        registry: @configuration,
        reload_callback: method(:reload_configuration)
      )
      session.console.dispatcher_stack.unshift(dispatcher)
      @dispatchers[session] = dispatcher
    end

    def detach_session(session)
      dispatcher = @dispatchers.delete(session)
      session.console.dispatcher_stack.delete(dispatcher) if dispatcher
    end
  end
end
