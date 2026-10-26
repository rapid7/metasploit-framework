# Garak console integration. The execution helper is private to
# this plugin; loading it does not register auxiliary modules in the framework.
module Msf
  # Adds Garak scan and import commands to msfconsole.
  class Plugin::Garak < Msf::Plugin
    # Owns console commands and defaults for this plugin instance.
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      unless const_defined?(:RUNNERS, false)
        RUNNERS = {
          'scan' => :Runner
        }.freeze
      end
      unless const_defined?(:INHERITED_OPTIONS, false)
        # Reuse only connection/runtime controls that have the same meaning for
        # discovery and execution; provider-specific options remain explicit.
        INHERITED_OPTIONS = %w[RHOSTS RPORT SSL TARGETURI PYTHON RunTimeout VERBOSE].freeze
      end

      def name
        'Garak'
      end

      def commands
        {
          'garak_help' => 'Show Garak plugin usage',
          'garak_options' => 'Show scan and import options',
          'garak_set' => 'Set a plugin default: OPTION VALUE',
          'garak_unset' => 'Remove a plugin default: OPTION',
          'garak_scan' => 'Scan an AI model: OPTION=VALUE ...',
          'garak_import' => 'Import a JSONL report: REPORT_FILE=path ...',
          'garak_list_generators' => 'List locally installed Garak generators',
          'garak_list_probes' => 'List locally installed Garak probes'
        }
      end

      def cmd_garak_help(*_args)
        print_line('Load with: load garak')
        print_line('Use garak_options [scan] to inspect available options.')
        print_line('Set defaults with garak_set OPTION VALUE; override them per command with OPTION=VALUE.')
        print_line('Example: garak_scan RHOSTS= TARGET_TYPE=test.Blank TARGET_NAME=blank PROBES=probes.test.Blank VERBOSE=true')
        print_line('Discover models with auxiliary/scanner/garak/garak_ollama or garak_llama.')
        print_line('Example: garak_import REPORT_FILE=/path/to/report.jsonl DB_HOST=192.0.2.1')
        print_line('Garak runs locally and connects directly to models; Metasploit routing does not apply.')
        print_line('Provider credentials are inherited from the msfconsole environment.')
      end

      def cmd_garak_options(*args)
        mode = args.first || 'scan'
        raise ArgumentError, 'Usage: garak_options [scan]' unless args.length <= 1 && RUNNERS.key?(mode)

        runner = build_runner(mode)
        table = Msf::Serializer::ReadableText.dump_options(runner)
        table.gsub!('When ACTION is SCAN:', 'Options for garak_scan:')
        table.gsub!('When ACTION is IMPORT:', 'Options for garak_import:')
        table.gsub!('When ACTION is LIST_PROBES:', 'Options for garak_list_probes:')
        print_line(table)
        print_line(Msf::Serializer::ReadableText.dump_advanced_options(runner))
        settings.each { |key, value| print_line("Plugin default: #{key}=#{value}") }
      rescue ArgumentError => e
        print_error(e.message)
      end

      def cmd_garak_set(*args)
        raise ArgumentError, 'Usage: garak_set OPTION VALUE' unless args.length == 2

        key = option_name(args.first)
        raise ArgumentError, 'REST_API_KEY is only accepted per command; set REST_API_KEY_ENV for inherited credentials' if key == 'REST_API_KEY'

        settings[key] = args.last
        print_status("Garak option #{key} set")
      rescue ArgumentError => e
        print_error(e.message)
      end

      def cmd_garak_unset(*args)
        raise ArgumentError, 'Usage: garak_unset OPTION' unless args.length == 1

        settings.delete(option_name(args.first))
      rescue ArgumentError => e
        print_error(e.message)
      end

      def cmd_garak_scan(*args)
        execute('scan', 'SCAN', args)
      end

      def cmd_garak_import(*args)
        execute('scan', 'IMPORT', args)
      end

      def cmd_garak_list_generators(*args)
        execute('scan', 'LIST_GENERATORS', args)
      end

      def cmd_garak_list_probes(*args)
        execute('scan', 'LIST_PROBES', args)
      end

      private

      def settings
        @settings ||= {}
      end

      def option_name(value)
        options = RUNNERS.keys.flat_map { |mode| build_runner(mode).options.keys }.uniq
        key = options.find { |candidate| candidate.casecmp?(value) }
        raise ArgumentError, "Unknown Garak option #{value}; use garak_options" unless key && key != 'ACTION'

        key
      end

      def build_runner(mode)
        # Each runner gets its own class metadata and datastore. Framework
        # module instances resolve their framework through the owning class.
        klass = Msf::Plugin::Garak.const_get(RUNNERS.fetch(mode)).dup
        klass.framework = framework
        klass.refname = "garak/#{mode}"
        klass.file_path = __FILE__
        klass.orig_cls = klass
        runner = klass.new
        if active_module
          INHERITED_OPTIONS.each do |key|
            next unless active_module.options.key?(key)
            next if active_module.datastore[key].nil?

            runner.datastore[key] = active_module.datastore[key]
          end
        end
        settings.each { |key, value| runner.datastore[key] = value if runner.options.key?(key) }
        runner
      end

      def execute(mode, action, args)
        if args.include?('-h') || args.include?('--help')
          cmd_garak_help
          return
        end

        runner = build_runner(mode)
        overrides = args.to_h do |argument|
          key, value = argument.split('=', 2)
          raise ArgumentError, 'Expected OPTION=VALUE arguments; use garak_help' unless value

          key = option_name(key)
          raise ArgumentError, "Option #{key} is unavailable for #{mode}; use garak_options #{mode}" unless runner.options.key?(key)

          [key, value]
        end
        Msf::Simple::Auxiliary.run_simple(runner,
                                          'Action' => action,
                                          'Options' => overrides,
                                          'LocalInput' => driver.input,
                                          'LocalOutput' => driver.output,
                                          'RunAsJob' => false)
      rescue ArgumentError, Msf::OptionValidateError => e
        print_error("Garak command failed: #{e.message}")
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_status('Garak plugin loaded; use garak_help for usage')
    end

    def cleanup
      remove_console_dispatcher('Garak')
      super
    end

    def name
      'garak'
    end

    def desc
      'Scan AI models and import Garak reports'
    end
  end
end

require 'msf/core/auxiliary/garak'
require_relative 'garak/garak_integration'
