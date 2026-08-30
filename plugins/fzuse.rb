require 'socket'

# this is the main routine that's executed in the grandchild process (msfconsole -> fzf -> this)
if $PROGRAM_NAME == __FILE__
  exit 64 unless ARGV.length == 2

  UNIXSocket.open(ARGV[0]) do |sock|
    sock.write ARGV[1] + "\n"
    sock.flush

    puts sock.read
  end
  exit 0
end

module Msf
  class Plugin::FuzzyUse < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      FZF_THEME = {
        'fg' => '-1',
        'fg+' => 'white:regular:bold',
        'bg' => '-1',
        'bg+' => '-1',
        'hl' => '-1',
        'hl+' => 'red:regular:bold',
        'info' => '-1',
        'marker' => '-1',
        'prompt' => '-1',
        'spinner' => '-1',
        'pointer' => 'blue:bold',
        'header' => '-1',
        'border' => '-1',
        'label' => '-1',
        'query' => '-1'
      }.freeze

      def initialize(driver)
        super

        @module_dispatcher = Msf::Ui::Console::CommandDispatcher::Modules.new(driver)
      end

      def name
        'FuzzyUse'
      end

      #
      # Returns the hash of commands supported by this dispatcher.
      #
      def commands
        {
          'fzuse' => 'A fuzzy use command added by the FuzzyUse plugin'
        }
      end

      def pipe_server(socket_path)
        server = UNIXServer.new(socket_path)
        File.chmod(0600, socket_path)
        loop do
          client = server.accept
          begin
            unless (input_string = client.gets&.chomp).blank?
              if (mod = framework.modules.create(input_string))
                client.puts(Serializer::ReadableText.dump_module(mod))
              end
            end
          rescue StandardError
          end
          client.close
        end
      rescue EOFError
      ensure
        server.close if server
        File.delete(socket_path) if File.exist?(socket_path)
      end

      #
      # This method handles the fzuse command.
      #
      def cmd_fzuse(*args)
        selection = nil

        Dir.mktmpdir('msf-fzuse-') do |dir|
          socket_path = File.join(dir, "msf-fzuse.sock")
          server_thread = Thread.new { pipe_server(socket_path) }

          query = args.empty? ? '' : args.first
          ruby = RbConfig::CONFIG['bindir'] + '/' + RbConfig::CONFIG['ruby_install_name'] + RbConfig::CONFIG['EXEEXT']

          color = "--color=#{FZF_THEME.map { |key, value| "#{key}:#{value}" }.join(',')}"
          Open3.popen3('fzf', '--select-1', '--query', query, '--pointer=->', color, '--preview', "'#{ruby}' '#{__FILE__}' '#{socket_path}' '{1}'", '--preview-label', "Module Information") do |stdin, stdout, stderr, wait_thr|
            framework.modules.module_types.each do |module_type|
              framework.modules.module_names(module_type).each do |module_name|
                stdin.puts "#{module_type}/#{module_name}"
              end
            end
            stdin.close
            selection = stdout.read
          end

          server_thread.kill
          server_thread.join
        end

        return if selection.blank?

        selection.strip!
        @module_dispatcher.cmd_use(selection)
      end
    end

    def initialize(framework, opts)
      super

      unless defined?(UNIXSocket)
        # This isn't a requirement that can be fixed by installing something
        print_error("The FuzzyUse plugin has loaded but the Ruby environment does not support UNIX sockets.")
        return
      end

      missing_requirements = []
      missing_requirements << 'fzf' unless Msf::Util::Helper.which('fzf')

      unless missing_requirements.empty?
        print_error("The FuzzyUse plugin has loaded but the following requirements are missing: #{missing_requirements.join(', ')}")
        print_error("Please install the missing requirements, then reload the plugin by running: `unload fzuse` and `load fzuse`.")
        return
      end

      add_console_dispatcher(ConsoleCommandDispatcher)

      print_status('FuzzyUse plugin loaded.')
    end

    def cleanup
      remove_console_dispatcher('FuzzyUse')
    end

    def name
      'fuzzy_use'
    end

    def desc
      'A plugin offering a fuzzy use command'
    end

  end
end
