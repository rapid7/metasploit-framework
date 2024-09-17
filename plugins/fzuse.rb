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
  ###
  #
  # This class illustrates a fuzzy_use plugin.  Plugins can change the behavior of
  # the framework by adding new features, new user interface commands, or
  # through any other arbitrary means.  They are designed to have a very loose
  # definition in order to make them as useful as possible.
  #
  ###
  class Plugin::FuzzyUse < Msf::Plugin

    ###
    #
    # This class implements a fuzzy_use console command dispatcher.
    #
    ###
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def initialize(driver)
        super

        @module_dispatcher = Msf::Ui::Console::CommandDispatcher::Modules.new(driver)
      end

      #
      # The dispatcher's name.
      #
      def name
        'FuzzyUse'
      end

      #
      # Returns the hash of commands supported by this dispatcher.
      #
      def commands
        {
          'fzuse' => 'A fuzzy_use command added by the fuzzy_use plugin'
        }
      end

      def start_pipe_server(socket_path)
        def pipe_server(socket_path)
          server = UNIXServer.new(socket_path)
          File.chmod(0600, socket_path)
          loop do
            client = server.accept
            unless (input_string = client.gets&.chomp).blank?
              if (mod = framework.modules.create(input_string))
                client.puts(Serializer::ReadableText.dump_module(mod))
              end
            end
            client.close
          end
        rescue EOFError
        ensure
          server.close if server
          File.delete(socket_path) if File.exist?(socket_path)
        end

        Thread.new do
          pipe_server(socket_path)
        end
      end

      #
      # This method handles the fuzzy_use command.
      #
      def cmd_fzuse(*args)
        selection = nil

        Dir.mktmpdir('msf-fzuse-') do |dir|
          File.chmod(0700, dir)
          socket_path = File.join(dir, "msf-fzuse.sock")
          server_thread = start_pipe_server(socket_path)

          query = args.empty? ? '' : args.first
          ruby = RbConfig::CONFIG['bindir'] + '/' + RbConfig::CONFIG['ruby_install_name'] + RbConfig::CONFIG['EXEEXT']

          Open3.popen3('fzf', '--select-1', '--query', query, '--preview', "'#{ruby}' '#{__FILE__}' '#{socket_path}' '{1}'", '--preview-label', "Module Information") do |stdin, stdout, stderr, wait_thr|
            framework.modules.module_types.each do |module_type|
              framework.modules.module_names(module_type).each do |module_name|
                stdin.puts "#{module_type}/#{module_name}"
              end
            end
            stdin.close
            selection = stdout.read
          end

          server_thread.kill
        end

        return if selection.blank?

        selection.strip!
        @module_dispatcher.cmd_use(selection)
      end
    end

    #
    # The constructor is called when an instance of the plugin is created.  The
    # framework instance that the plugin is being associated with is passed in
    # the framework parameter.  Plugins should call the parent constructor when
    # inheriting from Msf::Plugin to ensure that the framework attribute on
    # their instance gets set.
    #
    def initialize(framework, opts)
      super

      missing_requirements = []
      missing_requirements << 'fzf' unless Msf::Util::Helper.which('fzf')

      unless missing_requirements.empty?
        print_error("The FuzzyUse plugin has loaded but the following requirements are missing: #{missing_requirements.join(', ')}")
        print_error("Please install the missing requirements, then reload the plugin by running: `unload fzuse` and `load fzuse`.")
        return
      end

      # If this plugin is being loaded in the context of a console application
      # that uses the framework's console user interface driver, register
      # console dispatcher commands.
      add_console_dispatcher(ConsoleCommandDispatcher)

      print_status('FuzzyUse plugin loaded.')
    end

    #
    # The cleanup routine for plugins gives them a chance to undo any actions
    # they may have done to the framework.  For instance, if a console
    # dispatcher was added, then it should be removed in the cleanup routine.
    #
    def cleanup
      # If we had previously registered a console dispatcher with the console,
      # deregister it now.
      remove_console_dispatcher('FuzzyUse')
    end

    #
    # This method returns a short, friendly name for the plugin.
    #
    def name
      'fuzzy_use'
    end

    #
    # This method returns a brief description of the plugin.  It should be no
    # more than 60 characters, but there are no hard limits.
    #
    def desc
      'Demonstrates using framework plugins'
    end

  end
end
