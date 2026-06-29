module Msf
  class Plugin::VulnEnv < Msf::Plugin

    class PortAllocator
      EPHEMERAL_START = 49152
      EPHEMERAL_END   = 65535

      def initialize(used_ports = [])
        @used_ports = Set.new(used_ports)
      end

      def allocate(preferred = nil)
        # 1. Try user-requested port first
        if preferred && available?(preferred)
          @used_ports.add(preferred)
          return preferred
        end

        # 2. Fall back to ephemeral range
        (EPHEMERAL_START..EPHEMERAL_END).each do |port|
          next if @used_ports.include?(port)
          if available?(port)
            @used_ports.add(port)
            return port
          end
        end

        raise "No available ports in range #{EPHEMERAL_START}-#{EPHEMERAL_END}"
      end

      def release(port)
        @used_ports.delete(port)
      end

      private

      def available?(port)
        return false if @used_ports.include?(port)

        server = TCPServer.new('127.0.0.1', port)
        server.close
        true
      rescue Errno::EADDRINUSE
        false
      end
    end
       
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'VulnEnv'
      end

      def commands
        {
          'test_env' => 'Manage vulnerable test environments'
        }
      end

      def cmd_test_env(*args)
        if args.empty? || args.first == '-h' || args.first == '--help'
          cmd_test_env_help
          return
        end

        subcommand = args.shift

        case subcommand
        when 'build'
          print_status("TODO: test_env build")
        when 'list'
          print_status("TODO: test_env list")
        when 'stop'
          print_status("TODO: test_env stop")
        when 'start'
          print_status("TODO: test_env start")
        when 'remove'
          print_status("TODO: test_env remove")
        when 'remove-all'
          print_status("TODO: test_env remove-all")
        when 'exec'
          print_status("TODO: test_env exec")
        when 'help'
          cmd_test_env_help
        else
          print_error("Unknown subcommand: #{subcommand}")
          cmd_test_env_help
        end
      end

      def cmd_test_env_help
        print_line("Usage: test_env <command>")
        print_line
        print_line("Commands:")
        print_line("  build      Build and launch environment for active module")
        print_line("  list       List tracked environments")
        print_line("  stop <ID>  Stop a running environment")
        print_line("  start <ID> Restart a stopped environment")
        print_line("  remove <ID> Tear down an environment")
        print_line("  remove-all Tear down all environments")
        print_line("  exec <ID>  Execute exploit against environment")
        print_line("  help       Show this help")
        print_line
      end

      def cmd_test_env_tabs(str, words)
        if words.length == 1
          return %w[build list stop start remove remove-all exec help]
        end
        []
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_status("VulnEnv plugin loaded.")
    end

    def cleanup
      remove_console_dispatcher('VulnEnv')
    end

    def name
      'vulnenv'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end
