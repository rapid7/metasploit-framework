require 'set'
require 'json'
require 'open3'
module Msf
  class Plugin::VulnEnv < Msf::Plugin

    # =====================================================================
    # Runtime Abstraction Layer
    # =====================================================================

    class BaseRuntime
      def available?
        raise NotImplementedError, "#{self.class} must implement available?"
      end

      def name
        raise NotImplementedError, "#{self.class} must implement name"
      end

      def pull(image)
        raise NotImplementedError, "#{self.class} must implement pull"
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        raise NotImplementedError, "#{self.class} must implement run"
      end

      def inspect(container_id)
        raise NotImplementedError, "#{self.class} must implement inspect"
      end

      def stop(container_id)
        raise NotImplementedError, "#{self.class} must implement stop"
      end

      def start(container_id)
        raise NotImplementedError, "#{self.class} must implement start"
      end

      def remove(container_id)
        raise NotImplementedError, "#{self.class} must implement remove"
      end

      def exec(container_id, command)
        raise NotImplementedError, "#{self.class} must implement exec"
      end

      def list(filters: {})
        raise NotImplementedError, "#{self.class} must implement list"
      end
    end

    class DockerRuntime < BaseRuntime
      def available?
        _out, _err, status = Open3.capture3('docker', 'version')
        status.success?
      rescue Errno::ENOENT
        false
      end

      def name
        'docker'
      end

      def pull(image)
        _out, err, status = Open3.capture3('docker', 'pull', image)
        if status.success?
          true
        else
          elog("Docker pull failed: #{err}")
          false
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        cmd = ['docker', 'run', '-d']

        ports.each do |container_port, host_port|
          cmd += ['-p', "127.0.0.1:#{host_port}:#{container_port}"]
        end

        labels.each do |key, value|
          cmd += ['--label', "#{key}=#{value}"]
        end

        volumes.each do |host_path, container_path|
          cmd += ['-v', "#{host_path}:#{container_path}"]
        end

        env.each do |key, value|
          cmd += ['-e', "#{key}=#{value}"]
        end

        cmd += ['--name', name] if name
        cmd << image

        out, err, status = Open3.capture3(*cmd)
        if status.success?
          out.strip
        else
          raise "Docker run failed: #{err}"
        end
      end

      def inspect(container_id)
        out, _err, status = Open3.capture3('docker', 'inspect', container_id)
        return nil unless status.success?
        return nil if out.empty?

        begin
          data = JSON.parse(out)
          data.first
        rescue JSON::ParserError => e
          elog("Docker inspect JSON parse error: #{e.message}")
          nil
        end
      end

      def stop(container_id)
        _out, _err, status = Open3.capture3('docker', 'stop', container_id)
        status.success?
      end

      def start(container_id)
        _out, _err, status = Open3.capture3('docker', 'start', container_id)
        status.success?
      end

      def remove(container_id)
        _out, _err, status = Open3.capture3('docker', 'rm', container_id)
        status.success?
      end

      def exec(container_id, command)
        out, err, status = Open3.capture3('docker', 'exec', container_id, *command.split)
        [out + err, status.exitstatus]
      end

      def list(filters: {})
        cmd = ['docker', 'ps', '-a', '--format', '{{json .}}']

        filters.each do |key, value|
          cmd += ['--filter', "#{key}=#{value}"]
        end

        out, _err, status = Open3.capture3(*cmd)
        return [] unless status.success?
        return [] if out.empty?

        containers = out.lines.map do |line|
          begin
            JSON.parse(line.strip)
          rescue JSON::ParserError
            nil
          end
        end.compact

        # Docker returns Labels as comma-separated string, not Hash
        containers.each do |c|
          c['Labels'] = parse_labels(c['Labels']) if c['Labels'].is_a?(String)
        end

        containers
      end

      private

      def parse_labels(labels_string)
        return {} if labels_string.nil? || labels_string.empty?

        labels_string.split(',').each_with_object({}) do |pair, hash|
          key, value = pair.split('=', 2)
          hash[key] = value || ''
        end
      end
    end
    # =====================================================================
    # Port Allocator
    # =====================================================================
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
    # =====================================================================
    # Console Command Dispatcher
    # =====================================================================
       
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
    # =====================================================================
    # Plugin Lifecycle
    # =====================================================================
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
