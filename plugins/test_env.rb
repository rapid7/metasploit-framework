require 'set'
require 'json'
require 'open3'
require 'shellwords'

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

      private

      def parse_labels(labels_string)
        return {} if labels_string.nil? || labels_string.empty?

        labels_string.split(',').each_with_object({}) do |pair, hash|
          key, value = pair.split('=', 2)
          hash[key] = value || ''
        end
      end
    end

    # ============================================================
    # DOCKER RUNTIME 
    # ============================================================
    class DockerRuntime < BaseRuntime
      VALID_IMAGE_NAME = /\A[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-zA-Z0-9._-]+)?\z/

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
        validate_image_name!(image)
        _out, err, status = Open3.capture3('docker', 'pull', image)
        if status.success?
          true
        else
          elog("Docker pull failed: #{err}")
          false
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
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
        out, err, status = Open3.capture3('docker', 'exec', container_id, *Shellwords.split(command))
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

        containers.each do |c|
          c['Labels'] = parse_labels(c['Labels']) if c['Labels'].is_a?(String)
        end

        containers
      end

      private

      def validate_image_name!(image)
        unless image.to_s.match?(VALID_IMAGE_NAME)
          raise ArgumentError, "Invalid image name: #{image.inspect}"
        end
      end
    end

    # ============================================================
    # PODMAN RUNTIME
    # ============================================================
    class PodmanRuntime < BaseRuntime
      def available?
        _out, _err, status = Open3.capture3('podman', 'version')
        status.success?
      rescue Errno::ENOENT
        false
      end

      def name
        'podman'
      end

      def pull(image)
        validate_image_name!(image)
        qualified = qualify_image(image)
        _out, err, status = Open3.capture3('podman', 'pull', qualified)
        if status.success?
          true
        else
          _out2, err2, status2 = Open3.capture3('podman', 'pull', image)
          if status2.success?
            true
          else
            elog("Podman pull failed: #{err}")
            false
          end
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
        cmd = ['podman', 'run', '-d']

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
        cmd << qualify_image(image)

        out, err, status = Open3.capture3(*cmd)
        if status.success?
          out.strip
        else
          raise "Podman run failed: #{err}"
        end
      end

      def inspect(container_id)
        out, _err, status = Open3.capture3('podman', 'inspect', container_id)
        return nil unless status.success?
        return nil if out.empty?

        begin
          data = JSON.parse(out)
          data.first
        rescue JSON::ParserError => e
          elog("Podman inspect JSON parse error: #{e.message}")
          nil
        end
      end

      def stop(container_id)
        _out, _err, status = Open3.capture3('podman', 'stop', container_id)
        status.success?
      end

      def start(container_id)
        _out, _err, status = Open3.capture3('podman', 'start', container_id)
        status.success?
      end

      def remove(container_id)
        _out, _err, status = Open3.capture3('podman', 'rm', container_id)
        status.success?
      end

      def exec(container_id, command)
        out, err, status = Open3.capture3('podman', 'exec', container_id, *Shellwords.split(command))
        [out + err, status.exitstatus]
      end

      def list(filters: {})
        cmd = ['podman', 'ps', '-a', '--format', '{{json .}}']

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

        containers.each do |c|
          c['Labels'] = parse_labels(c['Labels']) if c['Labels'].is_a?(String)
        end

        containers
      end

      private

      def qualify_image(image)
        return image if image.include?('/')
        "docker.io/library/#{image}"
      end
    end

    # ============================================================
    # RUNTIME ADAPTER 
    # ============================================================
    class RuntimeAdapter
      def self.detect(datastore = {})
        runtime_pref = normalize_pref(datastore['TEST_ENV_RUNTIME'] || ENV['TEST_ENV_RUNTIME'])

        case runtime_pref
        when 'docker'  then detect_docker
        when 'podman'  then detect_podman
        else                detect_auto
        end
      end

      def self.normalize_pref(raw)
        pref = raw.to_s.downcase.strip
        return pref if %w[auto docker podman].include?(pref)
        elog("Invalid TEST_ENV_RUNTIME: #{raw.inspect}, falling back to auto")
        'auto'
      end

      def self.detect_docker
        docker = DockerRuntime.new
        return docker if docker.available?
        raise "Docker requested but not available"
      end

      def self.detect_podman
        podman = PodmanRuntime.new
        return podman if podman.available?
        raise "Podman requested but not available"
      end

      def self.detect_auto
        docker = DockerRuntime.new
        return docker if docker.available?
        podman = PodmanRuntime.new
        return podman if podman.available?
        nil
      end
    end

    # =====================================================================
    # Port Allocator
    # =====================================================================
    class PortAllocator
      EPHEMERAL_START = 49152
      EPHEMERAL_END   = 65535

      class NoPortsAvailable < RuntimeError; end

      def initialize(used_ports = [])
        @used_ports = Set.new(used_ports)
      end

      def allocate(preferred = nil)
        if preferred && available?(preferred)
          @used_ports.add(preferred)
          return preferred
        end

        (EPHEMERAL_START..EPHEMERAL_END).each do |port|
          next if @used_ports.include?(port)
          if available?(port)
            @used_ports.add(port)
            return port
          end
        end

        raise NoPortsAvailable, "No available ports in range #{EPHEMERAL_START}-#{EPHEMERAL_END}"
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

      # Class-level storage for runtime reference
      @@runtime = nil

      def self.runtime=(runtime)
        @@runtime = runtime
      end

      def self.runtime
        @@runtime
      end

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
        when 'status'
          cmd_test_env_status(args)
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
        print_line("  status     Show runtime status")
        print_line("  help       Show this help")
        print_line
      end

      def cmd_test_env_status(args)
        runtime = self.class.runtime
        
        if runtime
          print_status("Runtime: #{runtime.name}")
          print_status("Available: #{runtime.available?}")
          
          begin
            containers = runtime.list
            print_status("Container engine responsive: yes")
            print_status("Active containers: #{containers.length}")
          rescue => e
            print_error("Container engine check failed: #{e.message}")
          end
        else
          print_error("No container runtime configured.")
          print_error("Install Docker or Podman, or set TEST_ENV_RUNTIME.")
        end
      end

      def cmd_test_env_tabs(str, words)
        if words.length == 1
          return %w[build list stop start remove remove-all exec status help]
        end
        []
      end
    end

    # =====================================================================
    # Plugin Lifecycle
    # =====================================================================
    def initialize(framework, opts)
      super
      @runtime = RuntimeAdapter.detect
      ConsoleCommandDispatcher.runtime = @runtime
      if @runtime
        print_status("VulnEnv plugin loaded. Runtime: #{@runtime.name}")
      else
        print_error("VulnEnv plugin loaded, but no container runtime found.")
        print_error("Install Docker or Podman to use test_env.")
      end
      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('VulnEnv')
      ConsoleCommandDispatcher.runtime = nil
    end

    def name
      'vulnenv'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end