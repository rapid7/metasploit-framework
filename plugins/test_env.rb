require 'active_model'
require 'psych'
require 'set'
require 'json'
require 'yaml'
require 'open3'
require 'shellwords'
require 'tmpdir'
require 'socket'
require 'fileutils'
require 'timeout'   
require 'net/http'
require 'rex/text/table'

module Msf
  class Plugin::TestEnv < Msf::Plugin
    # =====================================================================
    # VulnerableEnvironment Struct
    # =====================================================================

    # Encapsulates and validates VulnerableEnvironment metadata from a module.
    # Mirrors the framework pattern used by #name, #description, #notes, etc.
    # but adds validation and returns a typed object instead of a raw Hash.
    class VulnerableEnvironment
      attr_reader :definition, :default_variant, :profile, :port_mapping, :overrides

      # Required keys that must be present
      REQUIRED_KEYS = %w[definition default_variant port_mapping].freeze unless defined?(REQUIRED_KEYS)

      # Valid types for each key
      SCHEMA = {
        'definition'      => String,
        'default_variant' => String,
        'profile'         => String,
        'port_mapping'    => Hash,
        'overrides'       => Hash
      }.freeze unless defined?(SCHEMA)

      def initialize(raw_hash)
        @raw = raw_hash || {}

        validate!

        @definition      = @raw['definition']
        @default_variant = @raw['default_variant']
        @profile         = @raw['profile'] || 'default'
        @port_mapping    = @raw['port_mapping'] || {}
        @overrides       = @raw['overrides'] || {}
      end

      def valid?
        errors.empty?
      end

      def errors
        errs = []

        REQUIRED_KEYS.each do |key|
          errs << "Missing required key: '#{key}'" unless @raw.key?(key)
        end

        SCHEMA.each do |key, expected_type|
          next unless @raw.key?(key)
          unless @raw[key].is_a?(expected_type)
            errs << "Key '#{key}' must be #{expected_type}, got #{@raw[key].class}"
          end
        end

        if @raw['port_mapping'].is_a?(Hash)
          @raw['port_mapping'].each do |k, v|
            unless k.is_a?(Integer) || k.to_s.match?(/\A\d+\z/)
              errs << "port_mapping key must be an integer port, got: #{k.inspect}"
            end
            unless v.is_a?(String)
              errs << "port_mapping value must be a String datastore option name, got: #{v.inspect}"
            end
          end
        end

        errs
      end

      private

      def validate!
        errs = errors
        raise ArgumentError, "Invalid VulnerableEnvironment: #{errs.join('; ')}" unless errs.empty?
      end
    end

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

      # =====================================================================
      # Label Helpers (Shared Across Runtimes)
      # =====================================================================

      # Build container labels from environment metadata.
      # Stores only minimal dynamic data; static metadata is reconstructible
      # from the module's VulnerableEnvironment definition.
      def build_labels(instance_id:, module_fullname:, env_id:, version:, ports:)
        {
          'msf.vulnenv.managed_by' => 'test_env',
          'msf.vulnenv.instance_id' => instance_id,
          'msf.vulnenv.module' => module_fullname,
          'msf.vulnenv.env_id' => env_id.to_s,
          'msf.vulnenv.version' => version.to_s,
          'msf.vulnenv.ports' => encode_port_label(ports)
        }
      end

      # Encode port mapping hash {container_port => host_port} into label string
      # Format: "host:container,host:container" (e.g., "8081:8080,9090:61616")
      def encode_port_label(ports)
        ports.map { |container_port, host_port| "#{host_port}:#{container_port}" }.join(',')
      end

      # Decode port label string back into {container_port => host_port} hash
      def decode_port_label(label_value)
        return {} unless label_value

        label_value.split(',').each_with_object({}) do |pair, hash|
          host_port, container_port = pair.split(':')
          hash[container_port.to_i] = host_port.to_i
        end
      end

      # reject only dangerous shell characters
      VALID_IMAGE_NAME = /\A[^\s;|&`$(){}]+\z/ unless defined?(VALID_IMAGE_NAME)
      
      private

      def validate_image_name!(image)
        unless image.to_s.match?(VALID_IMAGE_NAME)
          raise ArgumentError, "Invalid image name: #{image.inspect}"
        end
      end

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

        # ports: {container_port => host_port}
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
        return ["", 1] if command.nil? || command.empty?
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

      def verify_rootless
        # Verify Podman mode and networking backend.
        # Returns [ok, message] — ok is true if viable, message describes status.
        out, _, st = Open3.capture3('podman', 'info', '--format', '{{.Host.Security.Rootless}}')
        rootless = st.success? && out.strip.downcase == 'true'

        unless rootless
          return [true, 'Podman running in rootful mode.']
        end

        # Rootless: check for pasta (preferred) or slirp4netns (fallback) using Ruby's PATH search
        if executable_in_path?('pasta')
          [true, 'Rootless Podman verified — pasta networking available.']
        elsif executable_in_path?('slirp4netns')
          [true, 'Rootless Podman verified — slirp4netns networking available.']
        else
          [false, 'Rootless Podman detected but no networking backend (pasta or slirp4netns) found. ' \
                  'Port forwarding may fail. Install pasta or slirp4netns.']
        end
      end

      def pull(image)
        validate_image_name!(image)
        qualified = qualify_image(image)
        _out, err, status = Open3.capture3('podman', 'pull', qualified)
        if status.success?
          true
        else
          elog("Podman pull failed for #{qualified}: #{err}")
          false
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
        cmd = ['podman', 'run', '-d']

        # ports: {container_port => host_port}
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
        return ["", 1] if command.nil? || command.empty?
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

      def executable_in_path?(cmd)
        return false if ENV['PATH'].nil?
        ENV['PATH'].split(File::PATH_SEPARATOR).any? do |dir|
          File.executable?(File.join(dir, cmd))
        end
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
        return 'auto' if pref.empty?  # Unset env var is not an error
        return pref if %w[auto docker podman].include?(pref)
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
    # Allocates free host ports for container bindings.
    # Checks both the current registry AND actively bound Docker/Podman ports
    # to avoid collisions with orphaned containers from previous sessions.
    class PortAllocator
      EPHEMERAL_START = 49152 unless defined?(EPHEMERAL_START)
      EPHEMERAL_END   = 65535 unless defined?(EPHEMERAL_END)

      class NoPortsAvailable < RuntimeError; end

      # runtime: the runtime adapter (DockerRuntime or PodmanRuntime) used to
      # query already-bound ports from previous sessions.
      def initialize(runtime = nil, used_ports = [])
        @runtime = runtime
        @used_ports = Set.new(used_ports)

        # Seed the set with ports already bound by Docker/Podman containers.
        # This prevents collisions with orphaned containers from previous
        # msfconsole sessions whose registry state is lost.
        scan_runtime_ports if @runtime
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

      # Query the container runtime for ports already bound on the host.
      # This catches orphaned containers from previous sessions.
      def scan_runtime_ports
        return unless @runtime

        begin
          containers = @runtime.list
          containers.each do |c|
            next unless c['Ports'].is_a?(String)

            # Docker ps output format: "127.0.0.1:49153->8161/tcp, 127.0.0.1:49154->80/tcp"
            # Extract host ports from the binding string.
            c['Ports'].scan(/:(\d+)->\d+\//).each do |match|
              port = match[0].to_i
              @used_ports.add(port) if port.between?(EPHEMERAL_START, EPHEMERAL_END)
            end
          end
        rescue => e
          # If the runtime query fails, fall back to TCPServer-only checking
          # This is a graceful degradation, not a fatal error
          elog("PortAllocator: failed to scan runtime ports: #{e.message}")
        end
      end

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
    # VulnTarget — ActiveModel-based environment instance
    # =====================================================================
    class VulnTarget
      include ActiveModel::Model
      include ActiveModel::Validations

      attr_accessor :local_id, :container_id, :module_fullname, :env_version,
                    :runtime, :image_ref, :status, :datastore, :allocated_ports,
                    :created_at, :started_at, :stopped_at, :removed_at, :temp_dirs
                    
      validates :container_id, presence: true
      validates :module_fullname, presence: true
      validates :local_id, presence: true, numericality: { only_integer: true }

      def initialize(attrs = {})
        @datastore = {}
        @allocated_ports = {}
        @temp_dirs = []
        @status = 'running'
        super
      end

      def running?
        status.to_s == 'running'
      end

      def stopped?
        status.to_s == 'stopped'
      end

      def removed?
        status.to_s == 'removed'
      end

      def rhost
        datastore['RHOSTS'] || datastore['RHOST']
      end

      def rport
        datastore['RPORT']
      end

      def all_host_ports
        allocated_ports.values
      end

      def exploit_command
        opts = datastore.map { |k, v| "#{k}=#{v}" }.join(' ')
        "exploit #{opts}"
      end

      def mark_running
        self.status = 'running'
        self.started_at = Time.now
      end

      def mark_stopped
        self.status = 'stopped'
        self.stopped_at = Time.now
      end

      def mark_removed
        self.status = 'removed'
        self.removed_at = Time.now
      end

      def to_h
        {
          'local_id' => local_id,
          'container_id' => container_id,
          'module_fullname' => module_fullname,
          'env_version' => env_version,
          'runtime' => runtime,
          'image_ref' => image_ref,
          'status' => status,
          'datastore' => datastore,
          'allocated_ports' => allocated_ports,
          'temp_dirs' => temp_dirs,
          'created_at' => created_at&.iso8601,
          'started_at' => started_at&.iso8601,
          'stopped_at' => stopped_at&.iso8601,
          'removed_at' => removed_at&.iso8601
        }
      end

      def self.from_h(hash)
        new(
          local_id: hash['local_id'],
          container_id: hash['container_id'],
          module_fullname: hash['module_fullname'],
          env_version: hash['env_version'],
          runtime: hash['runtime'],
          image_ref: hash['image_ref'],
          status: hash['status'] || 'running',
          datastore: hash['datastore'] || {},
          allocated_ports: hash['allocated_ports'] || {},
          temp_dirs: hash['temp_dirs'] || [],
          created_at: parse_time(hash['created_at']),
          started_at: parse_time(hash['started_at']),
          stopped_at: parse_time(hash['stopped_at']),
          removed_at: parse_time(hash['removed_at'])
        )
      end

      private

      def self.parse_time(val)
        return nil if val.nil?
        Time.parse(val)
      rescue
        nil
      end
    end

    # =====================================================================
    # VulnEnvironment — ActiveModel collection of targets
    # =====================================================================
    class VulnEnvironment
      include ActiveModel::Validations

      DEFAULT_VERSION = '1.0.0' unless defined?(DEFAULT_VERSION)

      attr_accessor :version, :instance_id

      validate :valid_targets

      def initialize(version: DEFAULT_VERSION, instance_id: nil, targets: [])
        raise ArgumentError, "targets must be an Array" unless targets.is_a?(Array)

        @version = version.freeze
        @instance_id = instance_id
        @targets = targets
        @mutex = Mutex.new
      end

      def add_target(target)
        @targets << target
      end

      def remove_target(local_id)
        @targets.reject! { |t| t.local_id == local_id }
      end

      def targets
        @targets.dup.freeze
      end

      def running_targets
        @targets.select(&:running?)
      end

      def find_by_id(local_id)
        @targets.find { |t| t.local_id == local_id }
      end

      def find_by_container(container_id)
        @targets.find { |t| t.container_id == container_id }
      end

      def used_ports
        @targets.flat_map(&:all_host_ports).compact
      end

      def next_id
        @mutex.synchronize do
          max_id = @targets.map(&:local_id).max || 0
          max_id + 1
        end
      end

      def to_h
        {
          'version' => version,
          'instance_id' => instance_id,
          'targets' => @targets.map(&:to_h)
        }
      end

      def self.from_h(hash)
        raw_targets = hash['targets']
        raise ArgumentError, "targets must be an Array" unless raw_targets.nil? || raw_targets.is_a?(Array)

        new(
          version: hash['version'] || DEFAULT_VERSION,
          instance_id: hash['instance_id'],
          targets: Array(raw_targets).map { |t| VulnTarget.from_h(t) }
        )
      end

      private

      def valid_targets
        @targets.each do |target|
          next if target.valid?

          target.errors.each do |error|
            errors.add(:target, error.full_message)
          end
        end
      end
    end

    # =====================================================================
    # VulnEnvironmentStore — YAML persistence in ~/.msf4/
    # =====================================================================
    class VulnEnvironmentStore
      DEFAULT_PATH = File.join(Dir.home, '.msf4', 'test_env_registry.yml') unless defined?(DEFAULT_PATH)

      def initialize(path = DEFAULT_PATH)
        @path = path
      end

      def load
        return VulnEnvironment.new(instance_id: current_instance_id) unless File.exist?(@path)

        File.open(@path, 'r') do |f|
          f.flock(File::LOCK_SH)
          yaml_content = f.read
          hash = Psych.safe_load(yaml_content, permitted_classes: [Symbol, Time, Date])
          VulnEnvironment.from_h(hash)
        end
      rescue Psych::DisallowedClass => e
        elog("VulnEnvironmentStore: Disallowed class in YAML: #{e.message}")
        VulnEnvironment.new(instance_id: current_instance_id)
      rescue => e
        elog("VulnEnvironmentStore: Failed to load: #{e.message}")
        VulnEnvironment.new(instance_id: current_instance_id)
      end

      def save(environment)
        FileUtils.mkdir_p(File.dirname(@path))
        File.open(@path, File::RDWR|File::CREAT, 0644) do |f|
          f.flock(File::LOCK_EX)
          f.rewind
          f.write(environment.to_h.to_yaml)
          f.flush
          f.truncate(f.pos)
        end
      rescue => e
        elog("VulnEnvironmentStore: Failed to save: #{e.message}")
      end

      private

      def current_instance_id
        "msf-#{Socket.gethostname}-#{Process.pid}"
      end
    end
    
    # =====================================================================
    # BuiltEnvironmentRegistry — YAML-backed registry
    # =====================================================================
    class BuiltEnvironmentRegistry
      attr_reader :framework

      def initialize(framework)
        @framework = framework
        @store = VulnEnvironmentStore.new
        @vuln_env = @store.load
        @instance_id = "msf-#{Socket.gethostname}-#{Process.pid}"
        @mutex = Mutex.new

        
      end

      # Docker run returns full 64-char IDs, but docker ps returns short 12-char IDs.
      # Normalize to short form so registry lookups and runtime queries are consistent.
      def normalize_container_id(id)
        id.to_s[0, 12]
      end

      def register(container_id:, module_fullname:, env_version: nil,
                   runtime:, image_ref:, datastore: {}, allocated_ports: {}, temp_dirs: [])
        @mutex.synchronize do
          id = @vuln_env.next_id

          target = VulnTarget.new(
            local_id: id,
            container_id: normalize_container_id(container_id),
            module_fullname: module_fullname,
            env_version: env_version,
            runtime: runtime,
            image_ref: image_ref,
            datastore: datastore,
            allocated_ports: allocated_ports,
            temp_dirs: temp_dirs,
            created_at: Time.now,
            started_at: Time.now
          )

          @vuln_env.add_target(target)
          @store.save(@vuln_env)
          id
        end
      end

      def register_with_id(env_id:, container_id:, module_fullname:, env_version: nil,
                           runtime:, image_ref:, datastore: {}, allocated_ports: {}, temp_dirs: [])
        @mutex.synchronize do
          target = VulnTarget.new(
            local_id: env_id,
            container_id: normalize_container_id(container_id),
            module_fullname: module_fullname,
            env_version: env_version,
            runtime: runtime,
            image_ref: image_ref,
            datastore: datastore,
            allocated_ports: allocated_ports,
            temp_dirs: temp_dirs,
            created_at: Time.now,
            started_at: Time.now
          )

          @vuln_env.add_target(target)
          @store.save(@vuln_env)
          env_id
        end
      end

      def reserve_id
        @mutex.synchronize do
          @vuln_env = @store.load  # See other sessions' IDs
          @vuln_env.next_id
        end
      end

      def get(id)
        @vuln_env = @store.load
        @vuln_env.find_by_id(id)
      end

      def list
        @vuln_env = @store.load
        @vuln_env.targets.sort_by(&:local_id)
      end

      def update_status(id, status)
        target = @vuln_env.find_by_id(id)
        return unless target

        case status.to_sym
        when :running then target.mark_running
        when :stopped then target.mark_stopped
        when :removed then target.mark_removed
        end

        @store.save(@vuln_env)
      end

      def remove(id)
        target = @vuln_env.find_by_id(id)
        return unless target

        target.temp_dirs.each do |dir|
          FileUtils.rm_rf(dir) if Dir.exist?(dir)
        end

        @vuln_env.remove_target(id)
        @store.save(@vuln_env)
      end

      def remove_all
        # Clean up temp directories for all tracked targets
        @vuln_env.targets.each do |target|
          target.temp_dirs.each do |dir|
            FileUtils.rm_rf(dir) if Dir.exist?(dir)
          end
        end

        # Hard reset: fresh empty environment state → next_id will return 1
        @vuln_env = VulnEnvironment.new(instance_id: @instance_id)
        @store.save(@vuln_env)
      end

      def prune(runtime)
        return unless runtime

        # PRUNE: remove registry entries for containers that no longer exist
        alive_ids = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' }).map { |c| normalize_container_id(c['ID'] || c['Id']) }
        @vuln_env = @store.load
        @vuln_env.targets.each do |target|
          unless alive_ids.include?(target.container_id)
            @vuln_env.remove_target(target.local_id)
          end
        end
        @store.save(@vuln_env)
      end

      def reconstruct_state(runtime)
        return unless runtime

        prune(runtime)

        # RECONSTRUCT: add containers found by labels but missing from registry
        containers = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' })
        elog("reconstruct_state: found #{containers.length} managed container(s)")

        containers.each do |container|
          labels = container.dig('Config', 'Labels') || container['Labels'] || {}
          if labels.is_a?(String)
            labels = labels.split(',').each_with_object({}) do |pair, hash|
              key, value = pair.split('=', 2)
              hash[key] = value || ''
            end
          end
          container_id = normalize_container_id(container['ID'] || container['Id'])

          # Identify by container_id, NOT by env_id label (labels are immutable
          # and become stale after ID compaction)
          if @vuln_env.find_by_container(container_id)
            elog("reconstruct_state: skip #{container_id} — already in registry")
            next
          end

          module_fullname = labels['msf.vulnenv.module']
          version = labels['msf.vulnenv.version']
          ports = decode_port_label(labels['msf.vulnenv.ports'])

          unless module_fullname && !module_fullname.empty?
            elog("reconstruct_state: skip #{container_id} — missing msf.vulnenv.module label")
            next
          end

          mod = @framework.modules.create(module_fullname) rescue nil
          unless mod
            elog("reconstruct_state: skip #{container_id} — could not load module '#{module_fullname}'")
            next
          end

          vuln_env_meta = mod.send(:module_info)['VulnerableEnvironment'] rescue nil
          unless vuln_env_meta
            elog("reconstruct_state: skip #{container_id} — module has no VulnerableEnvironment")
            next
          end

          definition_name = vuln_env_meta['definition']
          profile = vuln_env_meta['profile'] || 'default'
          overrides = vuln_env_meta['overrides'] || {}

          loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
          begin
            config = loader.resolve(definition_name, version, profile, overrides)
          rescue => e
            elog("reconstruct_state: skip #{container_id} — resolve failed for #{definition_name}/#{version}: #{e.message}")
            next
          end

          datastore = { 'RHOSTS' => '127.0.0.1' }
          (vuln_env_meta['port_mapping'] || {}).each do |container_port, ds_option|
            host = ports[container_port.to_i] || ports[container_port.to_s.to_i]
            datastore[ds_option] = host if host
          end

          if config['datastore_defaults']
            config['datastore_defaults'].each do |key, value|
              datastore[key] = value unless datastore.key?(key)
            end
          end

          # Merge default credentials the same way build does
          if config['credentials'] && config['credentials']['default']
            config['credentials']['default'].each do |key, value|
              ds_key = key.to_s.upcase
              datastore[ds_key] = value unless datastore.key?(ds_key)
            end
          end

          created_time = Time.parse(container['Created']) rescue Time.now
          started_time = Time.parse(container.dig('State', 'StartedAt') || container['StartedAt']) rescue Time.now

          preferred_id = labels['msf.vulnenv.env_id'].to_i
          assigned_id = if preferred_id > 0 && @vuln_env.find_by_id(preferred_id).nil?
                          preferred_id
                        else
                          @vuln_env.next_id
                        end
          target = VulnTarget.new(
            local_id: assigned_id,
            container_id: container_id,
            module_fullname: module_fullname,
            env_version: version,
            runtime: runtime.name,
            image_ref: container['Image'] || config['image'],
            datastore: datastore,
            allocated_ports: ports,
            created_at: created_time,
            started_at: started_time
          )

          @vuln_env.add_target(target)
          elog("reconstruct_state: reconstructed environment #{assigned_id} from container #{container_id}")
        end

        @store.save(@vuln_env)
      rescue => e
        elog("Label reconstruction failed: #{e.message}")
        elog(e.backtrace.join("\n")) if e.backtrace
      end

      def find_by_container(container_id)
        @vuln_env.find_by_container(container_id)
      end

      def find_by_module(module_fullname)
        @vuln_env = @store.load
        @vuln_env.targets.select { |t| t.module_fullname == module_fullname }
      end

      def used_ports
        @vuln_env = @store.load
        @vuln_env.used_ports
      end

      def running?
        @vuln_env = @store.load
        @vuln_env.running_targets.any?
      end

      private

      def decode_port_label(label_value)
        return {} unless label_value

        label_value.split(',').each_with_object({}) do |pair, hash|
          host_port, container_port = pair.split(':')
          hash[container_port.to_i] = host_port.to_i
        end
      end
    end

    # =====================================================================
    # Health Manager
    # =====================================================================
    # waits for a container to become ready using a configurable strategy
    # supports HTTP (status code), TCP (port open), and Command (exec inside container)
    class HealthManager
      def initialize(runtime, container_id, health_config, host_port, dispatcher = nil)
        @runtime = runtime
        @container_id = container_id
        @config = health_config || {}
        @host_port = host_port
        @dispatcher = dispatcher
      end

      # block until the health check passes or retries are exhausted
      # returns true on success. raises on failure so the caller decides cleanup
      def wait
        type = @config['type']
        interval = @config['interval'] || 5
        timeout = @config['timeout'] || 2
        retries = @config['retries'] || 12

        unless %w[http tcp command].include?(type)
          raise "Unknown health check type: #{type.inspect}"
        end

        print_status("Waiting for health check (#{type.upcase})...")

        retries.times do |i|
          print_status("  Attempt #{i + 1}/#{retries}...")

          result = false
          begin
            # Wrap each individual check in a timeout so a hanging TCP/HTTP
            # connection doesn't consume the entire retry budget.
            Timeout.timeout(timeout) do
              result = case type
                       when 'http'    then check_http
                       when 'tcp'     then check_tcp
                       when 'command' then check_command
                       end
            end
          rescue Timeout::Error
            result = false
          rescue => e
            # Log debug details but don't spam the console on every retry
            @dispatcher&.elog("Health check attempt #{i + 1} error: #{e.class} - #{e.message}") if @dispatcher&.respond_to?(:elog)
            result = false
          end

          if result
            print_good("Health check passed.")
            return true
          end

          sleep(interval)
        end

        total_seconds = retries * interval
        raise "Health check timed out after #{total_seconds} seconds"
      end

      def print_status(msg)
        @dispatcher&.print_status(msg)
      end

      def print_good(msg)
        @dispatcher&.print_good(msg)
      end

      def print_error(msg)
        @dispatcher&.print_error(msg)
      end

      private

      def check_http
        path = @config['path'] || '/'
        expected_status = @config['expected_status'] || 200

        uri = URI("http://127.0.0.1:#{@host_port}#{path}")

        # Explicit timeouts prevent hanging connections from consuming the retry budget.
        # Timeout.timeout is unreliable with Net::HTTP blocking I/O.
        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = 2   # Max seconds to establish TCP connection
        http.read_timeout = 2   # Max seconds to read response

        request = Net::HTTP::Get.new(uri)

        # If credentials are defined in the health_check config, add Basic Auth.
        # ActiveMQ's Jolokia endpoint requires this.
        if @config['credentials'] && @config['credentials']['username']
          request.basic_auth(
            @config['credentials']['username'],
            @config['credentials']['password']
          )
        end

        response = http.request(request)

        actual_status = response.code.to_i
        unless actual_status == expected_status
          # Diagnostic output: tell the user what actually came back
          print_status("  Health check returned #{actual_status}, expected #{expected_status}")
          return false
        end

        expected_match = @config['match']
        if expected_match && !response.body.to_s.match?(Regexp.new(expected_match))
          print_status("  Health check got status #{actual_status} but response did not contain expected content")
          return false
        end

        true
      rescue Errno::ECONNRESET
        # TCP connection accepted but HTTP server not yet initialized.
        # This is a transient "not ready" signal — retry on next attempt.
        print_status("  Connection reset on port #{@host_port} (service still initializing)")
        false

      rescue Errno::ECONNREFUSED
        print_status("  Connection refused on port #{@host_port}")
        false

      rescue Net::OpenTimeout
        print_status("  Connection timeout on port #{@host_port}")
        false
      rescue => e
        print_status("  Health check error: #{e.class} - #{e.message}")
        false
      end

      def check_tcp
        # A successful connection + immediate close means the port is listening
        TCPSocket.new('127.0.0.1', @host_port).close
        true
      rescue => e
        false
      end

      def check_command
        command = @config['command']
        expected_output = @config['expected_output']

        output, exit_code = @runtime.exec(@container_id, command)
        return false unless exit_code == 0

        if expected_output
          output.match?(Regexp.new(expected_output))
        else
          true
        end
      end
    end

    # =====================================================================
    # Provisioner
    # =====================================================================
    # Runs a one-time setup action against a container after it passes its
    # health check, but before the environment is considered ready. Needed
    # for images (like vulnerable WordPress) that boot with an unconfigured
    # app: the process is up and answering HTTP, but there's no database
    # schema or admin account yet, so nothing is actually exploitable until
    # this runs.
    class Provisioner
      PROVISION_MARKER = '/tmp/.msf_test_env_provisioned'.freeze unless defined?(PROVISION_MARKER)

      def initialize(runtime, container_id, provision_config, host_port, dispatcher = nil)
        @runtime = runtime
        @container_id = container_id
        @config = provision_config || {}
        @host_port = host_port
        @dispatcher = dispatcher
      end

      # Returns true if there's nothing to do, or if provisioning succeeds.
      # Returns false (does not raise) on failure so the caller decides
      # whether that's fatal.
      def run(datastore = {})
        return true if @config.empty?

        if @config['run_once'] && already_provisioned?
          print_status("Provisioning already completed (run_once). Skipping.")
          return true
        end

        type = @config['type']
        unless type == 'http'
          raise "Unknown provision type: #{type.inspect}"
        end

        print_status("Provisioning environment...")

        Timeout.timeout(@config['timeout'] || 10) do
          http_request(datastore)
        end

        mark_provisioned! if @config['run_once']

        print_good("Provisioning request sent.")
        true
      rescue => e
        print_error("Provisioning failed: #{e.class} - #{e.message}")
        false
      end

      def print_status(msg)
        @dispatcher&.print_status(msg)
      end

      def print_good(msg)
        @dispatcher&.print_good(msg)
      end

      def print_error(msg)
        @dispatcher&.print_error(msg)
      end

      private

      # Checks whether the provision marker file exists inside the
      # container. This allows run_once provisioning to survive container
      # stops/starts and state reconstruction.
      def already_provisioned?
        output, exit_code = @runtime.exec(@container_id, "test -f #{PROVISION_MARKER}")
        exit_code == 0
      rescue => e
        # If we can't check, assume not provisioned and proceed
        false
      end

      # Creates the provision marker file inside the container so that
      # future start/restart operations know provisioning is complete.
      def mark_provisioned!
        @runtime.exec(@container_id, "touch #{PROVISION_MARKER}")
      rescue => e
        # Non-fatal: provisioning succeeded but marker could not be written.
        # The worst case is that a future restart might re-run provisioning,
        # which for idempotent operations (like form submissions) is harmless.
        print_warning("Could not write provision marker: #{e.message}")
      end

      def http_request(datastore)
        path = @config['path'] || '/'
        uri = URI("http://127.0.0.1:#{@host_port}#{path}")

        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = 5
        http.read_timeout = 10

        method = (@config['method'] || 'post').to_s.downcase
        request = case method
                  when 'get'
                    Net::HTTP::Get.new(uri)
                  when 'put'
                    Net::HTTP::Put.new(uri)
                  when 'patch'
                    Net::HTTP::Patch.new(uri)
                  when 'post'
                    Net::HTTP::Post.new(uri)
                  else
                    raise "Unknown HTTP method: #{method.inspect}"
                  end

        if %w[post put patch].include?(method)
          body = resolve_template(@config['body'] || {}, datastore)
          request.set_form_data(body)
        end

        response = http.request(request)

        unless response.code.to_i.between?(200, 399)
          raise "provision request to #{path} returned #{response.code}"
        end
      end
      # Resolves "{{ credentials.default.username }}"-style tokens in the
      # provision body against the datastore already built for this
      # environment (USERNAME/PASSWORD etc. are merged in from
      # config['credentials']['default'] before this runs).
      def resolve_template(body, datastore)
        body.each_with_object({}) do |(key, value), out|
          out[key] = value.is_a?(String) ? substitute(value, datastore) : value
        end
      end

      def substitute(str, datastore)
        str.gsub(/\{\{\s*credentials\.default\.(\w+)\s*\}\}/) do
          datastore[Regexp.last_match(1).upcase].to_s
        end
      end
    end

    # =====================================================================
    # Environment Definition Loader
    # =====================================================================
    class EnvironmentDefinitionLoader
      def initialize(data_directory)
        @base_path = File.join(data_directory, 'vuln_envs')
      end

      def load(name)
        path = File.join(@base_path, "#{name}.yml")
        raise "Definition not found: #{path}" unless File.exist?(path)

        yaml_content = File.read(path)
        begin
          data = YAML.safe_load(yaml_content, permitted_classes: [Symbol])
        rescue ArgumentError
          data = YAML.safe_load(yaml_content, [Symbol])
        end

        validate!(data, name)
        data
      end

      def resolve(name, variant, profile = 'default', overrides = {})
        data = load(name)

        variant_cfg = data['variants'].find { |v| v['name'] == variant }
        unless variant_cfg
          available = data['variants'].map { |v| v['name'] }.join(', ')
          raise "Variant '#{variant}' not defined for '#{name}'. Available: #{available}"
        end

        unless data['profiles'].key?(profile)
          available = data['profiles'].keys.join(', ')
          raise "Profile '#{profile}' not defined for '#{name}'. Available: #{available}"
        end

        config = deep_copy(data['shared'] || {})

        profile_data = data['profiles'][profile].dup
        profile_data.delete('description')
        config = deep_merge(config, profile_data)

        config = deep_merge(config, overrides) if overrides.is_a?(Hash) && !overrides.empty?

        config['image'] = variant_cfg['image']
        config['build_args'] = variant_cfg['build_args'] if variant_cfg['build_args']

        config
      end

      def available_definitions
        return [] unless Dir.exist?(@base_path)
        Dir.glob(File.join(@base_path, '*.yml')).map { |f| File.basename(f, '.yml') }
      end

      private

      def validate!(data, filename)
        unless data['name'] == filename
          raise "Validation failed: name '#{data['name']}' does not match filename '#{filename}'"
        end

        unless data['variants'].is_a?(Array) && !data['variants'].empty?
          raise "Validation failed: 'variants' must be a non-empty list"
        end

        data['variants'].each do |cfg|
          unless cfg.is_a?(Hash) && cfg['name'].is_a?(String) && !cfg['name'].empty?
            raise "Validation failed: variant missing valid 'name'"
          end
          unless cfg['image'].is_a?(String) && !cfg['image'].empty?
            raise "Validation failed: variant '#{cfg['name']}' missing valid 'image'"
          end
        end

        unless data['shared'].is_a?(Hash) && data['shared']['ports'].is_a?(Hash) && !data['shared']['ports'].empty?
          raise "Validation failed: 'shared.ports' must have at least one entry"
        end

        unless data['profiles'].is_a?(Hash) && !data['profiles'].empty?
          raise "Validation failed: 'profiles' must have at least one entry"
        end

        unless data['profiles'].key?('default')
          raise "Validation failed: 'profiles' must contain a 'default' profile"
        end

        data['profiles'].keys.each do |profile_name|
          unless profile_name.to_s.match?(/\A[a-z0-9-]+\z/)
            raise "Validation failed: profile name '#{profile_name}' must match [a-z0-9-]+"
          end
        end

        shared_has_health = data['shared'].is_a?(Hash) && data['shared']['health_check'].is_a?(Hash)
        unless shared_has_health
          data['profiles'].each do |name, cfg|
            unless cfg.is_a?(Hash) && cfg['health_check'].is_a?(Hash)
              raise "Validation failed: 'health_check' must be defined in 'shared' or in every profile (missing in '#{name}')"
            end
          end
        end
      end

      def deep_copy(obj)
        Marshal.load(Marshal.dump(obj))
      end

      def deep_merge(base, override)
        return base unless override.is_a?(Hash)
        base.merge(override) do |_key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(old_val, new_val)
          else
            new_val
          end
        end
      end
    end

    # =====================================================================
    # Console Command Dispatcher
    # =====================================================================
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      @@runtime = nil
      @@registry = nil

      def self.registry=(registry)
        @@registry = registry
      end

      def self.registry
        @@registry
      end

      def self.runtime=(runtime)
        @@runtime = runtime
      end

      def self.runtime
        @@runtime
      end

      def name
        'TestEnv'
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
          cmd_test_env_build(args)
        when 'list'
          cmd_test_env_list(args)
        when 'modules'
          cmd_test_env_modules(args)
        when 'stop'
          cmd_test_env_stop(args)
        when 'start'
          cmd_test_env_start(args)
        when 'remove'
          cmd_test_env_remove(args)
        when 'remove-all'
          cmd_test_env_remove_all(args)
        when 'exec'
          cmd_test_env_exec(args)
        when 'validate'
          cmd_test_env_validate(args)
        when 'status'
          cmd_test_env_status(args)
        when 'help'
          cmd_test_env_help
        else
          print_error("Unknown subcommand: #{subcommand}")
          cmd_test_env_help
        end
      end

def cmd_test_env_build(args)
  container_id = nil
  registered   = false
  runtime      = nil

  begin
    # Steps 1-3: validate module, metadata, and user arguments
    mod, env, options = build_validate_prerequisites(args)
    return unless mod && env

    # Steps 4-7: resolve definition, variant, profile, and config
    definition_name, variant, profile, config, port_mapping = build_resolve_environment(mod, env, options)
    return unless definition_name

    # Step 6: runtime availability
    runtime = self.class.runtime
    unless runtime
      print_error("No container runtime available. Install Docker or Podman.")
      return
    end

    # Step 8: pull image
    return unless build_pull_image(runtime, config)

    # Step 9: allocate host ports
    allocated_ports = build_allocate_ports(runtime, port_mapping, options)

    # Steps 10-12: prune registry, build labels, prepare volumes
    labels, run_ports, volumes, temp_dirs, env_id = build_prepare_resources(
      runtime, config, definition_name, variant, mod, allocated_ports
    )

    # Step 13: launch container
    container_id = build_launch_container(runtime, config, run_ports, labels, volumes, definition_name, variant)

    # verify container actually started
    container_info = runtime.inspect(container_id)
    unless container_info
      print_error("Container started but inspect failed immediately.")
      runtime.remove(container_id)
      return
    end

    # check if running (Docker/Podman both use State.Status)
    status = container_info.dig('State', 'Status') || container_info.dig('State', 'Running')
    if status != 'running' && status != true
      error_msg = container_info.dig('State', 'Error') || 'unknown'
      print_error("Container failed to start. Status: #{status.inspect}, Error: #{error_msg}")
      runtime.remove(container_id)
      return
    end

    print_good("Container started: #{container_id[0..11]}")

    # Step 14: health check BEFORE registering
    return unless build_wait_for_health(runtime, container_id, config, port_mapping, allocated_ports)

    # TCP health checks confirm liveness (port open) but not readiness
    # (protocol fully initialized). Some services (e.g. ActiveMQ OpenWire)
    # accept connections before the protocol handler is ready.
    if config.dig('health_check', 'type') == 'tcp'
      print_status("TCP port open; waiting 5 seconds for protocol initialization...")
      sleep 5
    end
    # Step 15: build the datastore (RHOSTS/RPORT/credentials/etc.)
    datastore = build_construct_datastore(config, allocated_ports, port_mapping)

    # Step 15.5: run optional one-time provisioning (e.g. WordPress install
    # wizard), then re-verify, before the environment is registered as ready
    unless build_provision_environment(runtime, container_id, config, port_mapping, allocated_ports, datastore)
      print_error("Provisioning failed; tearing down container.")
      runtime.stop(container_id) rescue nil
      runtime.remove(container_id) rescue nil
      return
    end

    # Step 16: register environment in registry
    build_register_environment(
      runtime, container_id, mod, variant, config, allocated_ports, temp_dirs, env_id, datastore
    )
    registered = true

    # Step 17: free host ports for stage/fetch payloads (avoids Rex::BindFailed on 8080)
    %w[SRVPORT FETCH_SRVPORT].each do |opt|
      if mod.options.include?(opt)
        free_port = free_local_port
        datastore[opt] = free_port
      end
    end

    # Step 18: apply datastore to the active module
    datastore.each do |key, value|
      if mod.options.include?(key)
        mod.datastore[key] = value
      end
    end

    # Step 19: display results to user
    build_display_results(env_id, config, datastore, mod)

  rescue PortAllocator::NoPortsAvailable => e
    print_error("No available ports: #{e.message}")
  rescue => e
    # Clean up orphaned container if we created one but failed to register it
    if container_id && !registered
      begin
        runtime.stop(container_id) rescue nil
        runtime.remove(container_id)
        print_status("Cleaned up orphaned container #{container_id[0..11]}")
      rescue => cleanup_err
        elog("Failed to cleanup orphaned container: #{cleanup_err.message}")
      end
    end

    print_error("test_env build failed: #{e.message}")
    elog("test_env build error: #{e.class} - #{e.message}")
    elog(e.backtrace.join("\n"))
  end
end

# -------------------------------------------------------------------------
# Build Phase Helpers
# -------------------------------------------------------------------------

# Steps 1-3: Preconditions, metadata validation, and argument parsing.
# Returns [mod, env, options] or [nil, nil, nil] on failure.
def build_validate_prerequisites(args)
  mod = driver.active_module
  unless mod
    print_error("No active module. Use 'use <module>' first.")
    return [nil, nil, nil]
  end

  env = vulnerable_environment(mod)
  unless env
    print_error("Module does not define a vulnerable environment configuration.")
    return [nil, nil, nil]
  end

  options = parse_build_args(args)
  [mod, env, options]
end

# Steps 4-7: Resolve environment definition and validate port mappings.
# Returns [definition_name, variant, profile, config, port_mapping]
# or [nil, nil, nil, nil, nil] when variant is missing.
def build_resolve_environment(mod, env, options)
  definition_name = env.definition
  default_variant = env.default_variant
  port_mapping    = env.port_mapping

  variant = options['VARIANT'].to_s.empty? ? default_variant : options['VARIANT']
  profile = options['PROFILE'].to_s.empty? ? env.profile : options['PROFILE']

  unless variant
    print_error("No variant specified and module has no default_variant.")
    return [nil, nil, nil, nil, nil]
  end

  loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
  config = loader.resolve(definition_name, variant, profile, env.overrides)

  # Validate: every port in module's port_mapping must exist in the environment's exposed ports
  resolved_ports = config.fetch('ports', {}).values.map(&:to_i)
  port_mapping.keys.each do |container_port|
    port_int = container_port.to_i
    unless resolved_ports.include?(port_int)
      available = resolved_ports.join(', ')
      raise "Port mapping mismatch: module maps port #{port_int} but environment '#{definition_name}' (variant '#{variant}', profile '#{profile}') only exposes ports: #{available}"
    end
  end

  print_status("Resolving environment for #{mod.fullname}...")
  print_status("Definition: #{definition_name} | Variant: #{variant} | Profile: #{profile}")
  print_status("Image: #{config['image']}")

  # If the environment definition names a recommended payload (e.g. because
  # the module's own auto-selected default is known not to work against
  # this specific image/variant), apply it now, before the container is
  # even started, so it's reflected if the user runs 'show options'.
  recommended_payload = config.dig('ci', 'exploit', 'payload')
  if recommended_payload && !mod.datastore['PAYLOAD'].nil? && mod.datastore['PAYLOAD'] != recommended_payload
    print_status("Setting recommended payload for this environment: #{recommended_payload}")
    mod.datastore['PAYLOAD'] = recommended_payload
  end

  [definition_name, variant, profile, config, port_mapping]
end

# Step 8: Pull the container image. Returns true on success, false on failure.
def build_pull_image(runtime, config)
  print_status("Pulling image #{config['image']}...")
  unless runtime.pull(config['image'])
    print_error("Failed to pull image: #{config['image']}")
    return false
  end
  print_good("Image pulled successfully.")
  true
end

# Step 9: Allocate free host ports for container bindings.
def build_allocate_ports(runtime, port_mapping, options)
  allocator = PortAllocator.new(runtime, self.class.registry.used_ports)
  allocated_ports = {}
  user_rport = options['RPORT'] ? options['RPORT'].to_i : nil
  target_container_port = user_rport ? port_mapping.key('RPORT') : nil

  port_mapping.each do |container_port, ds_option|
    preferred = (container_port == target_container_port) ? user_rport : nil
    host_port = allocator.allocate(preferred)

    if preferred && host_port != preferred
      print_status("Requested port #{preferred} unavailable. Using dynamically allocated port #{host_port}.")
    end

    allocated_ports[container_port] = host_port
  end

  allocated_ports
end

# Steps 10-12: Prune registry, build labels, map ports for runtime, and prepare volumes.
# Returns [labels, run_ports, volumes, temp_dirs, env_id].
def build_prepare_resources(runtime, config, definition_name, variant, mod, allocated_ports)
  self.class.registry.prune(runtime)

  instance_id = "msf-#{Socket.gethostname}-#{Process.pid}"
  env_id = self.class.registry.reserve_id

  labels = runtime.build_labels(
    instance_id: instance_id,
    module_fullname: mod.fullname,
    env_id: env_id,
    version: variant,
    ports: allocated_ports
  )

  run_ports = {}
  allocated_ports.each do |container_port, host_port|
    run_ports[container_port] = host_port
  end

  volumes = {}
  temp_dirs = []

  if config['volumes']
    config['volumes'].each do |name, vol_cfg|
      host_path = vol_cfg['host_path']
      unless host_path
        host_path = Dir.mktmpdir("test_env_#{name}_")
        temp_dirs << host_path
      end
      volumes[host_path] = vol_cfg['container_path']
    end
  end

  [labels, run_ports, volumes, temp_dirs, env_id]
end

# Step 13: Launch the container. Returns the container_id.
def build_launch_container(runtime, config, run_ports, labels, volumes, definition_name, variant)
  print_status("Starting container...")
  container_name = "msf-vulnenv-#{definition_name}-#{variant}-#{Time.now.to_f.to_s.delete('.')}"

  runtime.run(
    image: config['image'],
    ports: run_ports,
    labels: labels,
    volumes: volumes,
    name: container_name
  )
end

# Step 14: Wait for health check. Returns true if healthy, false otherwise
# (container is already cleaned up on failure).
def build_wait_for_health(runtime, container_id, config, port_mapping, allocated_ports)
  primary_container_port = port_mapping.key('RPORT')
  health_host_port = allocated_ports[primary_container_port] || allocated_ports.values.first

  health = config['health_check']
  begin
    HealthManager.new(runtime, container_id, health, health_host_port, self).wait
  rescue => e
    print_error("Health check failed: #{e.message}")
    begin
      runtime.stop(container_id) rescue nil
      runtime.remove(container_id) rescue nil
    rescue => cleanup_err
      elog("Failed to cleanup unhealthy container: #{cleanup_err.message}")
    end
    return false
  end
  true
end

# Step 15: Build the datastore hash (RHOSTS/RPORT/TARGETURI/credentials/etc.)
# Split out from registration so provisioning (below) has USERNAME/PASSWORD
# and the resolved ports available before the environment is registered.
def build_construct_datastore(config, allocated_ports, port_mapping)
  datastore = { 'RHOSTS' => '127.0.0.1' }
  allocated_ports.each do |container_port, host_port|
    ds_option = port_mapping[container_port]
    datastore[ds_option] = host_port if ds_option
  end

  if config['datastore_defaults']
    config['datastore_defaults'].each do |key, value|
      datastore[key] = value unless datastore.key?(key)
    end
  end

  # Merge credentials into datastore so they are applied to the module,
  # stored in the registry, and included in the suggested exploit command.
  if config['credentials'] && config['credentials']['default']
    config['credentials']['default'].each do |key, value|
      ds_key = key.to_s.upcase
      datastore[ds_key] = value unless datastore.key?(ds_key)
    end
  end

  datastore
end

# Step 15.5: Run the optional one-time provisioning step (e.g. driving the
# WordPress install wizard) against the primary port, then re-verify with
# an optional 'verify' block. No-op (returns true) if the definition has no
# 'provision' config. On failure, the caller is responsible for cleanup.
def build_provision_environment(runtime, container_id, config, port_mapping, allocated_ports, datastore)
  provision = config['provision']
  return true unless provision.is_a?(Hash) && !provision.empty?

  primary_container_port = port_mapping.key('RPORT')
  host_port = allocated_ports[primary_container_port] || allocated_ports.values.first

  unless Provisioner.new(runtime, container_id, provision, host_port, self).run(datastore)
    return false
  end

  verify = config['verify']
  return true unless verify.is_a?(Hash) && !verify.empty?

  begin
    HealthManager.new(runtime, container_id, verify, host_port, self).wait
  rescue => e
    print_error("Post-provision verification failed: #{e.message}")
    return false
  end

  true
end

# Step 16: Register the built, provisioned environment with the registry.
def build_register_environment(runtime, container_id, mod, variant, config, allocated_ports, temp_dirs, env_id, datastore)
  self.class.registry.register_with_id(
    env_id: env_id,
    container_id: container_id,
    module_fullname: mod.fullname,
    env_version: variant,
    runtime: runtime.name,
    image_ref: config['image'],
    datastore: datastore,
    allocated_ports: allocated_ports,
    temp_dirs: temp_dirs
  )

  datastore
end

# Step 18: Display build results and suggested exploit command.
def build_display_results(env_id, config, datastore, mod)
  print_good("Environment ready.")
  print_status("Environment ID: #{env_id}")

  %w[SRVPORT FETCH_SRVPORT].each do |opt|
    if mod.options.include?(opt)
      free_port = free_local_port
      mod.datastore[opt] = free_port
      datastore[opt] = free_port
    end
  end

  applicable = datastore.select { |k, _v| mod.options.include?(k) }
  applicable.each do |key, value|
    print_status("   #{key.ljust(12)} => #{value}")
  end

  action = mod.type == 'auxiliary' ? 'run' : 'exploit'
  opts = applicable.map { |k, v| "#{k}=#{v}" }.join(' ')
  print_status("Suggested: #{action} #{opts}")
end

      def cmd_test_env_help
        print_line("Usage: test_env <command>")
        print_line
        print_line("Commands:")
        print_line("  build      Build and launch environment for active module")
        print_line("  list       List tracked environments")
        print_line("  modules    List all modules with test_env support")
        print_line("  stop <ID>  Stop a running environment")
        print_line("  start <ID> Restart a stopped environment")
        print_line("  remove <ID> Tear down an environment")
        print_line("  remove-all Tear down all environments")
        print_line("  exec <ID>  Execute exploit against environment")
        print_line("  validate <ID> Check session/output against ci.validation")
        print_line("  status     Show runtime status")
        print_line("  help       Show this help")
        print_line
      end

      def cmd_test_env_status(args)
        runtime = self.class.runtime
        if runtime
          print_status("Runtime: #{runtime.name}")
          if runtime.respond_to?(:verify_rootless)
            ok, msg = runtime.verify_rootless
            ok ? print_good(msg) : print_warning(msg)
          end

          # count framework-managed containers
          containers = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' })
          running = containers.count { |c| c['State'] == 'running' }
          total = containers.length

          print_status("Managed containers: #{total} total, #{running} running")
        else
          print_error("No runtime configured.")
        end

        loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
        defs = loader.available_definitions

        valid_defs = []
        defs.each do |name|
          begin
            loader.load(name)
            valid_defs << name
          rescue => e
            print_error("Validation failed for '#{name}': #{e.message}")
          end
        end

        if valid_defs.any?
          print_status("Available definitions: #{valid_defs.join(', ')}")
        else
          print_error("No valid definitions found.")
        end
      rescue => e
        print_error("Status check failed: #{e.message}")
      end
      def cmd_test_env_list(_args = [])
        targets = self.class.registry.list

        if targets.empty?
          print_status("No environments currently tracked.")
          return
        end

        rows = targets.map do |t|
          [
            t.local_id.to_s,
            t.container_id.to_s[0..11],
            t.module_fullname.to_s,
            t.rhost || '127.0.0.1',
            t.rport.to_s,
            t.status.to_s,
            t.env_version.to_s
          ]
        end

        tbl = Rex::Text::Table.new(
          'Header'     => 'Test Environments',
          'Indent'     => 1,
          'Columns'    => ['ID', 'Container', 'Module', 'RHOST', 'RPORT', 'Status', 'Version']
        )

        rows.each { |r| tbl << r }
        print_line(tbl.to_s)

        print_status("#{targets.length} environment(s) tracked.")
      end

      def cmd_test_env_exec(args)
        if args.empty? || args.first == '-h' || args.first == '--help'
          print_line("Usage: test_env exec <ID>")
          print_line
          print_line("Loads the module this environment was built for, applies its")
          print_line("stored datastore and recommended payload (if any), and runs it.")
          print_line("Equivalent to manually running the 'Suggested:' command printed")
          print_line("by 'test_env build', but works from anywhere in the console -")
          print_line("you do not need to 'use' the module first.")
          return
        end

        # --- Step A: look up the stored environment. Fail fast with a
        # specific, actionable message rather than letting a nil target
        # propagate into a confusing NoMethodError three lines down. This
        # is the "improve error handling" deliverable in practice: every
        # precondition gets its own guard and its own message.
        id = nil
        background = false

        args.each do |arg|
          case arg
          when '-z', '--background'
            background=true
          when /^-/
            print_warning("Unknown option: #{arg}")
          else
            id = arg.to_i if id.nil?
          end
        end

        unless id
          print_error("No environment ID specified.")
          return
        end

        target = self.class.registry.get(id)

        unless target
          print_error("Environment #{id} not found. Run 'test_env list' to see tracked environments.")
          return
        end

        unless target.running?
          print_error("Environment #{id} is #{target.status}, not running.")
          print_status("Run 'test_env start #{id}' first, then retry.")
          return
        end

        # --- Step B: load the module by fullname. Deliberately not using
        # driver.active_module here - exec should work standalone, even if
        # the console is currently pointed at a completely different module
        # (or nothing at all). This makes 'exec' safe to call repeatedly in
        # automation without tracking console state externally.
        print_status("Using #{target.module_fullname}...")
        driver.run_single("use #{target.module_fullname}")

        mod = driver.active_module
        unless mod && mod.fullname == target.module_fullname
          print_error("Could not load module '#{target.module_fullname}'. It may have been removed or renamed since this environment was built.")
          return
        end

        # --- Step C: re-resolve the environment definition to recover any
        # ci.exploit recommendation (payload + options). This is NOT part
        # of target.datastore - build_construct_datastore only stores
        # RHOSTS/RPORT/TARGETURI/credentials, not PAYLOAD/LHOST/LPORT - so
        # without this step 'exec' would silently fall back to whatever
        # payload the module auto-selects, reintroducing the exact
        # incompatible-default-payload problem 'build' already solves.
        raw = mod.send(:module_info)['VulnerableEnvironment'] rescue nil
        if raw
          env_meta = VulnerableEnvironment.new(raw)
          loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
          config = loader.resolve(env_meta.definition, target.env_version, env_meta.profile, env_meta.overrides) rescue nil
          ci_exploit = config&.dig('ci', 'exploit') || {}

          if ci_exploit['payload'] && mod.datastore['PAYLOAD'] != ci_exploit['payload']
            print_status("Setting recommended payload for this environment: #{ci_exploit['payload']}")
            driver.run_single("set PAYLOAD #{ci_exploit['payload']}")
          end

          ci_exploit['options']&.each do |key, value|
            driver.run_single("set #{key} #{value}")
          end

          if ci_exploit['force_exploit']
            driver.run_single("set ForceExploit true")
          end
        end

        # --- Step D: apply the suggested datastore automatically. This
        # reuses target.datastore directly rather than re-deriving RHOSTS/
        # RPORT/credentials by hand - single source of truth, and it's the
        # exact same hash 'test_env build' already showed the user under
        # "Suggested:", so what runs here always matches what was printed.
        applied = {}
        target.datastore.each do |key, value|
          if mod.options.include?(key)
            driver.run_single("set #{key} #{value}")
            applied[key] = value
          end
        end

        # --- Step D.5: avoid Rex::BindFailed from stale listeners on
        # repeated runs. Some payloads (e.g. cmd/linux/http/.../reverse_tcp)
        # bind a local server on this host to serve the stage/fetch content
        # - by default on a fixed port (often 8080). If a previous 'exec'
        # run's server didn't get torn down cleanly, that port stays bound
        # and every subsequent run fails until someone manually finds and
        # kills the stale process. Picking a fresh free port each time
        # removes the collision entirely rather than requiring cleanup.
        %w[SRVPORT FETCH_SRVPORT].each do |opt|
          if mod.options.include?(opt)
            free_port = free_local_port
            driver.run_single("set #{opt} #{free_port}")
            applied[opt] = free_port
          end
        end
          
        # --- Step E: run it. driver.run_single("exploit") reuses the
        # console's own exploit-execution path - AutoCheck, payload
        # generation, session creation, and all success/failure messaging
        # come from that well-tested path rather than being reimplemented
        # here. See the design note above for why this matters.
        action =  if mod.type == 'auxiliary'
                    'run'
                  elsif background
                    'exploit -z'
                  else
                    'exploit'
                  end

        opts = applied.map { |k, v| "#{k}=#{v}" }.join(' ')
        print_status("Executing: #{action} #{opts}")
        driver.run_single(action)
      rescue => e
        print_error("test_env exec failed: #{e.class} - #{e.message}")
        elog("test_env exec error: #{e.class} - #{e.message}")
        elog(e.backtrace.join("\n"))
      end

      # Asks the OS for an unused ephemeral port by binding to port 0 and
      # reading back what it was assigned. Simpler and more reliable than
      # maintaining our own "is this port free" bookkeeping for host-side
      # (non-container) ports - the OS already tracks this correctly.
      def free_local_port
        server = TCPServer.new('0.0.0.0', 0)
        port = server.addr[1]
        server.close
        port
      end

      # Runs a lightweight "who am I" check on a session and returns
      # output in the same shape a raw 'id' command would (so it can be
      # matched against a shell-style expected_output like "uid=").
      #
      # Deliberately NOT using shell_command_token for Meterpreter: that
      # opens a process channel (sys.process.execute under the hood), and
      # in testing that channel path failed deterministically - every
      # attempt, every session, same "core_channel_write: Operation
      # failed: 9" - which points to the channel mechanism itself being
      # unreliable in this environment, not a one-off timing issue.
      # sys.config.getuid is a plain TLV request/response call with no
      # channel involved, so it avoids that failure mode entirely.
      #
      # Shell sessions have no such alternative - shell_command_token IS
      # the interface for them, and it worked without issue in testing
      # (see the WordPress php/reverse_php run), so it stays as-is there.
      def run_verification_command(session)
        if session.type.to_s == 'meterpreter' && session.respond_to?(:sys)
          uid = session.sys.config.getuid
          "uid=#{uid}"
        else
          session.shell_command_token('id')
        end
      end

      # Checks a built (and typically already-'exec'd) environment against
      # its definition's ci.validation block: was a session created, is it
      # the expected type, and does it produce the expected output. Prints
      # a clear PASS/FAIL.
      #
      # This is the concrete "align shared definitions with CI and local
      # execution workflows" deliverable: ci.validation was previously
      # documented in the YAML schema but never actually read by any code
      # path. Because this method only reads from the resolved definition
      # (never anything console-session-specific beyond the session list
      # itself), the exact same check a human runs interactively here is
      # what a headless CI runner would perform against the same YAML -
      # there is one definition of "did this pass," not two.
      def cmd_test_env_validate(args)
        if args.empty? || args.first == '-h' || args.first == '--help'
          print_line("Usage: test_env validate <ID>")
          print_line
          print_line("Checks session(s) opened against this environment's")
          print_line("module against the definition's ci.validation")
          print_line("expectations (session type + expected output). If")
          print_line("multiple sessions exist (some modules open duplicates),")
          print_line("each is tried until one responds correctly. Prints PASS")
          print_line("or FAIL. Run 'test_env exec <ID>' first if no session")
          print_line("exists yet.")
          print_line
          print_line("IMPORTANT: sessions are process-local. Run 'exec' and")
          print_line("'validate' in the SAME msfconsole window - a session")
          print_line("opened in one msfconsole process is invisible to another.")
          return
        end

        id = args.shift.to_i
        target = self.class.registry.get(id)

        unless target
          print_error("Environment #{id} not found. Run 'test_env list' to see tracked environments.")
          return
        end

        # Load the module read-only - validate doesn't change console
        # context (unlike exec, which needs 'use' for driver.run_single
        # to apply datastore/run the exploit).
        mod = framework.modules.create(target.module_fullname)
        unless mod
          print_error("Could not load module '#{target.module_fullname}'. It may have been removed or renamed since this environment was built.")
          return
        end

        raw = mod.send(:module_info)['VulnerableEnvironment'] rescue nil
        unless raw
          print_error("Module '#{target.module_fullname}' does not define a VulnerableEnvironment.")
          return
        end

        env_meta = VulnerableEnvironment.new(raw)
        loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
        config = loader.resolve(env_meta.definition, target.env_version, env_meta.profile, env_meta.overrides) rescue nil

        unless config
          print_error("Could not resolve environment definition '#{env_meta.definition}'.")
          return
        end

        validation = config.dig('ci', 'validation')
        unless validation
          print_error("Definition '#{env_meta.definition}' has no ci.validation block - nothing to check against.")
          return
        end

        expected_session = validation.fetch('expected_session', true)
        expected_type    = validation['session_type']
        expected_output  = validation['expected_output']
        wait_timeout     = validation['timeout'] || 120

        print_status("Validating environment #{id} (#{target.module_fullname}) against #{env_meta.definition}'s ci.validation...")

        unless expected_session
          print_status("No session required; validating service behavior...")

          expected_text = validation['expected_output']
          probe_port = target.allocated_ports.values.first

          if expected_text && !expected_text.empty?
            response = nil

            # Probe based on the environment's health check type
            case config.dig('health_check', 'type')
            when 'http'
              begin
                uri = URI("http://127.0.0.1:#{probe_port}/")
                http = Net::HTTP.new(uri.host, uri.port)
                http.open_timeout = 5
                http.read_timeout = 5
                response = http.request(Net::HTTP::Get.new(uri))
                response_body = response.body.to_s
                response_headers = response.to_hash.map { |k, v| "#{k}: #{v.join}" }.join("\n")
                response = "#{response_headers}\n\n#{response_body}"
              rescue => e
                print_error("FAIL: HTTP probe failed: #{e.message}")
                return
              end

            when 'tcp'
              begin
                socket = TCPSocket.new('127.0.0.1', probe_port)
                response = socket.gets.to_s
                socket.close
              rescue => e
                print_error("FAIL: TCP probe failed: #{e.message}")
                return
              end
            end

            if response && response.match?(Regexp.new(expected_text))
              print_good("Service response contains expected text: '#{expected_text}'")
            else
              print_error("FAIL: service response did not contain '#{expected_text}'")
              print_status("--- Response (first 400 chars) ---")
              print_status(response.to_s[0..400])
              print_status("----------------------------------")
              return
            end
          else
            print_warning("No ci.validation.expected_output defined for this auxiliary module.")
            print_warning("Falling back to smoke test (module executed without errors).")
          end

          # Layer 2: verify service is still healthy after the scan
          begin
            if config && config['health_check']
              primary_port = target.allocated_ports[env_meta.port_mapping.key('RPORT')]
              health_port = primary_port || target.allocated_ports.values.first
              runtime = self.class.runtime || (RuntimeAdapter.detect(framework.datastore) rescue nil)

              if runtime && health_port
                HealthManager.new(runtime, target.container_id,
                                config['health_check'], health_port, self).wait
              end
            end
          rescue => e
            print_error("FAIL: environment unhealthy after module execution: #{e.message}")
            return
          end

          print_good("PASS: environment validated successfully against #{env_meta.definition}'s ci.validation.")
          return
        end

        # Session creation can lag slightly behind 'exploit' returning
        # (staged payloads in particular), so poll for a short window
        # rather than checking exactly once.
        candidates = []
        begin
          Timeout.timeout(wait_timeout) do
            until candidates.any?
              candidates = framework.sessions.values
                                     .select { |s| s.via_exploit == target.module_fullname }
                                     .sort_by(&:sid)
              sleep 2 if candidates.empty?
            end
          end
        rescue Timeout::Error
          # handled by the empty check below
        end

        if candidates.empty?
          print_error("FAIL: no session was created within #{wait_timeout}s (expected_session: true) in this console session.")
          print_status("Sessions are process-local: they only exist in the msfconsole process that opened them.")
          print_status("If you ran 'test_env exec #{id}' in a different msfconsole window, run 'test_env validate #{id}' there too - not here.")
          print_status("Otherwise, run 'test_env exec #{id}' first, then 'test_env validate #{id}' in the same console.")
          return
        end

        print_status("Found #{candidates.length} session(s) for this module: #{candidates.map(&:sid).join(', ')}")

        if expected_type
          candidates = candidates.select { |s| s.type.to_s == expected_type.to_s }
          if candidates.empty?
            print_error("FAIL: no session of type '#{expected_type}' found.")
            return
          end
        end

        # Some modules (notably this ActiveMQ one, which fires its Spring
        # XML payload multiple times) can leave more than one session -
        # some real, some stale/half-connected duplicates. The most
        # recent SID is not reliably the working one (observed directly:
        # the session actually interacted with was SID 1, while SID 2 -
        # a duplicate opened moments later - consistently failed channel
        # writes). So rather than guessing based on recency, try each
        # candidate oldest-first and use the first one that actually
        # responds. If expected_output isn't set, there's nothing to
        # distinguish working from broken, so just take the oldest.
        session = nil
        output = nil

        if expected_output
          candidates.each do |candidate|
            if candidate.respond_to?(:load_stdapi)
              begin
                candidate.load_stdapi
              rescue => e
                print_status("Could not explicitly load stdapi on session #{candidate.sid} (#{e.message}), continuing anyway...")
              end
            end

            result = nil
            attempts = 0
            begin
              attempts += 1
              result = run_verification_command(candidate)
            rescue => e
              if attempts < 3
                print_status("Session #{candidate.sid}: verification command failed on attempt #{attempts}/3 (#{e.message}), retrying...")
                sleep 3
                retry
              else
                print_status("Session #{candidate.sid} did not respond after #{attempts} attempts (#{e.message}) - trying next candidate, if any.")
              end
            end

            if result&.match?(Regexp.new(expected_output))
              session = candidate
              output = result
              break
            end
          end

          unless session
            print_error("FAIL: none of #{candidates.length} candidate session(s) (#{candidates.map(&:sid).join(', ')}) produced the expected output '#{expected_output}'.")
            return
          end
        else
          session = candidates.first
        end

        print_status("Using session #{session.sid} (#{session.type})")

        print_good("PASS: environment #{id} validated successfully against #{env_meta.definition}'s ci.validation.")
      rescue => e
        print_error("test_env validate failed: #{e.class} - #{e.message}")
        elog("test_env validate error: #{e.class} - #{e.message}")
        elog(e.backtrace.join("\n"))
      end

      def cmd_test_env_start(args)
        if args.empty?
          print_error("Usage: test_env start <ID>")
          return
        end

        # start accepts single ID
        id = args.first.to_i
        target = self.class.registry.get(id)

        unless target
          print_error("Environment #{id} not found.")
          return
        end

        unless target.stopped?
          print_warning("Environment #{id} is already #{target.status}.")
          return
        end

        runtime = self.class.runtime
        unless runtime
          print_error("No container runtime available.")
          return
        end

        begin
          unless runtime.start(target.container_id)
            print_error("Failed to start container for environment #{id}.")
            return
          end

          # Reconstruct health check configuration
          mod = framework.modules.create(target.module_fullname) rescue nil
          if mod
            raw = mod.send(:module_info)['VulnerableEnvironment'] rescue nil
            if raw
              env_meta = VulnerableEnvironment.new(raw)
              loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
              config = loader.resolve(env_meta.definition, target.env_version,
                                      env_meta.profile, env_meta.overrides) rescue nil

              if config
                # For environments that were provisioned during build, the
                # service state after restart is post-provision (e.g. WordPress
                # returns 200 at /, not 302 to the install wizard). Use verify
                # instead of the base health_check to confirm the configured
                # state is restored.
                check_config = if config['provision'] && config['verify']
                                 config['verify']
                               else
                                 config['health_check']
                               end

                if check_config
                  primary_port = target.allocated_ports[env_meta.port_mapping.key('RPORT')]
                  health_port = primary_port || target.allocated_ports.values.first

                  begin
                    HealthManager.new(runtime, target.container_id,
                                    check_config, health_port, self).wait
                  rescue => e
                    print_warning("Health check warning after start: #{e.message}")
                    # Container started; we still mark running but warn user

                  end
                end
              end
            end
          end

          self.class.registry.update_status(id, :running)
          print_good("Environment #{id} started. RPORT=#{target.rport}")
        rescue => e
          print_error("Error starting environment #{id}: #{e.message}")
        end
      end

      def cmd_test_env_stop(args)
        if args.empty?
          print_error("Usage: test_env stop <ID range>")
          return
        end

        ids = parse_id_range(args.first)
        if ids.empty?
          print_error("No valid IDs provided.")
          return
        end

        runtime = self.class.runtime
        unless runtime
          print_error("No container runtime available.")
          return
        end

        ids.each do |id|
          target = self.class.registry.get(id)
          unless target
            print_error("Environment #{id} not found.")
            next
          end

          unless target.running?
            print_warning("Environment #{id} is already #{target.status}.")
            next
          end

          begin
            if runtime.stop(target.container_id)
              self.class.registry.update_status(id, :stopped)
              print_good("Environment #{id} stopped.")
            else
              print_error("Failed to stop container for environment #{id}.")
            end
          rescue => e
            print_error("Error stopping environment #{id}: #{e.message}")
          end
        end
      end

      def cmd_test_env_remove(args)
        if args.empty?
          print_error("Usage: test_env remove <ID range>")
          return
        end

        ids = parse_id_range(args.first)
        if ids.empty?
          print_error("No valid IDs provided.")
          return
        end

        runtime = self.class.runtime
        unless runtime
          print_error("No container runtime available.")
          return
        end

        # Resolve all targets FIRST before any mutation
        targets = ids.map { |id| [id, self.class.registry.get(id)] }.to_h

        # Validate all exist before attempting any removal
        missing = targets.select { |_id, t| t.nil? }.keys
        missing.each { |id| print_error("Environment #{id} not found.") }

        valid_ids = targets.reject { |_id, t| t.nil? }.keys

        valid_ids.each do |id|
          target = targets[id]

          begin
            runtime.stop(target.container_id) if target.running?
          rescue => e
            print_warning("Stop warning for #{id}: #{e.message}")
          end

          begin
            runtime.remove(target.container_id)
          rescue => e
            print_error("Failed to remove container for environment #{id}: #{e.message}")
            next  # DO NOT purge registry if runtime removal failed
          end

          self.class.registry.remove(id)
          print_good("Environment #{id} removed.")
        end
      end

      def cmd_test_env_remove_all(_args = [])
        runtime = self.class.runtime
        unless runtime
          print_error("No container runtime available.")
          return
        end

        targets = self.class.registry.list
        if targets.empty?
          print_status("No environments to remove.")
          return
        end

        print_status("Tearing down #{targets.length} environment(s)...")

        targets.each do |target|
          begin
            runtime.stop(target.container_id) if target.running?
          rescue => e
            print_warning("Stop warning for #{target.local_id}: #{e.message}")
          end

          begin
            runtime.remove(target.container_id)
          rescue => e
            print_warning("Remove warning for #{target.local_id}: #{e.message}")
          end
        end

        # Atomic registry reset
        self.class.registry.remove_all
        print_good("All environments removed.")
      end
    
      def cmd_test_env_modules(args)
        print_status("Scanning framework modules for test_env support...")

        matches = []
        scanned = 0

        framework.modules.each do |name, modclass|
          scanned += 1
          instance = nil

          begin
            instance = framework.modules.create(name)
          rescue => e
            next
          end

          next unless instance

          begin
            raw = instance.send(:module_info)['VulnerableEnvironment']
            next unless raw

            env = VulnerableEnvironment.new(raw)

            loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
            begin
              config = loader.resolve(env.definition, env.default_variant, env.profile, env.overrides)
              image = config['image'] || 'unknown'
            rescue => e
              image = "definition error"
            end

            ports = env.port_mapping.map { |cp, ds| "#{cp}→#{ds}" }.join(', ')

            matches << {
              fullname: name,
              definition: env.definition,
              variant: env.default_variant,
              profile: env.profile,
              ports: ports,
              image: image
            }
          rescue => e
            next
          end
        end

        if matches.empty?
          print_status("No modules with test_env support found.")
          print_status("Scanned #{scanned} module(s).")
          return
        end

        tbl = Rex::Text::Table.new(
          'Header' => 'Modules with test_env Support',
          'Columns' => ['Module', 'Definition', 'Variant', 'Profile', 'Ports', 'Image']
        )

        matches.sort_by { |m| m[:fullname] }.each do |m|
          tbl << [m[:fullname], m[:definition], m[:variant], m[:profile], m[:ports], m[:image]]
        end

        print_line(tbl.to_s)

        print_status("Found #{matches.length} module(s) with test_env support (scanned #{scanned} total).")
      end
      
      def cmd_test_env_tabs(str, words)
        if words.length == 1
          return %w[build list modules stop start remove remove-all exec validate status help]
        end

        if words.length == 2 && words[0] == 'build'
          return %w[VARIANT= PROFILE= RPORT=]
        end

        if words.length == 2
          case words[0]
          when 'stop', 'start', 'remove', 'exec', 'validate'
            return self.class.registry.list.map(&:local_id).map(&:to_s)
          end
        end

        []
      end

      private

      # Reads and validates VulnerableEnvironment metadata from the active module.
      # Mirrors the framework pattern used by #name, #description, #notes, etc.
      # Returns a VulnerableEnvironment Struct, or nil if the module has none.
      def vulnerable_environment(mod)
        return nil unless mod

        raw = mod.send(:module_info)['VulnerableEnvironment']
        return nil unless raw

        VulnerableEnvironment.new(raw)
      rescue ArgumentError => e
        print_error("Module has invalid VulnerableEnvironment: #{e.message}")
        nil
      end

      # Parse build arguments. Only accepts known keys.
      def parse_build_args(args)
        options = {}
        args.each do |arg|
          if arg.include?('=')
            key, value = arg.split('=', 2)
            key = key.upcase
            if %w[VARIANT PROFILE RPORT].include?(key)
              options[key] = value
            else
              print_warning("Unknown build option: #{key}. Expected: VARIANT=, PROFILE=, RPORT=")
            end
          end
        end
        options
      end

      # Parses "1", "1-3", "1,3,5", "1-3,5,7-9" into [1, 2, 3, 5, 7, 8, 9]
      def parse_id_range(range_str)
        return [] if range_str.nil? || range_str.empty?

        ids = []
        range_str.split(',').each do |part|
          part.strip!
          if part.include?('-')
            start_id, end_id = part.split('-', 2).map(&:to_i)
            ids.concat((start_id..end_id).to_a)
          else
            ids << part.to_i
          end
        end
        ids.uniq.sort
      rescue => e
        print_error("Invalid ID range format: #{range_str}")
        []
      end
    end

    # =====================================================================
    # Plugin Lifecycle
    # =====================================================================
    def initialize(framework, opts = nil)
      super(framework, opts)
      # Prefer framework.datastore (from 'set TEST_ENV_RUNTIME ...') over ENV
      @runtime = RuntimeAdapter.detect(framework.datastore)
      @registry = BuiltEnvironmentRegistry.new(framework)

      ConsoleCommandDispatcher.runtime = @runtime
      ConsoleCommandDispatcher.registry = @registry

      if @runtime
        print_status("TestEnv plugin loaded. Runtime: #{@runtime.name}")
        if @runtime.respond_to?(:verify_rootless)
          ok, msg = @runtime.verify_rootless
          ok ? print_status(msg) : print_warning(msg)
        end
      else
        print_error("TestEnv plugin loaded, but no container runtime found.")
        print_error("Install Docker or Podman to use test_env.")
      end

      if @runtime
        before = @registry.list.length
        @registry.reconstruct_state(@runtime)
        added = @registry.list.length - before
        print_status("Reconstructed #{added} environment(s) from running containers.") if added > 0
      end

      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def preserve_on_exit?
      val = framework.datastore['TEST_ENV_PRESERVE'] || ENV['TEST_ENV_PRESERVE']
      return false if val.nil?
      val.to_s.downcase == 'true' || val.to_s == '1'
    end

    def cleanup
      if preserve_on_exit?
        print_status("TEST_ENV_PRESERVE is set. Leaving containers running.")
        print_status("Run 'test_env remove-all' manually when done.")
      else
        print_status("Auto-cleaning test_env environments...")
        registry = ConsoleCommandDispatcher.registry
        runtime = ConsoleCommandDispatcher.runtime

        if registry && runtime
          registry.list.each do |env|
            begin
              runtime.stop(env.container_id) if env.running?
              runtime.remove(env.container_id)
              registry.update_status(env.local_id, :removed)
            rescue => e
              print_warning("Failed to clean up environment #{env.local_id}: #{e.message}")
            end
          end
          registry.remove_all
        end
      end

      remove_console_dispatcher('TestEnv')
      ConsoleCommandDispatcher.runtime = nil
      ConsoleCommandDispatcher.registry = nil
    end

    def name
      'test_env'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end