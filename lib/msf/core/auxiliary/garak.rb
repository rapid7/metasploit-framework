# frozen_string_literal: true

require 'tmpdir'
require 'timeout'
require 'json'
require 'yaml'
require 'shellwords'

# Shared adapter metadata for garak execution and service discovery modules.
module Msf::Auxiliary::Garak
  # Register local runtime and listing controls.
  # @return [void]
  def register_garak_options
    register_garak_runtime_options
    register_options([
      Msf::OptString.new('PROBE_FILTER', [false, 'Case-insensitive substring for LIST_PROBES, such as dan or encoding'], conditions: ['ACTION', '==', 'LIST_PROBES'])
    ])
  end

  # Register local runtime controls without adding listing actions or filters.
  # @return [void]
  def register_garak_runtime_options
    register_options([
      Msf::OptString.new('PYTHON', [true, 'Python executable with the garak package installed', 'python3'])
    ])
    register_advanced_options([
      Msf::OptInt.new('RunTimeout', [true, 'Maximum garak runtime in seconds', 3600])
    ])
  end

  # Register optional discovery configuration output.
  # @return [void]
  def register_garak_yaml_option
    register_options([
      Msf::OptBool.new('OUTPUT_YAML', [true, 'Save a garak YAML configuration for each discovered target', false])
    ])
  end

  # Save a complete garak configuration without requiring a local garak runtime.
  # @param ip [String] Discovered host
  # @param namespace [String] Service name for loot
  # @param config [Hash] Generator configuration containing string keys
  # @param target_type [String] Garak generator name
  # @param target_name [String] Model name or REST URL
  # @param key_env_var [String, nil] Environment variable used by the REST configuration
  # @return [String] Saved loot path
  def store_garak_yaml(ip:, namespace:, config:, target_type:, target_name:, key_env_var: nil)
    settings = config.merge('plugins' => config.fetch('plugins').merge('target_type' => target_type, 'target_name' => target_name))
    path = store_loot("#{namespace}.garak.config.yaml", 'application/x-yaml', ip, YAML.dump(settings), "#{namespace}_garak.yaml", 'Garak target configuration')
    print_good("Garak YAML configuration saved: #{path}")
    spec = settings.dig('run', 'spec')
    python = Shellwords.escape(datastore['PYTHON'].presence || 'python3')
    print_garak_scan_command(config_path: path, target_type: target_type, target_name: target_name, probes: spec ? nil : 'probes.test.Blank', key_env_var: key_env_var)
    terminal_config = Shellwords.escape(path)
    if spec
      print_status("Or run in a terminal: #{python} -m garak --config #{terminal_config}")
    else
      print_status("Or run in a terminal: #{python} -m garak --config #{terminal_config} --spec probes.test.Blank")
      print_status('This example tests connectivity only; use garak_list_probes to select security probes')
    end
    path
  end

  # Print a complete scan command without storing credentials in configuration loot.
  # @param config_path [String] Saved generator configuration
  # @param target_type [String] Garak generator name
  # @param target_name [String] Model name or REST URL
  # @param probes [String, nil] CLI probe selection; omit to retain the configuration spec
  # @param key_env_var [String, nil] Environment variable used by the REST configuration
  # @return [void]
  def print_garak_scan_command(config_path:, target_type:, target_name:, probes: 'probes.test.Blank', key_env_var: nil)
    options = { 'TARGET_TYPE' => target_type, 'TARGET_NAME' => target_name, 'CONFIG_FILE' => config_path, 'PYTHON' => datastore['PYTHON'].presence || 'python3' }
    options['PROBES'] = probes if probes.present?
    options['REST_API_KEY_ENV'] = key_env_var if key_env_var.present?
    options['VERBOSE'] = 'true'
    print_status("Use garak_scan #{options.map { |key, value| "#{key}=#{Shellwords.escape(value)}" }.join(' ')}")
  end

  # Read garak's plugin metadata without instantiating probes or generators.
  # @param target_types [Array<String>] Generator names to inspect
  # @return [Hash] Probe and generator metadata
  def garak_probe_metadata(target_types: OLLAMA_TARGET_TYPES)
    cache = garak_plugin_cache
    generators = target_types.to_h { |name| [name, cache['generators']["generators.#{name}"]] }
    { 'probes' => cache['probes'], 'generators' => generators }
  end

  # Compare declared probe inputs with model and generator inputs. Unknown
  # capabilities do not imply support or incompatibility.
  # @param input_types [Array<String>, nil] Model input modalities or unknown
  # @param metadata [Hash] Local garak metadata
  # @param target_types [Array<String>] Generator names to compare
  # @return [Hash] Model inputs and per-probe compatibility for each adapter
  def garak_probe_suggestions(input_types, metadata, target_types: OLLAMA_TARGET_TYPES)
    inputs = input_types if input_types.is_a?(Array) && input_types.all? { |value| value.is_a?(String) }
    probes = metadata['probes'].sort.to_h.transform_values do |probe|
      required = garak_input_types(probe)
      target_types.to_h do |adapter|
        supported = garak_input_types(metadata['generators'][adapter])
        status = if required.nil? || inputs.nil?
                   'unknown'
                 elsif supported.nil?
                   'unknown'
                 elsif !(required - inputs).empty? || !(required - supported).empty?
                   'incompatible'
                 else
                   'suggested'
                 end
        [adapter, status]
      end
    end
    { 'input_types' => inputs || [], 'probes' => probes }
  end

  # Display and persist a model's input compatibility results.
  # @param ip [String] Target address
  # @param name [String] Model name
  # @param capabilities [Array<String>, nil] Normalized model capabilities
  # @param result [Hash] Compatibility comparison
  # @param metadata [Hash] Local garak metadata
  # @param namespace [String] Provider name for loot and database notes
  # @return [void]
  def report_garak_probe_suggestions(ip:, name:, capabilities:, result:, metadata:, namespace:)
    result.merge!('target_name' => name)
    filter = datastore['PROBE_FILTER'].to_s.strip.downcase
    result['probes'].select! { |probe, _| probe.downcase.include?(filter) } unless filter.empty?
    print_status("Model #{name} capabilities: #{capabilities ? capabilities.join(', ') : 'unknown'}; identified input types: #{result['input_types'].presence&.join(', ') || 'unknown'}")
    table = Rex::Text::Table.new('Header' => "Suggested probes for #{name} (input compatibility only)", 'Indent' => 2, 'Columns' => ['PROBES', 'Inputs', 'TARGET_TYPE'])
    suggested = 0
    unknown = 0
    result['probes'].each do |probe, adapters|
      matches = adapters.select { |_, status| status == 'suggested' }.keys
      unknown += 1 if adapters.value?('unknown')
      next if matches.empty?

      suggested += 1
      table << [probe, garak_input_types(metadata['probes'][probe]).join(', '), matches.join(', ')]
    end
    print_status(table.to_s) if suggested.positive?
    print_status("Probe comparison for #{name}: #{suggested} suggested, #{unknown} with unknown compatibility, #{result['probes'].length} considered")
    print_warning('No probes matched PROBE_FILTER; change or unset the filter') if result['probes'].empty?
    print_warning('Probe suggestions compare declared input types only; dependencies, languages and behavior still need validation')
    path = store_loot("#{namespace}.garak.probes", 'application/json', ip, result.to_json, 'garak-probe-suggestions.json')
    print_status("Full probe compatibility results saved to #{path}")
    report_note(
      host: ip, port: rport, proto: 'tcp', sname: ssl ? 'https' : 'http',
      type: "#{namespace}.garak.probes", update: :unique_data, data: result
    )
  end

  # Normalize a plugin's declared input types without assuming text defaults.
  # @param plugin [Hash, nil] Extracted plugin metadata
  # @return [Array<String>, nil] Declared inputs, or nil for unknown metadata
  def garak_input_types(plugin)
    inputs = plugin.dig('modality', 'in') if plugin.is_a?(Hash)
    return nil unless inputs.is_a?(Array) && !inputs.empty? && inputs.all? { |value| value.is_a?(String) }

    inputs.uniq.sort
  end

  # Adapter names and configuration fields from garak/generators/{ollama,rest,openai}.py:
  # https://github.com/NVIDIA/garak/tree/main/garak/generators
  OLLAMA_TARGET_TYPES = %w[ollama.OllamaGeneratorChat ollama.OllamaGenerator].freeze
  OPENAI_COMPATIBLE_TARGET_TYPE = 'openai.OpenAICompatible'
  ENDPOINT_OPTIONS = OLLAMA_TARGET_TYPES.to_h { |adapter| [adapter, 'host'] }.merge(
    'rest.RestGenerator' => 'uri',
    OPENAI_COMPATIBLE_TARGET_TYPE => 'uri'
  ).freeze
  ENDPOINT_ALIASES = {
    'ollama' => OLLAMA_TARGET_TYPES.first,
    'rest' => 'rest.RestGenerator'
  }.freeze

  # Resolve whether a garak adapter supports Ollama model discovery.
  # @param target_type [String] A full generator name or garak alias
  # @return [Boolean] Whether the adapter uses the Ollama API
  def ollama_target_type?(target_type)
    OLLAMA_TARGET_TYPES.include?(ENDPOINT_ALIASES.fetch(target_type, target_type))
  end

  # List plugins using garak's versioned metadata cache.
  # @param category [String] CLI plugin category
  # @param active_only [Boolean] Omit plugins that Garak marks inactive
  # @return [Array<String>] Sorted plugin names
  def available_plugins(category, active_only: false)
    prefix = "#{category}."
    names = garak_plugin_cache.fetch(category).filter_map do |name, metadata|
      next if active_only && metadata.is_a?(Hash) && metadata['active'] == false

      name.delete_prefix(prefix) if name.start_with?(prefix)
    end
    (names + names.map { |name| name.split('.', 2).first }).uniq.sort
  end

  # Build and read garak's plugin cache in an isolated cache directory.
  # @return [Hash] Plugin metadata keyed by category and fully qualified name
  def garak_plugin_cache
    validate_garak_runtime
    @garak_plugin_cache ||= Dir.mktmpdir('msf-garak-metadata-') do |directory|
      output_path = File.join(directory, 'console.log')
      status = execute_garak([datastore['PYTHON'], '-u', '-m', 'garak', '--list_probes'], output_path)
      fail_with(Msf::Module::Failure::TimeoutExpired, 'Garak metadata query exceeded RunTimeout') unless status
      unless status.success?
        File.foreach(output_path) { |line| vprint_status("Garak: #{line.chomp}") } if File.file?(output_path)
        fail_with(Msf::Module::Failure::BadConfig, 'Could not read garak metadata; check PYTHON and the installed package')
      end

      cache_path = File.join(directory, 'garak', 'resources', 'plugin_cache.json')
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Garak did not create its plugin metadata cache') unless File.file?(cache_path)

      cache = JSON.parse(File.binread(cache_path))
      unless %w[probes detectors generators harnesses buffs].all? { |key| cache[key].is_a?(Hash) } && cache['probes'].present?
        fail_with(Msf::Module::Failure::UnexpectedReply, 'Garak returned invalid plugin metadata')
      end
      cache
    end
  rescue JSON::ParserError => e
    elog('Could not parse garak plugin metadata', error: e)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Garak returned malformed plugin metadata JSON')
  end

  # Validate local runtime prerequisites.
  # @return [void]
  def validate_garak_runtime
    fail_with(Msf::Module::Failure::BadConfig, 'Garak process management requires a POSIX host') if Gem.win_platform?
    fail_with(Msf::Module::Failure::BadConfig, 'RunTimeout must be positive') unless datastore['RunTimeout'].positive?
    validate_garak_python
    nil
  end

  # Check that the configured interpreter can start garak's CLI.
  # @return [void]
  def validate_garak_python
    python = datastore['PYTHON'].to_s
    guidance = 'Set PYTHON to an interpreter with garak installed (plugin: garak_set PYTHON /path/to/venv/bin/python). Install the released package with that interpreter: /path/to/venv/bin/python -m pip install garak'
    fail_with(Msf::Module::Failure::BadConfig, "PYTHON is empty. #{guidance}") if python.strip.empty?

    Dir.mktmpdir('msf-garak-python-') do |directory|
      output_path = File.join(directory, 'python.log')
      status = execute_garak([python, '-m', 'garak', '--version'], output_path)
      fail_with(Msf::Module::Failure::TimeoutExpired, "Garak startup check using PYTHON=#{python} exceeded RunTimeout") unless status
      next if status.success?

      output = File.file?(output_path) ? File.binread(output_path).force_encoding(::Encoding::UTF_8).scrub : ''
      output.each_line { |line| vprint_status("Garak: #{line.chomp}") }
      reason = output.lines.reverse.find { |line| line.match?(/\A(?:[\w.]*Error|[\w.]*Exception):/) }&.strip || "Process exited with status #{status.exitstatus}"
      fail_with(Msf::Module::Failure::BadConfig, "Garak cannot start using PYTHON=#{python}: #{reason}. #{guidance}")
    end
  rescue Errno::ENOENT, Errno::EACCES, Errno::ENOEXEC => e
    elog('Could not execute garak Python interpreter', error: e)
    fail_with(Msf::Module::Failure::BadConfig, "Cannot execute PYTHON=#{python}: #{e.message}. #{guidance}")
  end

  # Run garak with a bounded runtime and process-group cleanup.
  # @param command [Array<String>] Executable and literal arguments
  # @param output_path [String] Destination for console output
  # @param environment [Hash<String, String>] Additional child process environment variables
  # @return [Process::Status, nil] Exit status, or nil on timeout
  def execute_garak(command, output_path, environment: {})
    # Garak stores logs, reports, metadata, and some downloaded resources under
    # XDG data/cache paths. Give each process an isolated workspace so jobs do
    # not contend for these files or mutate the operator's Garak state.
    workspace = File.dirname(output_path)
    child_environment = environment.merge('XDG_DATA_HOME' => workspace, 'XDG_CACHE_HOME' => workspace)
    # A separate POSIX process group lets cancellation also stop garak workers.
    pid = Process.spawn(child_environment, *command, chdir: workspace,
                                                     in: File::NULL, out: output_path, err: %i[child out], pgroup: true)
    Timeout.timeout(datastore['RunTimeout']) { Process.wait2(pid).last }
  rescue Timeout::Error
    nil
  ensure
    if pid
      begin
        Process.kill('KILL', -pid)
      rescue Errno::ESRCH
        # The process group has already exited.
      end
      begin
        Process.wait(pid)
      rescue Errno::ECHILD
        # The successful wait above already reaped the child.
      end
    end
  end

  # Read probe selections with the configured substring filter.
  # @param active_only [Boolean] Omit probes that Garak marks inactive
  # @return [Array<String>] Qualified probe names
  def garak_probe_names(active_only: true)
    names = available_plugins('probes', active_only: active_only).map { |name| "probes.#{name}" }
    filter = datastore['PROBE_FILTER'].to_s.strip.downcase
    names.select! { |name| name.downcase.include?(filter) } unless filter.empty?
    names
  end

  # Print probe selections with an optional substring filter.
  # @param names [Array<String>, nil] Already filtered selections, or query Garak
  # @return [void]
  def list_garak_probes(names: nil)
    # Inactive probes remain useful when selected explicitly, so LIST_PROBES
    # shows every installed selection while generated configs use active probes.
    names ||= garak_probe_names(active_only: false)
    if names.empty?
      print_warning('No probes matched PROBE_FILTER; change or unset the filter and run again')
      return
    end
    print_good('Available PROBES selections from the local garak installation:')
    names.each { |name| print_status("Probe: #{name}") }
    print_status('Use garak_scan with PROBES set to a probe, a family, or comma-separated selections')
  end
end
