# frozen_string_literal: true

require 'tmpdir'
require 'timeout'
require 'json'
require 'yaml'
require 'shellwords'

# Shared adapter metadata for garak execution and service discovery modules.
module Msf::Auxiliary::Garak
  # Default sibling checkout used by local garak actions.
  # @return [String] Checkout path
  def default_garak_path
    File.expand_path('../garak', Msf::Config.install_root)
  end

  # Register local runtime and listing controls.
  # @param checkout_default [String, nil] Explicit option default, if required
  # @return [void]
  def register_garak_options(checkout_default: nil)
    register_garak_runtime_options(checkout_default: checkout_default)
    register_options([
      Msf::OptString.new('PROBE_FILTER', [false, 'Case-insensitive substring for LIST_PROBES, such as dan or encoding'], conditions: ['ACTION', '==', 'LIST_PROBES'])
    ])
  end

  # Register local runtime controls without adding listing actions or filters.
  # @param checkout_default [String, nil] Explicit checkout option default
  # @return [void]
  def register_garak_runtime_options(checkout_default: nil)
    register_options([
      Msf::OptPath.new('GARAK_PATH', [!checkout_default.nil?, 'Local garak checkout; defaults to the garak directory beside Metasploit', checkout_default]),
      Msf::OptString.new('PYTHON', [true, 'Python executable with garak dependencies installed', 'python3'])
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
  # @param rest_api_key [String, nil] REST credential to include in copyable commands only
  # @return [String] Saved loot path
  def store_garak_yaml(ip:, namespace:, config:, target_type:, target_name:, rest_api_key: nil)
    settings = config.merge('plugins' => config.fetch('plugins').merge('target_type' => target_type, 'target_name' => target_name))
    path = store_loot("#{namespace}.garak.config.yaml", 'application/x-yaml', ip, YAML.dump(settings), "#{namespace}_garak.yaml", 'Garak target configuration')
    print_good("Garak YAML configuration saved: #{path}")
    selections = settings.dig('run', 'spec', 'include')
    probes = selections ? selections.join(',') : 'probes.test.Blank'
    python = Shellwords.escape(datastore['PYTHON'].presence || 'python3')
    print_garak_scan_command(config_path: path, target_type: target_type, target_name: target_name, probes: probes, rest_api_key: rest_api_key)
    python = "REST_API_KEY=#{Shellwords.escape(rest_api_key)} #{python}" if rest_api_key.present?
    if selections
      print_status("Or run in a terminal: #{python} -m garak --config #{path}")
    else
      print_status("Or run in a terminal: #{python} -m garak --config #{path} --spec probes.test.Blank")
      print_status('This example tests connectivity only; use garak_list_probes to select security probes')
    end
    path
  end

  # Print a complete scan command without storing credentials in configuration loot.
  # @param config_path [String] Saved generator configuration
  # @param target_type [String] Garak generator name
  # @param target_name [String] Model name or REST URL
  # @param probes [String] Probe selection
  # @param rest_api_key [String, nil] REST credential for the scan child process
  # @return [void]
  def print_garak_scan_command(config_path:, target_type:, target_name:, probes: 'probes.test.Blank', rest_api_key: nil)
    options = { 'TARGET_TYPE' => target_type, 'TARGET_NAME' => target_name, 'CONFIG_FILE' => config_path, 'PROBES' => probes, 'PYTHON' => datastore['PYTHON'].presence || 'python3' }
    selections = probes.split(',').map(&:strip).reject(&:empty?).uniq
    # Listings contain both family selectors and their individual probes; count
    # the individual probes without counting the family a second time.
    probe_count = selections.count { |name| selections.none? { |other| other.start_with?("#{name}.") } }
    options['RunTimeout'] = (300 * [probe_count, 1].max).to_s
    options['GARAK_PATH'] = datastore['GARAK_PATH'] if datastore['GARAK_PATH'].present?
    options['REST_API_KEY'] = rest_api_key if rest_api_key.present?
    options['VERBOSE'] = 'true'
    print_status("Use garak_scan #{options.map { |key, value| "#{key}=#{Shellwords.escape(value)}" }.join(' ')}")
  end

  # Read garak's plugin metadata without instantiating probes or generators.
  # @param target_types [Array<String>] Generator names to inspect
  # @return [Hash] Probe and generator metadata
  def garak_probe_metadata(target_types: OLLAMA_TARGET_TYPES)
    checkout = validate_garak_runtime
    script = File.join(Msf::Config.data_directory, 'auxiliary', 'garak', 'probe_metadata.py')
    Dir.mktmpdir('msf-garak-metadata-') do |directory|
      destination = File.join(directory, 'metadata.json')
      output = File.join(directory, 'console.log')
      status = execute_garak([datastore['PYTHON'], script, destination, *target_types], checkout, output)
      fail_with(Msf::Module::Failure::TimeoutExpired, 'Garak metadata query exceeded RunTimeout') unless status
      unless status.success? && File.file?(destination)
        File.foreach(output) { |line| vprint_status("Garak: #{line.chomp}") } if File.file?(output)
        fail_with(Msf::Module::Failure::BadConfig, 'Could not read garak metadata; check GARAK_PATH, PYTHON and installed dependencies')
      end
      metadata = JSON.parse(File.binread(destination))
      unless metadata.is_a?(Hash) && metadata['probes'].is_a?(Hash) && !metadata['probes'].empty? && metadata['generators'].is_a?(Hash)
        fail_with(Msf::Module::Failure::UnexpectedReply, 'Garak returned invalid probe metadata')
      end
      metadata
    end
  rescue JSON::ParserError => e
    elog('Could not parse garak probe metadata', error: e)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Garak returned malformed metadata JSON')
  end

  # Compare declared probe inputs with model and generator inputs. Unknown
  # capabilities do not imply support or incompatibility.
  # @param capabilities [Array<String>, nil] Ollama capabilities or unknown
  # @param metadata [Hash] Local garak metadata
  # @param target_types [Array<String>] Generator names to compare
  # @return [Hash] Model inputs and per-probe compatibility for each adapter
  def garak_probe_suggestions(capabilities, metadata, target_types: OLLAMA_TARGET_TYPES)
    capabilities = nil unless capabilities.is_a?(Array) && !capabilities.empty? && capabilities.all? { |value| value.is_a?(String) }
    # Ollama capability names originate in server/images.go:
    # https://github.com/ollama/ollama/blob/main/server/images.go
    inputs = []
    inputs << 'text' if capabilities&.include?('completion')
    inputs << 'image' if capabilities&.include?('vision')
    # Only these capability names have a defined interpretation here. New
    # capability names may imply additional inputs, so retain uncertainty.
    complete = capabilities && (capabilities - %w[completion vision embedding tools thinking]).empty?
    probes = metadata['probes'].sort.to_h.transform_values do |probe|
      required = garak_input_types(probe)
      target_types.to_h do |adapter|
        supported = garak_input_types(metadata['generators'][adapter])
        status = if required.nil? || capabilities.nil?
                   'unknown'
                 elsif complete && (!capabilities.include?('completion') || !(required - inputs).empty?)
                   'incompatible'
                 elsif supported.nil?
                   'unknown'
                 elsif !(required - supported).empty?
                   'incompatible'
                 elsif capabilities.include?('completion') && (required - inputs).empty?
                   'suggested'
                 else
                   'unknown'
                 end
        [adapter, status]
      end
    end
    { 'capabilities' => capabilities, 'input_types' => inputs, 'probes' => probes }
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
    result.merge!('target_name' => name, 'garak_version' => metadata['garak_version'])
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
    inputs = plugin['inputs'] if plugin.is_a?(Hash)
    return nil unless inputs.is_a?(Array) && !inputs.empty? && inputs.all? { |value| value.is_a?(String) }
    return nil unless (inputs - %w[text image audio video 3d]).empty?

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

  # List plugins using the configured local garak checkout.
  # @param category [String] CLI plugin category
  # @return [Array<String>] Sorted plugin names
  def available_plugins(category)
    checkout = validate_garak_runtime
    Dir.mktmpdir('msf-garak-plugins-') do |directory|
      output_path = File.join(directory, 'plugins.log')
      # Keep garak's listing in plain-list mode: --verbose changes it to a
      # metadata table. See garak.command.print_plugins in the local checkout.
      command = [datastore['PYTHON'], '-u', '-m', 'garak', "--list_#{category}"]
      status = execute_garak(command, checkout, output_path)
      output = File.file?(output_path) ? File.binread(output_path).force_encoding(::Encoding::UTF_8).scrub : ''
      fail_with(Msf::Module::Failure::TimeoutExpired, "Listing garak #{category} exceeded RunTimeout") unless status
      unless status.success?
        output.each_line { |line| vprint_status("Garak: #{line.chomp}") }
        fail_with(Msf::Module::Failure::BadConfig, "Could not list garak #{category}; check PYTHON, GARAK_PATH and installed dependencies")
      end
      names = plugin_names(output, category)
      fail_with(Msf::Module::Failure::UnexpectedReply, "Garak returned no recognizable #{category}; check the installed garak CLI version") if names.empty?

      names
    end
  end

  # Parse the plain-list garak CLI output.
  # @param output [String] CLI output
  # @param category [String] Plugin category
  # @return [Array<String>] Sorted unique names
  def plugin_names(output, category)
    # The CLI prefixes each plugin/alias with its category and may append
    # activation markers. ANSI colors are presentation, not part of its name.
    output.gsub(%r{\e\[[0-?]*[ -/]*[@-~]}, '').each_line.filter_map do |line|
      line.match(/^#{Regexp.escape(category)}:\s+([A-Za-z_][A-Za-z0-9_.]*)\s*.*$/)&.[](1)
    end.uniq.sort
  end

  # Validate local runtime prerequisites.
  # @return [String] Absolute checkout path
  def validate_garak_runtime
    fail_with(Msf::Module::Failure::BadConfig, 'Garak process management requires a POSIX host') if Gem.win_platform?
    checkout = File.expand_path(datastore['GARAK_PATH'].presence || default_garak_path)
    unless File.file?(File.join(checkout, 'garak', '__main__.py'))
      fail_with(Msf::Module::Failure::BadConfig, 'GARAK_PATH must contain a garak source checkout')
    end
    fail_with(Msf::Module::Failure::BadConfig, 'RunTimeout must be positive') unless datastore['RunTimeout'].positive?
    validate_garak_python(checkout)
    checkout
  end

  # Check that the configured interpreter can start the checkout's CLI.
  # @param checkout [String] Absolute garak checkout path
  # @return [void]
  def validate_garak_python(checkout)
    python = datastore['PYTHON'].to_s
    guidance = 'Set PYTHON to the Python executable in an environment with garak dependencies installed (plugin: garak_set PYTHON /path/to/garak/.venv/bin/python). Install dependencies with that interpreter: /path/to/garak/.venv/bin/python -m pip install -e /path/to/garak'
    fail_with(Msf::Module::Failure::BadConfig, "PYTHON is empty. #{guidance}") if python.strip.empty?

    Dir.mktmpdir('msf-garak-python-') do |directory|
      output_path = File.join(directory, 'python.log')
      status = execute_garak([python, '-m', 'garak', '--version'], checkout, output_path)
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
  # @param checkout [String] Local checkout path
  # @param output_path [String] Destination for console output
  # @param environment [Hash<String, String>] Additional child process environment variables
  # @return [Process::Status, nil] Exit status, or nil on timeout
  def execute_garak(command, checkout, output_path, environment: {})
    # A separate POSIX process group lets cancellation also stop garak workers.
    pid = Process.spawn(environment.merge('PYTHONPATH' => checkout), *command, chdir: checkout,
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
  # @return [Array<String>] Qualified probe names
  def garak_probe_names
    names = available_plugins('probes').map { |name| "probes.#{name}" }
    filter = datastore['PROBE_FILTER'].to_s.strip.downcase
    names.select! { |name| name.downcase.include?(filter) } unless filter.empty?
    names
  end

  # Print probe selections with an optional substring filter.
  # @param names [Array<String>, nil] Already filtered selections, or query Garak
  # @return [void]
  def list_garak_probes(names: nil)
    names ||= garak_probe_names
    if names.empty?
      print_warning('No probes matched PROBE_FILTER; change or unset the filter and run again')
      return
    end
    print_good('Available PROBES selections from the local garak installation:')
    names.each { |name| print_status("Probe: #{name}") }
    print_status('Use garak_scan with PROBES set to a probe, a family, or comma-separated selections')
  end
end
