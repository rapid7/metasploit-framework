##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Garak
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Garak AI Scanner Integration',
        'Description' => %q{
          Runs a local garak checkout to assess an AI target and imports its JSONL
          evaluation report as loot. Displays per-probe detector results without
          treating heuristic detections as confirmed vulnerabilities. Requires a
          POSIX host and a Python environment with garak's dependencies installed.
          Target connections are made by garak and do not use Metasploit routing.
        },
        'Author' => ['bwatters-r7'], # Metasploit module
        'License' => MSF_LICENSE,
        'References' => [['URL', 'https://github.com/NVIDIA/garak']],
        'Actions' => [
          ['SCAN', { 'Description' => 'Run garak locally and import its report' }],
          ['IMPORT', { 'Description' => 'Import an existing garak JSONL report' }],
          ['LIST_GENERATORS', { 'Description' => 'List available TARGET_TYPE values from local garak' }],
          ['LIST_PROBES', { 'Description' => 'List available PROBES selections from local garak' }]
        ],
        'DefaultAction' => 'SCAN',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptAddressRange.new('RHOSTS', [false, 'Remote hosts for adapters with an endpoint mapping; omit to use garak configuration']),
      OptPort.new('RPORT', [true, 'Remote endpoint port when RHOSTS is set', 80]),
      OptBool.new('SSL', [true, 'Use HTTPS for mapped remote endpoints', false]),
      OptString.new('TARGETURI', [true, 'Remote API path when RHOSTS is set', '/'], regex: %r{^/[^\s?#]*$}),
      OptString.new('TARGET_TYPE', [false, 'Garak adapter for SCAN; use ACTION LIST_GENERATORS to list available values'], conditions: ['ACTION', '==', 'SCAN']),
      OptString.new('TARGET_NAME', [false, 'Required for SCAN; leave blank to list models for supported adapters with RHOSTS'], conditions: ['ACTION', '==', 'SCAN']),
      OptString.new('PROBES', [false, 'Garak selection spec for SCAN; use ACTION LIST_PROBES (example: probes.test.Blank)'], conditions: ['ACTION', '==', 'SCAN']),
      OptInt.new('GENERATIONS', [true, 'Responses to generate per prompt', 1]),
      OptPath.new('REPORT_FILE', [false, 'Existing garak JSONL report required for IMPORT'], conditions: ['ACTION', '==', 'IMPORT'])
    ])
    register_advanced_options([
      OptPath.new('CONFIG_FILE', [false, 'Local garak YAML or JSON configuration file']),
      OptAddress.new('DB_HOST', [false, 'Target address for database attribution (omit for workspace notes)']),
      OptPort.new('DB_PORT', [false, 'Target TCP service port for database attribution']),
      OptString.new('DB_SERVICE', [false, 'Target service name for database attribution', 'http'])
    ])
    register_garak_options(checkout_default: default_garak_path)
  end

  def garak_command(prefix, endpoint: nil)
    command = [
      datastore['PYTHON'], '-u', '-m', 'garak',
      '--target_type', datastore['TARGET_TYPE'], '--spec', datastore['PROBES'],
      '--generations', datastore['GENERATIONS'].to_s, '--report_prefix', prefix
    ]
    command.concat(['--target_name', datastore['TARGET_NAME']]) if datastore['TARGET_NAME'].present?
    command.concat(['--config', File.expand_path(datastore['CONFIG_FILE'])]) if datastore['CONFIG_FILE'].present?
    if endpoint
      adapter = endpoint_adapter
      plugin, klass = adapter.split('.', 2)
      options = { plugin => { klass => { ENDPOINT_OPTIONS.fetch(adapter) => endpoint } } }
      command.concat(['--generator_options', options.to_json])
    end
    command << '--verbose' if datastore['VERBOSE']
    command
  end

  def run
    return list_garak_probes if action.name == 'LIST_PROBES'

    if action.name == 'LIST_GENERATORS'
      names = available_generators
      print_good('Available TARGET_TYPE values from the local garak installation:')
      names.each { |name| print_status("Generator: #{name}") }
      print_status('Set ACTION SCAN and TARGET_TYPE to the adapter for your model provider')
      return
    end

    if !(action.name == 'SCAN' && datastore['RHOSTS'].present?) && datastore['DB_PORT'].present? && datastore['DB_HOST'].blank?
      fail_with(Failure::BadConfig, 'DB_PORT requires DB_HOST')
    end
    if action.name == 'IMPORT'
      fail_with(Failure::BadConfig, 'REPORT_FILE is required for IMPORT') if datastore['REPORT_FILE'].blank?

      path = File.expand_path(datastore['REPORT_FILE'])
      fail_with(Failure::BadConfig, 'REPORT_FILE must be an existing local file') unless File.file?(path)

      import_report(File.binread(path))
      return
    end

    if datastore['TARGET_TYPE'].blank?
      print_error('TARGET_TYPE is required for SCAN; querying local garak for available values')
      fail_with(Failure::BadConfig, "Set TARGET_TYPE to an appropriate generator. Available TARGET_TYPE values: #{available_generators.join(', ')}")
    end
    if datastore['RHOSTS'].present?
      endpoint_adapter
      return super if datastore['TARGET_NAME'].blank? && model_discovery_supported?

      validate_scan
      if datastore['DB_HOST'].present? || datastore['DB_PORT'].present?
        print_warning('Remote scan attribution uses RHOSTS and RPORT; DB_HOST and DB_PORT are ignored')
      end
      super
    else
      scan_garak(File.expand_path(datastore['GARAK_PATH']))
    end
  rescue SystemCallError, IOError => e
    elog('Garak execution or report processing failed', error: e)
    fail_with(Failure::BadConfig, "Could not execute garak or access its reports: #{e.message}")
  end

  def endpoint_adapter
    adapter = ENDPOINT_ALIASES.fetch(datastore['TARGET_TYPE'], datastore['TARGET_TYPE'])
    unless ENDPOINT_OPTIONS.key?(adapter)
      supported = (ENDPOINT_OPTIONS.keys + ENDPOINT_ALIASES.keys).sort.join(', ')
      fail_with(Failure::BadConfig, "RHOSTS has no endpoint mapping for #{datastore['TARGET_TYPE']}. Supported adapters: #{supported}. Unset RHOSTS and configure the endpoint through CONFIG_FILE for other adapters.")
    end
    adapter
  end

  def run_host(ip)
    return list_target_names if datastore['TARGET_NAME'].blank? && model_discovery_supported?

    endpoint = "#{datastore['SSL'] ? 'https' : 'http'}://#{Rex::Socket.to_authority(ip, datastore['RPORT'])}#{datastore['TARGETURI']}"
    association = { host: ip, port: datastore['RPORT'], proto: 'tcp', sname: datastore['SSL'] ? 'https' : 'http' }
    print_status("Scanning AI endpoint #{endpoint}")
    scan_garak(File.expand_path(datastore['GARAK_PATH']), endpoint: endpoint, association: association)
  rescue SystemCallError, IOError => e
    elog('Garak execution or report processing failed', error: e)
    fail_with(Failure::BadConfig, "Could not execute garak or access its reports: #{e.message}")
  end

  def model_discovery_supported?
    ollama_target_type?(datastore['TARGET_TYPE'])
  end

  def list_target_names
    # Ollama exposes installed model names at api/tags, also used by
    # auxiliary/scanner/http/ollama_info. TARGETURI is the service base path.
    response = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, 'api', 'tags'))
    fail_with(Failure::Unreachable, 'TARGET_NAME discovery failed: the model endpoint did not respond') unless response
    unless response.code == 200
      fail_with(Failure::UnexpectedReply, "TARGET_NAME discovery failed: HTTP #{response.code}; check RHOSTS, RPORT, SSL, TARGETURI and HTTP authentication")
    end

    document = response.get_json_document
    unless document.is_a?(Hash) && document['models'].is_a?(Array)
      fail_with(Failure::UnexpectedReply, 'TARGET_NAME discovery failed: expected a JSON model list from api/tags')
    end
    names = document['models'].filter_map do |model|
      name = model['name'] if model.is_a?(Hash)
      name if name.is_a?(String) && name.present?
    end.uniq.sort
    if names.empty?
      print_warning('No TARGET_NAME values were returned; install a model on the service or obtain its name from the provider')
      return
    end
    print_good('Available TARGET_NAME values:')
    names.each { |name| print_status("Model: #{name}") }
    print_status('Set TARGET_NAME to a listed model and run again to scan')
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog('Garak model discovery failed', error: e)
    fail_with(Failure::Unreachable, "TARGET_NAME discovery failed: #{e.message}")
  end

  def available_generators
    available_plugins('generators')
  end

  def generator_names(output)
    plugin_names(output, 'generators')
  end

  def validate_scan
    if datastore['PROBES'].blank?
      fail_with(Failure::BadConfig, 'PROBES is required for SCAN. Use ACTION LIST_PROBES and optionally set PROBE_FILTER (for example, dan). Examples: probes.test.Blank for a smoke test, probes.dan.Dan_11_0 for a jailbreak probe. Set ACTION SCAN before running your chosen probes.')
    end
    if datastore['TARGET_NAME'].blank?
      guidance = if model_discovery_supported?
                   'Set RHOSTS, RPORT, SSL and TARGETURI to list models, or set TARGET_NAME explicitly'
                 else
                   'Model discovery is not supported for this TARGET_TYPE; obtain the model name or endpoint from the provider and set TARGET_NAME'
                 end
      fail_with(Failure::BadConfig, "TARGET_NAME is required for SCAN. #{guidance}")
    end
    validate_garak_runtime
    if datastore['CONFIG_FILE'].present? && !File.file?(File.expand_path(datastore['CONFIG_FILE']))
      fail_with(Failure::BadConfig, 'CONFIG_FILE must be an existing local file')
    end
    fail_with(Failure::BadConfig, 'GENERATIONS must be positive') unless datastore['GENERATIONS'].positive?
  end

  def scan_garak(checkout, association: nil, endpoint: nil)
    validate_scan
    association ||= database_association
    Dir.mktmpdir('msf-garak-') do |directory|
      prefix = File.join(directory, 'scan')
      output_path = File.join(directory, 'console.log')
      print_status('Running garak locally; this can take several minutes')
      status = execute_garak(garak_command(prefix, endpoint: endpoint), checkout, output_path)
      if File.file?(output_path)
        console = File.binread(output_path)
        path = store_loot('garak.console', 'text/plain', association[:host], console, 'garak-console.log')
        print_status("Garak console log saved to #{path}")
        console.each_line { |line| vprint_status("Garak: #{line.chomp}") }
      end
      report_path = "#{prefix}.report.jsonl"
      if File.file?(report_path)
        import_report(File.binread(report_path), association: association)
      else
        print_warning('Garak did not produce a JSONL report')
      end
      fail_with(Failure::TimeoutExpired, 'Garak exceeded RunTimeout; partial results were preserved') unless status
      fail_with(Failure::Unknown, "Garak failed (#{status}); inspect the console log and Python dependencies") unless status.success?
      fail_with(Failure::UnexpectedReply, 'Garak exited without a JSONL report') unless File.file?(report_path)
    end
  end

  def database_association
    return {} if datastore['DB_HOST'].blank?

    association = { host: datastore['DB_HOST'] }
    association.merge!(port: datastore['DB_PORT'], proto: 'tcp', sname: datastore['DB_SERVICE']) if datastore['DB_PORT'].present?
    association
  end

  def import_report(report, association: nil)
    association ||= database_association
    path = store_loot('garak.report', 'application/x-ndjson', association[:host], report, 'garak-report.jsonl')
    print_good("Garak report saved to #{path}")
    summarize_report(report, association: association)
  end

  def summarize_report(report, association: nil)
    evaluations = 0
    complete = false
    records = []
    valid_evaluations = []
    report.each_line.with_index(1) do |line, number|
      next if line.strip.empty?

      begin
        record = JSON.parse(line)
      rescue JSON::ParserError => e
        elog("Invalid garak JSONL record at line #{number}", error: e)
        print_warning("Skipping invalid JSON at report line #{number}")
        next
      end
      next unless record.is_a?(Hash)

      records << record
      complete ||= record['entry_type'] == 'completion'
      next unless record['entry_type'] == 'eval'

      passed = record['passed']
      # Older garak releases called total_evaluated 'total'.
      total = record.fetch('total_evaluated', record['total'])
      unless passed.is_a?(Integer) && total.is_a?(Integer) && passed >= 0 && total >= passed && record['probe'].is_a?(String) && record['detector'].is_a?(String)
        print_warning("Skipping invalid evaluation at report line #{number}")
        next
      end
      evaluations += 1
      valid_evaluations << record.merge('failed' => total - passed, 'total_evaluated' => total)
      result = "Probe #{record['probe']} / #{record['detector']}: #{total - passed} failed, #{passed} passed, #{total} evaluated"
      if total > passed
        print_warning(result)
      else
        print_status(result)
      end
    end
    print_warning('Garak report is incomplete (no completion record)') unless complete
    print_warning('Garak report contains no valid evaluations') if evaluations.zero?
    print_status("Imported #{evaluations} garak evaluations")
    report_database(records, valid_evaluations, Rex::Text.sha2(report), association: association)
  end

  def report_database(records, evaluations, report_hash, association: nil)
    unless db
      print_warning('Database is not connected; garak results are available in loot only')
      return
    end
    if evaluations.empty?
      print_warning('Skipping database import because the report has no valid evaluations')
      return
    end

    setup = records.find { |record| record['entry_type'] == 'start_run setup' } || {}
    init = records.find { |record| record['entry_type'] == 'init' } || {}
    completion = records.find { |record| record['entry_type'] == 'completion' } || {}
    context = {
      'run_id' => init['run'] || setup['transient.run_id'] || report_hash,
      'report_sha256' => report_hash,
      'garak_version' => init['garak_version'] || setup['_config.version'],
      'target_type' => setup['plugins.target_type'] || setup['plugins.model_type'],
      'target_name' => setup['plugins.target_name'] || setup['plugins.model_name']
    }
    association ||= database_association
    if association[:host]
      report_host(host: association[:host])
      if association[:port]
        report_service(host: association[:host], port: association[:port], proto: association[:proto], name: association[:sname])
      end
    end

    report_note(association.merge(
      type: 'garak.run', update: :unique_data,
      data: context.merge('start_time' => init['start_time'] || setup['transient.starttime_iso'],
                          'end_time' => completion['end_time'], 'complete' => !completion.empty?,
                          'evaluation_count' => evaluations.length)
    ))
    evaluations.each do |evaluation|
      report_note(association.merge(type: 'garak.evaluation', update: :unique_data, data: context.merge('evaluation' => evaluation)))
    end
    attempts = records.select { |record| record['entry_type'] == 'attempt' && record['status'] == 2 }
    attempts.each do |attempt|
      report_note(association.merge(type: 'garak.attempt', update: :unique_data, data: context.merge('attempt' => attempt)))
    end
    print_good("Saved garak run, #{evaluations.length} evaluations and #{attempts.length} completed attempts to the database")
  end
end
