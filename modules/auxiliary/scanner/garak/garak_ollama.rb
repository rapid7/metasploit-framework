##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Garak
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Garak Ollama Target Discovery',
        'Description' => %q{
          Identifies Ollama using its service banner and lists installed models
          through its API. Reports candidate garak TARGET_TYPE adapters and full
          TARGET_NAME values for use with the garak integration module. This
          scanner queries model capabilities and compares them with local garak
          probe and adapter metadata to suggest compatible input types. These
          suggestions do not verify generation behavior. Set SUGGEST_PROBES false
          to discover targets without a local garak installation.
        },
        'Author' => ['bwatters-r7'], # Metasploit module
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://docs.ollama.com/api/tags'],
          ['URL', 'https://github.com/NVIDIA/garak/blob/main/garak/generators/ollama.py']
        ],
        'DefaultOptions' => { 'RPORT' => 11434 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the Ollama service', '/']),
      OptBool.new('SUGGEST_PROBES', [true, 'Query model capabilities and suggest probes using local garak metadata', true]),
      OptString.new('PROBE_FILTER', [false, 'Optional case-insensitive substring to narrow probe suggestions'])
    ])
    register_garak_runtime_options
  end

  def run
    @probe_metadata = nil
    @probe_metadata = garak_probe_metadata if datastore['SUGGEST_PROBES']
    super
  rescue SystemCallError, IOError => e
    elog('Garak metadata query failed', error: e)
    fail_with(Failure::BadConfig, "Could not read garak metadata: #{e.message}; check PYTHON and GARAK_PATH, or disable SUGGEST_PROBES")
  end

  def run_host(ip)
    # Same service banner used by auxiliary/scanner/http/ollama_info.
    response = send_request_cgi({ 'uri' => normalize_uri(target_uri.path) })
    unless response && response.code == 200 && response.body.to_s.strip == 'Ollama is running'
      vprint_status('Ollama banner was not detected; no garak targets reported')
      return
    end

    print_good('Ollama service detected')
    service_name = ssl ? 'https' : 'http'
    report_service(host: ip, port: rport, proto: 'tcp', name: service_name, info: 'Ollama')
    types_table = Rex::Text::Table.new(
      'Header' => 'Candidate target types (generation support has not been tested)',
      'Indent' => 2,
      'Columns' => ['TARGET_TYPE', 'Alias for']
    )
    OLLAMA_TARGET_TYPES.each { |adapter| types_table << [adapter, ''] }
    types_table << ['ollama', ENDPOINT_ALIASES.fetch('ollama')]
    print_status(types_table.to_s)

    response = send_request_cgi({ 'uri' => normalize_uri(target_uri.path, 'api', 'tags') })
    fail_with(Failure::Unreachable, 'Ollama model discovery failed: api/tags did not respond') unless response
    unless response.code == 200
      fail_with(Failure::UnexpectedReply, "Ollama model discovery failed: api/tags returned HTTP #{response.code}; check HTTP authentication and TARGETURI")
    end

    document = response.get_json_document
    unless document.is_a?(Hash) && document['models'].is_a?(Array) && document['models'].all? { |model| model.is_a?(Hash) && model['name'].is_a?(String) && model['name'].present? }
      fail_with(Failure::UnexpectedReply, 'Ollama model discovery failed: api/tags returned an invalid model list')
    end

    names = document['models'].map { |model| model['name'] }.uniq.sort
    report_note(
      host: ip, port: rport, proto: 'tcp', sname: service_name,
      type: 'ollama.garak.targets', update: :unique_data,
      data: { base_path: target_uri.path, target_types: OLLAMA_TARGET_TYPES, target_names: names }
    )
    if names.empty?
      print_warning('No TARGET_NAME values are available; Ollama returned no installed models')
      return
    end

    names_table = Rex::Text::Table.new('Header' => 'Available target names', 'Indent' => 2, 'Columns' => ['TARGET_NAME'])
    names.each { |name| names_table << [name] }
    print_status(names_table.to_s)
    names.each { |name| suggest_model_probes(ip, name) } if datastore['SUGGEST_PROBES']
    print_status('Use these values with auxiliary/scanner/garak/garak_integration and the same RHOSTS, RPORT, SSL and TARGETURI')
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog('Ollama discovery request failed', error: e)
    vprint_error("Ollama discovery request failed: #{e.message}")
  end

  def model_capabilities(name)
    response = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'show'),
      'ctype' => 'application/json',
      'data' => { model: name }.to_json
    })
    unless response && response.code == 200
      print_warning("Capabilities for #{name} are unknown: api/show #{response ? "returned HTTP #{response.code}" : 'did not respond'}")
      return nil
    end
    document = response.get_json_document
    capabilities = document['capabilities'] if document.is_a?(Hash)
    unless capabilities.is_a?(Array) && !capabilities.empty? && capabilities.all? { |value| value.is_a?(String) }
      print_warning("Capabilities for #{name} are unknown: api/show did not return a valid capabilities list")
      return nil
    end
    capabilities.uniq.sort
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog("Ollama capability query failed for #{name}", error: e)
    print_warning("Capabilities for #{name} are unknown: #{e.message}")
    nil
  end

  def suggest_model_probes(ip, name)
    capabilities = model_capabilities(name)
    result = garak_probe_suggestions(capabilities, @probe_metadata)
    report_garak_probe_suggestions(ip: ip, name: name, capabilities: capabilities, result: result, metadata: @probe_metadata, namespace: 'ollama')
  end
end
