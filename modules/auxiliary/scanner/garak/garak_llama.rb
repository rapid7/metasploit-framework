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
        'Name' => 'Garak llama.cpp Target Discovery',
        'Description' => %q{
          Queries llama.cpp model metadata to report candidate garak TARGET_TYPE
          and TARGET_NAME values. Compares model capabilities with local garak
          probe and generator metadata to suggest compatible inputs. No prompts
          are submitted, and generation support is not verified. Missing capability
          information remains unknown. Disable SUGGEST_PROBES to discover model
          names without a local garak installation.
        },
        'Author' => ['bwatters-r7'], # Metasploit module
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/ggml-org/llama.cpp/tree/master/tools/server'],
          ['URL', 'https://github.com/NVIDIA/garak/blob/main/garak/generators/openai.py']
        ],
        'DefaultOptions' => { 'RPORT' => 8080 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the llama.cpp service (without /v1)', '/']),
      OptString.new('API_KEY', [false, 'Bearer API key if the server requires authentication']),
      OptBool.new('SUGGEST_PROBES', [true, 'Compare model capabilities with local garak metadata', true]),
      OptString.new('PROBE_FILTER', [false, 'Case-insensitive substring to narrow probe suggestions'])
    ])
    register_garak_runtime_options
  end

  def run
    @probe_metadata = nil
    @probe_metadata = garak_probe_metadata(target_types: [OPENAI_COMPATIBLE_TARGET_TYPE]) if datastore['SUGGEST_PROBES']
    super
  rescue SystemCallError, IOError => e
    elog('Garak metadata query failed', error: e)
    fail_with(Failure::BadConfig, "Could not read garak metadata: #{e.message}; check PYTHON and GARAK_PATH, or disable SUGGEST_PROBES")
  end

  def llama_request(*path)
    headers = {}
    headers['Authorization'] = "Bearer #{datastore['API_KEY']}" if datastore['API_KEY'].present?
    send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, *path), 'headers' => headers)
  end

  def run_host(ip)
    response = llama_request('v1', 'models')
    fail_with(Failure::Unreachable, 'Model discovery failed: v1/models did not respond') unless response
    if [401, 403].include?(response.code)
      fail_with(Failure::NoAccess, 'Model discovery was denied; check API_KEY')
    end
    unless response.code == 200
      vprint_status("Model discovery returned HTTP #{response.code}; check TARGETURI")
      return
    end
    document = response.get_json_document
    unless document.is_a?(Hash) && document['data'].is_a?(Array) && document['data'].all? { |entry| entry.is_a?(Hash) && entry['id'].is_a?(String) && entry['id'].present? }
      fail_with(Failure::UnexpectedReply, 'Model discovery returned an invalid v1/models list')
    end
    # llama.cpp identifies models with owned_by=llamacpp. Do not fingerprint
    # unrelated OpenAI-compatible services from the generic model-list schema.
    models = document['data'].select { |entry| entry['owned_by'] == 'llamacpp' }
    if models.empty?
      vprint_status('No llama.cpp models were identified; no garak targets reported')
      return
    end

    names = models.map { |entry| entry['id'] }.uniq.sort
    print_good('Llama.cpp models detected')
    service_name = ssl ? 'https' : 'http'
    report_service(host: ip, port: rport, proto: 'tcp', name: service_name, info: 'llama.cpp')
    table = Rex::Text::Table.new('Header' => 'Candidate target types (generation support has not been tested)', 'Indent' => 2, 'Columns' => ['TARGET_TYPE'])
    table << [OPENAI_COMPATIBLE_TARGET_TYPE]
    print_status(table.to_s)
    table = Rex::Text::Table.new('Header' => 'Available target names', 'Indent' => 2, 'Columns' => ['TARGET_NAME'])
    names.each { |name| table << [name] }
    print_status(table.to_s)
    report_note(
      host: ip, port: rport, proto: 'tcp', sname: service_name,
      type: 'llama.garak.targets', update: :unique_data,
      data: { base_path: target_uri.path, target_types: [OPENAI_COMPATIBLE_TARGET_TYPE], target_names: names }
    )
    if datastore['SUGGEST_PROBES']
      properties = llama_properties
      names.each do |name|
        capabilities = llama_capabilities(name, document, properties)
        result = garak_probe_suggestions(capabilities, @probe_metadata, target_types: [OPENAI_COMPATIBLE_TARGET_TYPE])
        report_garak_probe_suggestions(ip: ip, name: name, capabilities: capabilities, result: result, metadata: @probe_metadata, namespace: 'llama')
      end
    end
    print_status("Use these values with auxiliary/scanner/garak/garak_integration, the same RHOSTS/RPORT/SSL and TARGETURI #{normalize_uri(target_uri.path, 'v1', '/')}")
    print_status('Garak requires an API key value; provide the actual key or an unused placeholder for an unauthenticated server through CONFIG_FILE or OPENAICOMPATIBLE_API_KEY')
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog('llama.cpp discovery request failed', error: e)
    vprint_error("Llama.cpp discovery request failed: #{e.message}")
  end

  def llama_properties
    response = llama_request('props')
    if response && response.code == 200
      document = response.get_json_document
      return document if document.is_a?(Hash)
    end
    print_warning('Llama.cpp properties are unavailable; probe suggestions will use only per-model capabilities')
    {}
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog('llama.cpp properties request failed', error: e)
    print_warning("Llama.cpp properties are unavailable: #{e.message}")
    {}
  end

  def llama_capabilities(name, document, properties)
    # llama.cpp's /v1/models includes an extended models list with capabilities.
    # /props describes the loaded model only; never apply it to other model IDs.
    entries = document['models']
    entry = entries.find { |model| model.is_a?(Hash) && model['name'] == name } if entries.is_a?(Array)
    capabilities = entry['capabilities'] if entry
    return nil unless capabilities.is_a?(Array) && !capabilities.empty? && capabilities.all? { |value| value.is_a?(String) }

    capabilities = capabilities.dup
    modalities = properties['modalities'] if properties['model_alias'] == name
    if modalities.is_a?(Hash)
      capabilities << 'vision' if modalities['vision'] == true
      # Preserve unfamiliar modalities as uncertainty, rather than assuming text.
      %w[audio video].each { |kind| capabilities << kind if modalities[kind] == true }
    end
    capabilities.uniq.sort
  end
end
