##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/garak'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Garak
  include Msf::Auxiliary::Report

  # The v1 run API nests final text under results.message.text.
  # https://docs.langflow.org/api-flows-run
  RESPONSE_PATH = '$.outputs[*].outputs[*].results.message.text'.freeze
  TEXT_INPUTS = { 'ChatInput' => 'chat', 'TextInput' => 'text' }.freeze
  TEXT_OUTPUTS = { 'ChatOutput' => 'chat', 'TextOutput' => 'text' }.freeze
  FLOW_ID_PATTERN = /\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Garak Langflow Target Discovery',
        'Description' => %q{
          Identifies Langflow and reads saved flow graphs to discover text input
          and output components. Reports flow IDs, run endpoints and component
          types, and saves credential-free garak REST generator configurations
          for flows with an unambiguous text input and output. This scanner does
          not build or run flows, inspect component secrets, or verify generation
          behavior or vulnerabilities. Garak subsequently executes the selected
          flow and requires a Langflow API key. Lists available probes from the
          local garak installation; set SUGGEST_PROBES false to discover flows
          without a local garak runtime.
        },
        'Author' => ['bwatters-r7'], # Metasploit module
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://docs.langflow.org/api-flows'],
          ['URL', 'https://docs.langflow.org/api-flows-run'],
          ['URL', 'https://github.com/NVIDIA/garak/blob/main/garak/generators/rest.py']
        ],
        'DefaultOptions' => { 'RPORT' => 7860 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path to Langflow', '/']),
      OptString.new('API_KEY', [false, 'Existing Langflow API key for discovery; not saved in loot']),
      OptString.new('FLOW_ID', [false, 'Read a single saved flow UUID instead of listing flows'], regex: FLOW_ID_PATTERN),
      OptBool.new('SUGGEST_PROBES', [true, 'List available probes from the local garak installation after flow discovery', true]),
      OptString.new('PROBE_FILTER', [false, 'Optional case-insensitive substring to narrow the probe list'])
    ])
    register_garak_yaml_option
    register_garak_runtime_options
    register_advanced_options([
      OptInt.new('REST_TIMEOUT', [true, 'Garak REST request timeout in seconds, saved in generated configurations', 300]),
      OptBool.new('INCLUDE_EXAMPLES', [true, 'Include example flows in the inventory', false]),
      OptString.new('OUTPUT_COMPONENT', [false, 'Select a text output component ID when a flow has multiple outputs'])
    ])
  end

  def read_api(path, params = {})
    headers = {}
    headers['x-api-key'] = datastore['API_KEY'] if datastore['API_KEY'].present?
    response = send_request_cgi('method' => 'GET', 'uri' => path, 'headers' => headers, 'vars_get' => params)
    fail_with(Failure::Unreachable, "Langflow discovery failed: #{path} did not respond") unless response
    if [401, 403].include?(response.code)
      fail_with(Failure::NoAccess, "Langflow discovery denied for #{path}; set API_KEY to an existing key with access to the flows")
    end
    unless response.code == 200
      fail_with(Failure::UnexpectedReply, "Langflow discovery failed: #{path} returned HTTP #{response.code}")
    end
    response.gzip_decode! if response.headers['Content-Encoding'].to_s.downcase == 'gzip'
    response.get_json_document
  rescue Zlib::Error => e
    elog('Langflow discovery response decompression failed', error: e)
    fail_with(Failure::UnexpectedReply, "Langflow discovery failed: #{path} returned invalid gzip data")
  end

  def run_host(ip)
    version = read_api(normalize_uri(target_uri.path, 'api/v1/version'))
    unless version.is_a?(Hash) && version['package'].to_s.downcase == 'langflow' && Rex::Version.correct?(version['version'].to_s)
      vprint_status('Langflow version banner was not detected; no garak targets reported')
      return
    end
    release = Rex::Version.new(version['version'])
    print_good("Langflow #{release} detected")
    report_service(host: ip, port: rport, proto: 'tcp', name: ssl ? 'https' : 'http', info: "Langflow #{release}")
    types_table = Rex::Text::Table.new('Header' => 'Candidate target types (generation support has not been tested)', 'Indent' => 2, 'Columns' => ['TARGET_TYPE'])
    types_table << [ENDPOINT_ALIASES.fetch('rest')]
    print_status(types_table.to_s)
    flows = discover_flows
    names_table = Rex::Text::Table.new('Header' => 'Candidate target names (generation support has not been tested)', 'Indent' => 2, 'Columns' => ['TARGET_NAME', 'Flow ID', 'Name'])
    table = Rex::Text::Table.new('Header' => 'Langflow candidate targets (generation has not been tested)', 'Indent' => 2, 'Columns' => ['Flow ID', 'Name', 'Components', 'Configuration'])
    probe_names = nil
    targets = flows.reject { |flow| flow['is_component'] == true }.map do |flow|
      target = flow_target(flow)
      names_table << [target[:endpoint], target[:id], target[:name]]
      config_path = nil
      if target[:input_type] && target[:output_type]
        probe_names ||= garak_probe_names if datastore['SUGGEST_PROBES']
        config = generator_config(target)
        if datastore['OUTPUT_YAML'] && probe_names
          # Explicitly select none when the filter matches nothing; an absent spec selects all active probes.
          config['run'] = { 'spec' => { 'include' => probe_names.empty? ? ['probes.none'] : probe_names } }
        end
        config_path = if datastore['OUTPUT_YAML']
                        store_garak_yaml(ip: ip, namespace: 'langflow', config: config, target_type: ENDPOINT_ALIASES.fetch('rest'), target_name: target[:endpoint], rest_api_key: datastore['API_KEY'])
                      else
                        store_loot('langflow.garak.config', 'application/json', ip, JSON.pretty_generate(generator_config(target)), "langflow_#{target[:id]}_garak.json", 'Garak Langflow REST configuration')
                      end
        unless datastore['OUTPUT_YAML']
          print_garak_scan_command(config_path: config_path, target_type: ENDPOINT_ALIASES.fetch('rest'), target_name: target[:endpoint], rest_api_key: datastore['API_KEY'])
        end
        print_good("Garak configuration saved: #{config_path}")
        print_status("Garak values: TARGET_TYPE=rest.RestGenerator TARGET_NAME=#{target[:endpoint]} TARGETURI=#{target[:run_path]} CONFIG_FILE=#{config_path}")
      else
        print_warning("Flow #{target[:id]} needs an unambiguous text input and output; select OUTPUT_COMPONENT for multiple text outputs")
      end
      table << [target[:id], target[:name], target[:components].join(', '), config_path || 'Manual configuration required']
      target.merge(config_file: config_path)
    end
    print_status(names_table.to_s) unless targets.empty?
    print_status(table.to_s)
    print_warning('No saved flows were returned; specify FLOW_ID or enable INCLUDE_EXAMPLES if appropriate') if targets.empty?
    report_note(host: ip, port: rport, proto: 'tcp', type: 'langflow.garak.targets', update: :unique_data, data: { version: release.to_s, targets: targets })
    unless targets.empty?
      if datastore['API_KEY'].blank?
        print_status('Add REST_API_KEY=<existing-langflow-api-key> to the suggested command if flow execution requires authentication')
      end
      print_status('Use garak_scan with a saved configuration and the same RHOSTS, RPORT and SSL; flow execution and response extraction remain unverified')
      if datastore['SUGGEST_PROBES'] && targets.any? { |target| target[:config_file] }
        list_garak_probes(names: probe_names)
        print_status('Available probes are not verified for these flows; validate input compatibility and dependencies before scanning')
      end
    end
  rescue Rex::ConnectionError, Rex::TimeoutError => e
    elog('Langflow discovery request failed', error: e)
    vprint_error("Langflow discovery request failed: #{e.message}")
  rescue SystemCallError, IOError => e
    elog('Garak probe listing failed', error: e)
    fail_with(Failure::BadConfig, "Could not list garak probes: #{e.message}; check PYTHON and GARAK_PATH, or disable SUGGEST_PROBES")
  end

  def discover_flows
    if datastore['FLOW_ID'].present?
      flows = [read_api(normalize_uri(target_uri.path, 'api/v1/flows', datastore['FLOW_ID']))]
    else
      flows = read_api(normalize_uri(target_uri.path, 'api/v1/flows/'), {
        'get_all' => 'true', 'header_flows' => 'false', 'components_only' => 'false',
        'remove_example_flows' => (!datastore['INCLUDE_EXAMPLES']).to_s
      })
    end
    unless flows.is_a?(Array) && flows.all? { |flow| flow.is_a?(Hash) && flow['id'].is_a?(String) && FLOW_ID_PATTERN.match?(flow['id']) }
      fail_with(Failure::UnexpectedReply, 'Langflow discovery failed: expected complete flow objects with UUIDs; try FLOW_ID if listing is unsupported')
    end
    flows.uniq { |flow| flow['id'] }
  end

  def flow_target(flow)
    nodes = flow.dig('data', 'nodes') if flow['data'].is_a?(Hash)
    nodes = [] unless nodes.is_a?(Array)
    components = nodes.filter_map do |node|
      next unless node.is_a?(Hash) && node['data'].is_a?(Hash) && node['data']['type'].is_a?(String) && node['id'].is_a?(String)

      { id: node['id'], type: node['data']['type'] }
    end
    inputs = components.select { |component| TEXT_INPUTS.key?(component[:type]) }
    outputs = components.select { |component| TEXT_OUTPUTS.key?(component[:type]) }
    outputs.select! { |component| component[:id] == datastore['OUTPUT_COMPONENT'] } if datastore['OUTPUT_COMPONENT'].present?
    run_path = normalize_uri(target_uri.path, 'api/v1/run', flow['id'])
    {
      id: flow['id'], name: flow['name'].to_s, run_path: run_path, endpoint: full_uri(run_path),
      components: components.map { |component| component[:type] }.uniq.sort,
      input_type: inputs.length == 1 ? TEXT_INPUTS[inputs.first[:type]] : nil,
      output_type: outputs.length == 1 ? TEXT_OUTPUTS[outputs.first[:type]] : nil,
      output_component: outputs.length == 1 ? outputs.first[:id] : nil
    }
  end

  def generator_config(target)
    fail_with(Failure::BadConfig, 'REST_TIMEOUT must be positive') unless datastore['REST_TIMEOUT'].positive?

    {
      'plugins' => {
        'generators' => {
          'rest' => {
            'RestGenerator' => {
              'uri' => target[:endpoint], 'method' => 'post',
              'request_timeout' => datastore['REST_TIMEOUT'],
              'headers' => { 'Content-Type' => 'application/json', 'x-api-key' => '$KEY' },
              'req_template_json_object' => {
                'input_value' => '$INPUT', 'input_type' => target[:input_type],
                'output_type' => target[:output_type], 'output_component' => target[:output_component]
              },
              'response_json' => true, 'response_json_field' => RESPONSE_PATH
            }
          }
        }
      }
    }
  end
end
