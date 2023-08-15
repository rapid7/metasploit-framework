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
        'Name' => 'Prometheus Node Exporter And Windows Exporter Information Gather',
        'Description' => %q{
          This modules connects to a Prometheus Node Exporter or Windows Exporter service
          and gathers information about the host.

          Tested against Docker image 1.6.1, Linux 1.6.1, and Windows 0.23.1
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die'
        ],
        'References' => [
          ['URL', 'https://github.com/prometheus/node_exporter'],
          ['URL', 'https://sysdig.com/blog/exposed-prometheus-exploit-kubernetes-kubeconeu/']
        ],

        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2013-04-18', # node exporter first commit on github
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
        Opt::RPORT(9100), # windows 9182
        OptString.new('TARGETURI', [ true, 'The URI of the Prometheus Node Exporter', '/'])
      ]
    )
  end

  def run
    vprint_status("#{peer} - Checking ")
    # since we will check res to see if auth was a success, make sure to capture the return
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200
    fail_with(Failure::UnexpectedReply, "#{peer} - Prometheus Node Exporter not found") unless (
      res.body.include?('<h2>Prometheus Node Exporter</h2>') ||
      res.body.include?('<title>Node Exporter</title>') || # version 0.15.2
      res.body.include?('<h2>Prometheus Exporter for Windows servers</h2>')
    )

    vprint_good("#{peer} - Prometheus Node Exporter version: #{Regexp.last_match(1)}") if res.body =~ /version=([\d.]+)/

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'metrics'),
      'method' => 'GET'
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response from server (response code #{res.code})") unless res.code == 200

    results = process_results_page(res.body)

    if results.nil? || results == []
      print_bad("#{peer} - No metric data found")
      return
    end

    table_network = Rex::Text::Table.new(
      'Header' => 'Network Interfaces',
      'Indent' => 2,
      'Columns' =>
      [
        'Device',
        'MAC',
        'Broadcast',
        'State',
      ]
    )

    table_fs = Rex::Text::Table.new(
      'Header' => 'File Systems',
      'Indent' => 2,
      'Columns' =>
      [
        'Device',
        'Mount Point',
        'FS Type',
      ]
    )

    table_bios = Rex::Text::Table.new(
      'Header' => 'BIOS Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Value',
      ]
    )

    table_os = Rex::Text::Table.new(
      'Header' => 'OS Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Value',
      ]
    )

    table_uname = Rex::Text::Table.new(
      'Header' => 'uname Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Value',
      ]
    )

    table_windows_domain = Rex::Text::Table.new(
      'Header' => 'Domain Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Value',
      ]
    )

    table_device_mapper = Rex::Text::Table.new(
      'Header' => 'Disk Device Mapper Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Device',
        'Name',
        'Logical Volume Name',
        'UUID'
      ]
    )

    table_network_route = Rex::Text::Table.new(
      'Header' => 'Network Route Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Device',
        'IP',
        'Gateway',
        'Network'
      ]
    )

    table_systemd = Rex::Text::Table.new(
      'Header' => 'Systemd Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Service',
        'State',
        'Permission'
      ]
    )

    table_windows_cpu = Rex::Text::Table.new(
      'Header' => 'CPU Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Field',
        'Value',
      ]
    )

    results.each do |result|
      if result['go_info']
        print_good("Go Version: #{result.dig('go_info', 'labels', 'version')}")
      elsif result['node_selinux_enabled']
        print_good("SELinux enabled: #{result.dig('node_selinux_enabled', 'value')}")
      elsif result['node_time_zone_offset_seconds']
        print_good("Timezone: #{result.dig('node_time_zone_offset_seconds', 'labels', 'time_zone')}")
      elsif result['windows_os_timezone']
        print_good("Timezone: #{result.dig('windows_os_timezone', 'labels', 'timezone')}")
      elsif result['node_dmi_info']
        table_bios << ['Date', result.dig('node_dmi_info', 'labels', 'bios_date')]
        table_bios << ['Vendor', result.dig('node_dmi_info', 'labels', 'bios_vendor')]
        table_bios << ['Version', result.dig('node_dmi_info', 'labels', 'bios_version')]
        table_bios << ['Asset Tag', result.dig('node_dmi_info', 'labels', 'board_asset_tag')]
        table_bios << ['Board Vendor', result.dig('node_dmi_info', 'labels', 'board_vendor')]
        table_bios << ['Board Name', result.dig('node_dmi_info', 'labels', 'board_name')]
        table_bios << ['Board Version', result.dig('node_dmi_info', 'labels', 'board_version')]
        table_bios << ['Chassis Asset Tag', result.dig('node_dmi_info', 'labels', 'chassis_asset_tag')]
        table_bios << ['Chassis Vendor', result.dig('node_dmi_info', 'labels', 'chassis_vendor')]
        table_bios << ['Product Family', result.dig('node_dmi_info', 'labels', 'product_family')]
        table_bios << ['Product Name', result.dig('node_dmi_info', 'labels', 'product_name')]
        table_bios << ['System Vendor', result.dig('node_dmi_info', 'labels', 'system_vendor')]
      elsif result['node_filesystem_avail_bytes']
        table_fs << [
          result.dig('node_filesystem_avail_bytes', 'labels', 'device'),
          result.dig('node_filesystem_avail_bytes', 'labels', 'mountpoint'),
          result.dig('node_filesystem_avail_bytes', 'labels', 'fstype'),
        ]
      elsif result['node_filesystem_avail'] # version 0.15.2
        table_fs << [
          result.dig('node_filesystem_avail', 'labels', 'device'),
          result.dig('node_filesystem_avail', 'labels', 'mountpoint'),
          result.dig('node_filesystem_avail', 'labels', 'fstype'),
        ]
      elsif result['windows_logical_disk_size_bytes']
        table_fs << [
          '',
          result.dig('windows_logical_disk_size_bytes', 'labels', 'volume'),
          '',
        ]
      elsif result['node_network_info']
        table_network << [
          result.dig('node_network_info', 'labels', 'device'),
          result.dig('node_network_info', 'labels', 'address'),
          result.dig('node_network_info', 'labels', 'broadcast'),
          result.dig('node_network_info', 'labels', 'operstate')
        ]
      elsif result['node_os_info']
        table_os << ['Family', result.dig('node_os_info', 'labels', 'id')]
        table_os << ['Name', result.dig('node_os_info', 'labels', 'name')]
        table_os << ['Version', result.dig('node_os_info', 'labels', 'version')]
        table_os << ['Version ID', result.dig('node_os_info', 'labels', 'version_id')]
        table_os << ['Version Codename', result.dig('node_os_info', 'labels', 'version_codename')]
        table_os << ['Pretty Name', result.dig('node_os_info', 'labels', 'pretty_name')]
      elsif result['windows_os_info']
        table_os << ['Product', result.dig('windows_os_info', 'labels', 'product')]
        table_os << ['Version', result.dig('windows_os_info', 'labels', 'version')]
        table_os << ['Build Number', result.dig('windows_os_info', 'labels', 'build_number')]
      elsif result['node_uname_info']
        table_uname << ['Domain Name', result.dig('node_uname_info', 'labels', 'domainname')]
        table_uname << ['Arch', result.dig('node_uname_info', 'labels', 'machine')]
        table_uname << ['Release', result.dig('node_uname_info', 'labels', 'release')]
        table_uname << ['OS Type', result.dig('node_uname_info', 'labels', 'sysname')]
        table_uname << ['Version', result.dig('node_uname_info', 'labels', 'version')]
        table_uname << ['Node Name', result.dig('node_uname_info', 'labels', 'nodename')]
      elsif result['windows_cs_hostname']
        table_windows_domain << ['Domain Name', result.dig('windows_cs_hostname', 'labels', 'domain')]
        table_windows_domain << ['FQDN', result.dig('windows_cs_hostname', 'labels', 'fqdn')]
        table_windows_domain << ['Hostname', result.dig('windows_cs_hostname', 'labels', 'hostname')]
      elsif result['node_disk_device_mapper_info']
        table_device_mapper << [
          result.dig('node_disk_device_mapper_info', 'labels', 'device'),
          result.dig('node_disk_device_mapper_info', 'labels', 'name'),
          result.dig('node_disk_device_mapper_info', 'labels', 'lv_name'),
          result.dig('node_disk_device_mapper_info', 'labels', 'uuid'),
        ]
      elsif result['node_network_route_info']
        table_network_route << [
          result.dig('node_network_route_info', 'labels', 'device'),
          result.dig('node_network_route_info', 'labels', 'src'),
          result.dig('node_network_route_info', 'labels', 'gw'),
          result.dig('node_network_route_info', 'labels', 'dest'),
        ]
      elsif result['windows_net_bytes_sent_total']
        table_network_route << [
          result.dig('windows_net_bytes_sent_total', 'labels', 'nic'),
          '',
          '',
          '',
        ]
      elsif result['node_systemd_unit_state']
        # these come back in groups of 4-5 where the value is 0 if a state isn't enabled.
        # we only care about state 1 because thats what that service is at run time
        if result.dig('node_systemd_unit_state', 'value') == '1'
          table_systemd << [
            result.dig('node_systemd_unit_state', 'labels', 'name'),
            result.dig('node_systemd_unit_state', 'labels', 'state'),
            ''
          ]
        end
      elsif result['windows_service_info']
        table_systemd << [
          result.dig('windows_service_info', 'labels', 'display_name'),
          result.dig('windows_service_info', 'labels', 'process_id') == '0' ? 'inactive' : 'active',
          result.dig('windows_service_info', 'labels', 'run_as'),
        ]
      elsif result['windows_cpu_info']
        table_windows_cpu << ['ID', result.dig('windows_cpu_info', 'labels', 'device_id')]
        table_windows_cpu << ['Architecture', result.dig('windows_cpu_info', 'labels', 'architecture')]
        table_windows_cpu << ['Description', result.dig('windows_cpu_info', 'labels', 'description')]
        table_windows_cpu << ['Name', result.dig('windows_cpu_info', 'labels', 'name')]

      end
    end

    [
      table_bios, table_os, table_network, table_windows_domain, table_fs, table_uname, table_windows_cpu,
      table_device_mapper, table_network_route, table_systemd,
    ].each do |table|
      print_good(table.to_s) if !table.rows.empty?
    end
  rescue ::Rex::ConnectionError
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
  end
end
